"""
Wireshark (tshark) based live IDS.

    python wireshark_ids.py --collect            capture NORMAL traffic -> datasets/esp32_normal.csv
    python wireshark_ids.py                      live detection (needs a trained model)
    python wireshark_ids.py --pcap file.pcapng --device-ip IP [--collect]
                                                 analyse a saved Wireshark capture offline

Live mode waits until the ESP32 contacts gateway.py (which records the device
IP), then captures that device's traffic with tshark, builds the features for
every window, scores it with the Isolation Forest and publishes the verdict in
logs/verdict.json for the gateway to send back to the ESP32.
"""

import argparse
import csv
import json
import shutil
import subprocess
import sys
import threading
from collections import deque
import time
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "ai_engine"))

import train_model  # noqa: E402
from anomaly_detector import detect_anomalies  # noqa: E402
from confirm_rules import make_rule  # noqa: E402
from preprocessing import REQUIRED_FEATURES  # noqa: E402
from traffic_features import (  # noqa: E402
    TSHARK_FIELDS, parse_tshark_line, window_features, packets_to_windows)

LOGS = BASE_DIR / "logs"
NORMAL_CSV = BASE_DIR / "datasets" / "esp32_normal.csv"
LIVE_LOG = LOGS / "live_log.csv"
VERDICT = LOGS / "verdict.json"
DEVICE_IP_FILE = LOGS / "device_ip.txt"
ATTACK_CMD = LOGS / "attack_cmd.json"
STATS_FILE = LOGS / "stats.json"
LIVE_FIELDS = ["time"] + REQUIRED_FEATURES + ["anomaly_score", "status", "injected", "ts", "rule_value"]

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "tshark",
]


def find_tshark():
    for c in TSHARK_CANDIDATES:
        if c == "tshark" or Path(c).exists():
            return c
    sys.exit("tshark not found. Install Wireshark.")


def append_csv(path, fields, row):
    new = not path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        if new:
            w.writeheader()
        w.writerow(row)


def write_verdict(status, score=0.0):
    LOGS.mkdir(exist_ok=True)
    VERDICT.write_text(json.dumps(
        {"status": status, "score": round(score, 4), "time": time.time()}))


PHASE_FILE = LOGS / "phase.json"
PACKETS_FILE = LOGS / "packets_recent.csv"
EVIDENCE = BASE_DIR / "evidence"
recent = deque(maxlen=200)  # last packets, shown in the dashboard's Wireshark view
packet_no = 0


def write_recent_packets(device_ip):
    """Dump the latest packets in a Wireshark-like table for the dashboard."""
    rows = []
    for i, p in enumerate(recent):
        rows.append({
            "No.": i + 1,
            "Time": time.strftime("%H:%M:%S", time.localtime(p[0])) + f".{int(p[0] % 1 * 1000):03d}",
            "Source": p[2], "Destination": p[3], "Protocol": p[7],
            "Length": p[1], "Info": p[8],
            "Direction": "device → laptop" if p[2] == device_ip else "laptop → device",
        })
    pd.DataFrame(rows).to_csv(PACKETS_FILE, index=False)


def write_phase(phase, done=0, total=0):
    LOGS.mkdir(exist_ok=True)
    PHASE_FILE.write_text(json.dumps({"phase": phase, "done": done, "total": total}))


def injected_now(window):
    """1 if the dashboard's 'Generate anomaly' was active during this window (ground truth)."""
    try:
        cmd = json.loads(ATTACK_CMD.read_text())
    except (OSError, ValueError):
        return 0
    now = time.time()
    return int(cmd.get("started", 0) <= now <= cmd.get("until", 0) + window)


def score_window(feats):
    res = detect_anomalies(pd.DataFrame([feats])).iloc[0]
    return ("anomaly" if res["prediction"] == -1 else "normal"), float(res["anomaly_score"])


def tshark_cmd(extra):
    cmd = [find_tshark()] + extra + ["-T", "fields", "-E", "separator=,", "-E", "quote=d"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    return cmd


def run_offline(args):
    extra = ["-r", args.pcap, "-Y", f"ip.addr=={args.device_ip}"]
    out = subprocess.run(tshark_cmd(extra), capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    packets = [p for p in map(parse_tshark_line, out.splitlines()) if p]
    df = packets_to_windows(packets, args.device_ip, args.window or 5.0)
    if df.empty:
        sys.exit("No packets for that device in the capture.")
    print(f"{len(packets)} packets -> {len(df)} windows")
    if args.collect:
        df.to_csv(NORMAL_CSV, index=False)
        print(f"Saved baseline windows to {NORMAL_CSV}")
        return
    res = detect_anomalies(df)
    print(pd.concat([df.reset_index(drop=True), res.reset_index(drop=True)], axis=1)
          .to_string(index=False))
    print(f"\nFlagged {int((res['prediction'] == -1).sum())} of {len(res)} windows.")


def run_live(args):
    pkg = None
    if not args.collect:
        if not train_model.MODEL_PATH.exists():
            sys.exit("No model yet. Run: python wireshark_ids.py --collect, then python train_esp32.py")
        pkg = train_model.load_detector()
    window = args.window or (pkg or {}).get("window_seconds") or 5.0
    if pkg and pkg.get("window_seconds") and abs(pkg["window_seconds"] - window) > 1e-6:
        print(f"NOTE: the model was trained on {pkg['window_seconds']:g}s windows but --window {window:g} was given; "
              "retrain (run_system.py --retrain --window ...) for matching results.")
    hop = window if args.collect else (args.hop or min(1.0, window))   # baselines are always tumbling windows
    if args.collect and args.hop and args.hop != window:
        print("NOTE: baseline windows do not overlap; --hop is ignored while learning.")
    param = args.cusum_h if args.rule == "cusum" else args.confirm
    rule = make_rule(args.rule, param, p0=args.cusum_p0)
    rule_name = f"cusum(h={param:g})" if args.rule == "cusum" else f"{param}-in-a-row"

    device_ip = args.device_ip
    if not device_ip:
        print("Waiting for the ESP32 to contact gateway.py ...")
        while not DEVICE_IP_FILE.exists():
            time.sleep(1)
        device_ip = DEVICE_IP_FILE.read_text().strip()
    print(f"Device IP {device_ip}; capturing on '{args.interface}' with tshark")

    extra = ["-i", args.interface, "-l", "-f", args.filter or f"host {device_ip}"]
    proc = subprocess.Popen(tshark_cmd(extra), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1,
                            encoding="utf-8", errors="replace")
    buf, lock = deque(), threading.Lock()   # recent packets; windows are cut from it by capture time

    def reader():
        for line in proc.stdout:
            p = parse_tshark_line(line)
            if p:
                with lock:
                    buf.append(p)
                    recent.append(p)

    threading.Thread(target=reader, daemon=True).start()
    mode = "COLLECT (normal traffic)" if args.collect else "DETECT"
    cfg = f"{window:g}s windows" + ("" if hop == window else f", decision every {hop:g}s") + \
          ("" if args.collect else f", rule {rule_name}")
    print(f"{mode} mode, {cfg}. Ctrl+C to stop.")
    write_verdict("warming_up")
    write_phase("learning" if args.collect else "detecting", 0, args.max_windows)
    GRACE = 0.25                      # seconds: lets packets still in the capture pipe arrive before a window is cut
    collected = 0
    prev_alert = False
    total_packets = windows = flagged = 0
    last_end = None
    next_tick = time.time() + hop
    try:
        while True:
            time.sleep(max(next_tick - time.time(), 0))
            end = next_tick - GRACE
            next_tick += hop
            start = end - window
            with lock:
                while buf and buf[0][0] < start - 1:
                    buf.popleft()
                batch = [p for p in buf if start <= p[0] < end]
            feats = window_features(batch, device_ip, window)
            total_packets += len([p for p in batch if last_end is None or p[0] >= last_end])
            last_end = end
            write_recent_packets(device_ip)
            now = time.strftime("%H:%M:%S")
            if args.collect:
                if feats["packet_count"]:
                    append_csv(NORMAL_CSV, ["time"] + REQUIRED_FEATURES, {"time": now, **feats})
                    collected += 1
                    write_phase("learning", collected, args.max_windows)
                print(f"[{now}] collected {collected}/{args.max_windows or '?'} {feats}")
                if args.max_windows and collected >= args.max_windows:
                    break
                continue
            if feats["packet_count"] == 0:
                status, score = "idle", 0.0
                rule.reset()
            else:
                raw, score = score_window(feats)
                rule.update(raw == "anomaly")
                status = "anomaly" if rule.active else "normal"
            write_verdict(status, score)
            windows += 1
            flagged += status == "anomaly"
            STATS_FILE.write_text(json.dumps({
                "total_packets": total_packets, "windows": windows, "flagged": flagged,
                "last_analysis": time.time(), "window_seconds": window, "hop_seconds": hop,
                "rule": args.rule, "rule_param": param, "rule_name": rule_name}))
            if status == "anomaly" and not prev_alert:  # keep the packets as evidence
                EVIDENCE.mkdir(exist_ok=True)
                if PACKETS_FILE.exists():
                    shutil.copy(PACKETS_FILE, EVIDENCE / f"alert_{time.strftime('%Y%m%d_%H%M%S')}.csv")
            prev_alert = status == "anomaly"
            append_csv(LIVE_LOG, LIVE_FIELDS,
                       {"time": now, **feats, "anomaly_score": round(score, 4), "status": status,
                        "injected": injected_now(window), "ts": round(time.time(), 3),
                        "rule_value": round(rule.value, 3)})
            flag = "!! ANOMALY !!" if status == "anomaly" else status
            print(f"[{now}] {flag:14} score={score:+.3f} {feats}")
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--collect", action="store_true", help="record normal traffic for training")
    ap.add_argument("--pcap", help="analyse a saved Wireshark capture instead of capturing live")
    ap.add_argument("--device-ip", help="ESP32 IP (default: learnt from the gateway)")
    ap.add_argument("--interface", default="Wi-Fi", help="capture interface (see tshark -D)")
    ap.add_argument("--window", type=float, default=None,
                    help="window length in seconds (default: the length the model was trained on, else 5)")
    ap.add_argument("--hop", type=float, default=None,
                    help="seconds between decisions; below --window the windows overlap (default: = window)")
    ap.add_argument("--rule", choices=["fixed", "cusum"], default="fixed",
                    help="alert rule: k flagged windows in a row, or a sequential CUSUM")
    ap.add_argument("--cusum-h", type=float, default=4.0, help="CUSUM alert threshold h")
    ap.add_argument("--cusum-p0", type=float, default=0.05, help="CUSUM assumed normal flag rate")
    ap.add_argument("--max-windows", type=int, default=0,
                    help="with --collect: stop automatically after N windows")
    ap.add_argument("--filter", help="tshark capture filter (default: host <device IP>)")
    ap.add_argument("--confirm", type=int, default=2,
                    help="consecutive anomalous windows needed to raise an alert")
    args = ap.parse_args()
    if args.pcap:
        if not args.device_ip:
            sys.exit("--device-ip is required with --pcap")
        run_offline(args)
    else:
        run_live(args)
