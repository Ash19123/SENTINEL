"""
Time-to-detect experiment recorder.

Records, in one session, everything needed to compare detection rules offline:
  * the raw packets of the device (tshark, one CSV row per packet) -> packets.csv
  * the exact ground truth: when each commanded burst started and ended -> ground_truth.json

Timeline:  [ baseline: normal ] [ validation: normal ] [ N bursts at random times, with normal gaps ] [ tail: normal ]

    python experiments/run_trials.py --out experiments/data/runA                (simulated device)
    python experiments/run_trials.py --out experiments/data/runR --real         (real ESP32 already on the network)

The bursts are commanded exactly like the dashboard's Generate anomaly button
(logs/attack_cmd.json), so they travel through the real gateway and the real firmware logic.
"""

import argparse
import ctypes
import json
import random
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "ai_engine"))
from traffic_features import TSHARK_FIELDS  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
ap.add_argument("--baseline", type=float, default=240, help="seconds of normal traffic used for training")
ap.add_argument("--validation", type=float, default=600, help="seconds of normal traffic used to calibrate rules")
ap.add_argument("--bursts", type=int, default=20)
ap.add_argument("--gap-min", type=float, default=30)
ap.add_argument("--gap-max", type=float, default=60)
ap.add_argument("--lens", default="10,15,20,25", help="possible burst lengths in seconds")
ap.add_argument("--tail", type=float, default=45)
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--interface", default=r"\Device\NPF_Loopback")
ap.add_argument("--filter", default="tcp port 8000")
ap.add_argument("--real", action="store_true", help="do not start the simulator (a real ESP32 is sending)")
args = ap.parse_args()

try:  # ES_CONTINUOUS | ES_SYSTEM_REQUIRED: no sleep while this process runs; released when it exits
    ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
except Exception:  # noqa: BLE001
    pass
OUT = Path(args.out)
OUT.mkdir(parents=True, exist_ok=True)
LOGS = BASE / "logs"
LOGS.mkdir(exist_ok=True)
rng = random.Random(args.seed)
TSHARK = next((c for c in (r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe")
               if Path(c).exists()), "tshark")
procs, gt = [], {"meta": {"simulated": not args.real, "seed": args.seed, "interface": args.interface}, "bursts": []}


def save_gt():
    (OUT / "ground_truth.json").write_text(json.dumps(gt, indent=1))


_down_since = None


def write_progress():
    """Live progress for the dashboard (logs/recording.json)."""
    now = time.time()
    n, N = len(gt["bursts"]), args.bursts
    if "t0" not in gt:
        phase = "starting"
    elif "end" in gt:
        phase = "finished"
    elif now < gt["baseline_end"]:
        phase = "learning baseline (normal traffic)"
    elif now < gt["val_end"]:
        phase = "normal traffic (calibration)" if N else "normal traffic (long soak)"
    elif n and now < gt["bursts"][-1]["until"]:
        phase = f"BURST {n}/{N} in progress"
    elif n < N:
        phase = f"normal traffic, waiting for burst {n + 1}/{N}"
    else:
        phase = "normal traffic (tail)"
    est = args.baseline + args.validation + N * ((args.gap_min + args.gap_max) / 2 + 17.5) + args.tail
    try:
        (LOGS / "recording.json").write_text(json.dumps({
            "run": OUT.name, "phase": phase, "bursts_done": n, "bursts_total": N, "soak": N == 0,
            "t0": gt.get("t0"), "est_total_s": est, "updated": now}))
    except OSError:
        pass


def heartbeat_ok():
    for _ in range(3):   # the gateway rewrites the file up to 10 times a second: retry a torn read
        try:
            return time.time() - json.loads((LOGS / "device_status.json").read_text())["last_seen"] < 6
        except (OSError, ValueError, KeyError):
            time.sleep(0.03)
    return False


def wait_until(t):
    """Sleep until t, while logging any period in which the device stopped sending (outages)."""
    global _down_since
    while time.time() < t:
        time.sleep(min(0.5, max(t - time.time(), 0)))
        write_progress()
        up = heartbeat_ok()
        if not up and _down_since is None:
            _down_since = time.time()
        elif up and _down_since is not None:
            if time.time() - _down_since >= 5:   # shorter blips are read races, not outages
                gt.setdefault("outages", []).append({"start": _down_since, "end": time.time()})
                save_gt()
                stamp(f"WARNING: device was silent for {time.time() - _down_since:.0f}s")
            _down_since = None


def stamp(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


try:
    for f in ("attack_cmd.json", "device_status.json", "verdict.json", "device_ip.txt"):
        (LOGS / f).unlink(missing_ok=True)
    procs.append(subprocess.Popen([sys.executable, "-u", "gateway.py"], cwd=BASE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(2)
    cap_file = open(OUT / "packets.csv", "w", encoding="utf-8", newline="")
    cmd = [TSHARK, "-i", args.interface, "-l", "-f", args.filter, "-T", "fields", "-E", "separator=,", "-E", "quote=d"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    procs.append(subprocess.Popen(cmd, stdout=cap_file, stderr=subprocess.DEVNULL))
    time.sleep(2)
    if not args.real:
        procs.append(subprocess.Popen([sys.executable, "-u", "tools/simulate_esp32.py", "--host", "127.0.0.1", "--follow"],
                                      cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    stamp("waiting for the device heartbeat ...")
    for _ in range(120):
        try:
            if time.time() - json.loads((LOGS / "device_status.json").read_text())["last_seen"] < 5:
                break
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(1)
    else:
        sys.exit("no device heartbeat")

    t0 = time.time()
    gt.update(t0=t0, baseline_end=t0 + args.baseline, val_end=t0 + args.baseline + args.validation)
    save_gt()
    stamp(f"recording: {args.baseline:.0f}s baseline + {args.validation:.0f}s validation, then {args.bursts} bursts")
    wait_until(gt["val_end"])

    lens = [float(x) for x in args.lens.split(",")]
    for i in range(args.bursts):
        wait_until(time.time() + rng.uniform(args.gap_min, args.gap_max))
        length = rng.choice(lens)
        started = time.time()
        (LOGS / "attack_cmd.json").write_text(json.dumps({"started": started, "until": started + length}))
        gt["bursts"].append({"started": started, "until": started + length})
        save_gt()
        stamp(f"burst {i + 1}/{args.bursts}: {length:.0f}s")
        wait_until(started + length)
    wait_until(time.time() + args.tail)
    gt["end"] = time.time()
    save_gt()
    stamp("done")
finally:
    (LOGS / "recording.json").unlink(missing_ok=True)
    for p in procs:
        p.terminate()
    time.sleep(1)
    try:
        cap_file.close()
    except NameError:
        pass
