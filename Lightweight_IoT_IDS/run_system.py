"""
One command runs the whole system:

    python run_system.py               (or double-click start.bat)

  1. starts the gateway (receives the ESP32's telemetry)
  2. starts the live dashboard and opens it in the browser
  3. if there is no trained model yet: captures the ESP32's NORMAL traffic with
     Wireshark/tshark for a couple of minutes, then trains the Isolation Forest
  4. runs live detection until you press Ctrl+C

Options:  --retrain   learn the baseline again      --windows N   baseline length
          --interface NAME   capture interface (default Wi-Fi)
"""

import argparse
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOGS = BASE / "logs"
MODEL = BASE / "models" / "isolation_forest.joblib"
BASELINE = BASE / "datasets" / "esp32_normal.csv"
DASH_URL = "http://localhost:8501"

ap = argparse.ArgumentParser()
ap.add_argument("--retrain", action="store_true")
ap.add_argument("--windows", type=int, default=48, help="baseline windows (5 s each)")
ap.add_argument("--interface", default=None, help="capture interface (default Wi-Fi, loopback with --simulate)")
ap.add_argument("--window", type=float, default=None, help="traffic window length in seconds (default 5)")
ap.add_argument("--hop", type=float, default=None, help="seconds between decisions (below --window = overlapping windows)")
ap.add_argument("--rule", choices=["fixed", "cusum"], default=None, help="alert rule (default: fixed, 2 in a row)")
ap.add_argument("--cusum-h", type=float, default=None, help="CUSUM threshold h")
ap.add_argument("--simulate", action="store_true",
                help="laptop-only demo: a simulated ESP32 on this machine, no hardware or Wi-Fi needed")
args = ap.parse_args()
SIM_IFACE = r"\Device\NPF_Loopback"
IFACE = args.interface or (SIM_IFACE if args.simulate else "Wi-Fi")
FILTER = ["--filter", "tcp port 8000"] if args.simulate else []
WIN = ["--window", str(args.window)] if args.window else []
DETECT_OPTS = WIN + (["--hop", str(args.hop)] if args.hop else []) + (["--rule", args.rule] if args.rule else [])     + (["--cusum-h", str(args.cusum_h)] if args.cusum_h else [])

children = []


def spawn(cmd, log_name):
    log = open(LOGS / log_name, "w")
    p = subprocess.Popen([sys.executable, "-u", *cmd], cwd=BASE, stdout=log, stderr=subprocess.STDOUT)
    children.append(p)
    return p


def run(cmd):
    return subprocess.run([sys.executable, "-u", *cmd], cwd=BASE).returncode


def banner(text):
    print("\n" + "=" * 70 + f"\n  {text}\n" + "=" * 70, flush=True)


def main():
    LOGS.mkdir(exist_ok=True)
    for f in ("live_log.csv", "sensor_log.csv", "verdict.json", "phase.json", "stats.json",
              "device_status.json", "attack_cmd.json", "packets_recent.csv", "mode.json"):
        (LOGS / f).unlink(missing_ok=True)

    banner("Lightweight IoT Intrusion & Anomaly Detector" + ("  [SIMULATED DEVICE]" if args.simulate else ""))
    if args.simulate:
        (LOGS / "mode.json").write_text('{"simulated": true}')
    spawn(["gateway.py"], "gateway.out")
    spawn(["-m", "streamlit", "run", "dashboard/live.py", "--server.headless", "true",
           "--server.port", "8501", "--server.address", "127.0.0.1"], "streamlit.out")
    print(f"Gateway started on port 8000. Dashboard: {DASH_URL}")
    time.sleep(4)
    if args.simulate:
        spawn(["tools/simulate_esp32.py", "--host", "127.0.0.1", "--follow"], "simulator.out")
        print("Simulated ESP32 started (no hardware needed).")
    if not os.environ.get("SENTINEL_NO_BROWSER"):
        webbrowser.open(DASH_URL)

    if args.retrain or not MODEL.exists():
        banner(f"STEP 1/2  Learning normal traffic ({args.windows} windows). "
               + ("Leave the simulated device alone." if args.simulate
               else "Keep the ESP32 powered and do NOT press its button."))
        BASELINE.unlink(missing_ok=True)
        run(["wireshark_ids.py", "--collect", "--interface", IFACE, *FILTER,
             "--max-windows", str(args.windows), *WIN])
        if not BASELINE.exists():
            sys.exit("No traffic was captured. " + ("Is Npcap installed with loopback support? Run tools/check_setup.py."
                                              if args.simulate else "Is the ESP32 powered and on the same Wi-Fi?"))
        banner("STEP 2/2  Training the Isolation Forest")
        if run(["train_esp32.py"]) != 0:
            sys.exit("Training failed.")

    banner("LIVE DETECTION running. Use Generate anomaly in the dashboard. Ctrl+C stops.")
    run(["wireshark_ids.py", "--interface", IFACE, *FILTER, *DETECT_OPTS])


try:
    main()
except KeyboardInterrupt:
    pass
finally:
    for p in children:
        p.terminate()
    print("\nStopped.")
