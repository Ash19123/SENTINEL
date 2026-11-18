"""
Presence-counter demo: one command.

    python run_presence.py               real ESP32 running esp32_presence_node.ino
    python run_presence.py --simulate    laptop only, no hardware (a simulated node plays the ESP32)

Starts the gateway and the dashboard and opens the Presence page. Ctrl+C stops everything.
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
URL = "http://localhost:8501/?page=Presence"

ap = argparse.ArgumentParser()
ap.add_argument("--simulate", action="store_true", help="laptop-only demo with a simulated node")
ap.add_argument("--keep", action="store_true", help="keep earlier presence logs instead of starting fresh")
args = ap.parse_args()

LOGS.mkdir(exist_ok=True)
if not args.keep:
    for name in ("presence_log.csv", "presence_truth.csv", "presence_state.json", "presence_node.json",
                 "presence_cmd.json", "presence_infra.json"):
        (LOGS / name).unlink(missing_ok=True)

children = []


def spawn(cmd, log, env=None):
    f = open(LOGS / log, "w")
    children.append(subprocess.Popen([sys.executable, "-u", *cmd], cwd=BASE, stdout=f, stderr=subprocess.STDOUT,
                                     env={**os.environ, **(env or {})}))


spawn(["gateway.py"], "gateway.out")
spawn(["-m", "streamlit", "run", "dashboard/live.py", "--server.port", "8501", "--server.headless", "true"],
      "streamlit.out", {"SENTINEL_NO_BROWSER": "1"})
time.sleep(4)
if args.simulate:
    spawn(["tools/simulate_presence.py", "--loop"], "sim_presence.out")
    print("Simulated presence node started.")
else:
    print("Waiting for the ESP32 (esp32_presence_node.ino). Its Green LED lights when it reaches the gateway.")
print(f"Dashboard: {URL}")
if not os.environ.get("SENTINEL_NO_BROWSER"):
    webbrowser.open(URL)
print("Press 'Learn the empty room' on the dashboard once nobody's phone is in the room. Ctrl+C stops.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    for p in children:
        p.terminate()
