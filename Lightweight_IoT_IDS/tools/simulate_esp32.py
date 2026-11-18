"""
Stand-in for the ESP32 when no hardware is available.

    python tools/simulate_esp32.py --host 127.0.0.1 --follow      behaves like the firmware:
        one POST every 2 s, and a burst (one POST every 100 ms, max 30 s) while the
        gateway's reply carries "attack":true (the dashboard's Generate anomaly button)

    python tools/simulate_esp32.py --host <laptop IP> --attack 20   fixed 20 s burst, then normal
"""

import argparse
import json
import math
import random
import time
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--host", required=True)
ap.add_argument("--port", type=int, default=8000)
ap.add_argument("--follow", action="store_true", help="obey the gateway's attack flag like the real firmware")
ap.add_argument("--attack", type=float, default=0, help="seconds of flooding at start, then normal")
ap.add_argument("--jitter", type=float, default=0.1,
                help="random +/- seconds added to the 2 s send interval (network and firmware timing jitter)")
ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = forever)")
args = ap.parse_args()

NORMAL_S, FLOOD_S, MAX_BURST_S = 2.0, 0.1, 30.0   # same values as esp32_ids_node.ino


def post(flood, t):
    # Synthetic, gently varying readings. The dashboard labels the device as SIMULATED.
    body = json.dumps({"device": "simulated", "simulated": True,
                       "temperature": round(26 + 1.5 * math.sin(t / 60), 1),
                       "humidity": round(55 + 4 * math.sin(t / 90), 1),
                       "flood": flood}).encode()
    req = urllib.request.Request(f"http://{args.host}:{args.port}/data", body,
                                 {"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=2).read())


start = time.time()
burst_since = None
while not args.duration or time.time() - start < args.duration:
    now = time.time()
    flooding = False
    if args.follow:
        flooding = burst_since is not None and now - burst_since < MAX_BURST_S
    elif args.attack:
        flooding = now - start < args.attack
    try:
        reply = post(flooding, now - start)
        if args.follow:
            if reply.get("attack"):
                burst_since = burst_since or now
            else:
                burst_since = None
        print(f"{'BURST ' if flooding else 'normal'} verdict={reply.get('status')}", flush=True)
    except (OSError, ValueError) as e:
        print("error:", e, flush=True)
    time.sleep(FLOOD_S if flooding else NORMAL_S + random.uniform(-args.jitter, args.jitter))
