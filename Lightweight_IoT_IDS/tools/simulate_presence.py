"""
Simulated presence-counter node (no hardware needed). It plays the part of the ESP32 and posts a table of
nearby devices to the gateway every 3 s, exactly like esp32_presence_node.ino does.

The scene: a laptop and a router that are always there (infrastructure), people arriving and leaving
(each carries one device), plus noise: far-away neighbours and one-off stray frames. The true number of
people is written to logs/presence_truth.csv so the dashboard can compare it with the estimate.

    python tools/simulate_presence.py            (gateway.py must be running)
"""

import argparse
import csv
import json
import random
import time
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
LOGS = BASE / "logs"
SCENARIO = [(30, 0), (45, 2), (45, 4), (45, 1), (45, 0), (60, 3), (45, 5), (45, 2), (45, 0)]  # (seconds, people)


def h(prefix, i):
    return f"{abs(hash((prefix, i))) % 0xFFFFFFFF:08x}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000/presence")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-auto-learn", action="store_true", help="do not press Learn the empty room automatically")
    ap.add_argument("--loop", action="store_true", help="repeat the scenario forever")
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    LOGS.mkdir(exist_ok=True)
    truth = LOGS / "presence_truth.csv"
    if not truth.exists():
        truth.write_text("time,true_count,source\n")
    boot = rnd.randrange(1 << 30)
    people = {}             # slot -> {"h","r","f","last"}
    seen = {}               # hash -> table entry
    t_end, idx = 0.0, -1
    started = time.time()
    learned = args.no_auto_learn
    target = 0
    print("simulated presence node running; Ctrl+C stops")
    while True:
        now = time.time()
        if now >= t_end:
            idx += 1
            if idx >= len(SCENARIO):
                if not args.loop:
                    break
                idx = 0
            dur, target = SCENARIO[idx]
            t_end = now + dur
        if not learned and now - started > 15:   # the room is empty at the start: learn the infrastructure
            (LOGS / 'presence_cmd.json').write_text(json.dumps({'calibrate': now}))
            learned = True
        # people arrive and leave one at a time
        while len(people) < target:
            k = rnd.randrange(10**6)
            people[k] = {"h": h("p", k), "r": rnd.randint(-68, -45)}
        while len(people) > target:
            people.pop(rnd.choice(list(people)))
        heard = {"laptop": (h("infra", 1), -35, 1.0), "router": (h("infra", 2), -40, 1.0)}
        # every person's device is heard with some probability each cycle (phones are not always talking)
        frames, assoc = {}, set()
        for k, p in people.items():
            if rnd.random() < 0.85:
                frames[p["h"]] = (p["r"] + rnd.randint(-3, 3), rnd.randint(2, 9))
            assoc.add(p["h"])
        for name, (hh, r, _) in heard.items():
            frames[hh] = (r, rnd.randint(8, 25))
            assoc.add(hh)
        if rnd.random() < 0.5:   # a neighbour's device, too far to count
            frames[h("far", rnd.randrange(4))] = (rnd.randint(-92, -82), rnd.randint(2, 6))
        if rnd.random() < 0.6:   # a stray one-off frame (random address)
            frames[h("stray", rnd.randrange(10**6))] = (rnd.randint(-72, -55), 1)
        for hh, (r, f) in frames.items():
            e = seen.setdefault(hh, {"h": hh, "r": r, "f": 0, "g": int(rnd.random() < 0.3), "a": 0})
            if hh in assoc:
                e["a"] = 1
            e["r"], e["f"], e["last"] = r, e["f"] + f, now
        for hh in [k for k, e in seen.items() if now - e["last"] > 60]:
            del seen[hh]
        table = [{"h": e["h"], "r": e["r"], "f": e["f"], "t": int(now - e["last"]), "g": e["g"], "a": e["a"]} for e in seen.values()]
        body = json.dumps({"device": "esp32-presence", "boot": boot, "rssi": -50, "simulated": True, "devices": table}).encode()
        try:
            req = urllib.request.Request(args.url, body, {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2).read()
        except Exception as exc:
            print("gateway not reachable:", exc)
        with open(truth, "a", newline="") as f:
            f.write(f"{now:.3f},{len(people)},simulated\n")
        time.sleep(3)


if __name__ == "__main__":
    main()
