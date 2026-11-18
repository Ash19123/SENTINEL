"""
Guided accuracy test with real devices. You bring known numbers of devices (phones, tablets, laptops that are
on and connected to the same Wi-Fi), and the script records the true count while the ESP32 estimates it.

    python experiments/presence_guided.py --levels 0 1 2 3 --minutes 2

For each level it asks you to put that many devices in range, waits for you to press Enter, records for the
given minutes, then moves on. At the end it prints the accuracy. Run "Learn the empty room" on the dashboard
first (with none of the test devices present).
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from presence_accuracy import BASE, evaluate  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--levels", type=int, nargs="+", default=[0, 1, 2, 3])
ap.add_argument("--minutes", type=float, default=2.0)
ap.add_argument("--logs", default=str(BASE / "logs"))
ap.add_argument("--settle", type=float, default=20.0)
a = ap.parse_args()
logs = Path(a.logs)
truth = logs / "presence_truth.csv"
if not truth.exists() or truth.stat().st_size == 0:
    truth.write_text("time,true_count,source\n")
t_start = time.time()
for k in a.levels:
    input(f"\nPut exactly {k} device(s) in range (switched on, screen woken, connected to the Wi-Fi). Press Enter to start... ")
    end = time.time() + a.minutes * 60
    print(f"recording {k} for {a.minutes:g} min ...")
    while time.time() < end:
        with open(truth, "a", newline="") as f:
            f.write(f"{time.time():.3f},{k},manual\n")
        time.sleep(3)
print("\nResults")
r = evaluate(logs, a.settle, t_start)
print(f"  exactly right {r['exact_match']:.0%}, within one device {r['within_1']:.0%}, mean absolute error {r['mae']:.2f}")
for b in r["by_true_count"]:
    print(f"  true {b['true']}: mean estimate {b['mean_estimate']:.2f}, exact {b['exact']:.0%} (n={b['samples']})")
