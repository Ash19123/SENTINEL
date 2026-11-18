"""
How accurate is the presence count?

Compares the estimate in logs/presence_log.csv with the true count in logs/presence_truth.csv (written by the
simulator, by the dashboard's "Record the true count" box, or by presence_guided.py). The first SETTLE seconds
after every change of the true count are ignored, because people take time to arrive and the estimate smooths
over a few updates.

    python experiments/presence_accuracy.py [--logs logs] [--settle 15] [--since <epoch>]
"""

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent


def evaluate(logs, settle=15.0, since=0.0):
    est = pd.read_csv(Path(logs) / "presence_log.csv")
    tru = pd.read_csv(Path(logs) / "presence_truth.csv").sort_values("time")
    est = est[est["time"] >= since].copy()
    tru = tru[tru["time"] >= since - 60].copy()
    if est.empty or tru.empty:
        raise SystemExit("no data to compare yet")
    # true count in force at each estimate, and when that count last changed
    idx = np.searchsorted(tru["time"].to_numpy(), est["time"].to_numpy(), side="right") - 1
    ok = idx >= 0
    est, idx = est[ok].copy(), idx[ok]
    # a true count only applies while truth rows keep arriving (every 3 s): pauses between levels are not scored
    fresh = (est["time"].to_numpy() - tru["time"].to_numpy()[idx]) <= 8.0
    est, idx = est[fresh].copy(), idx[fresh]
    est["true"] = tru["true_count"].to_numpy()[idx]
    changed = (tru["true_count"].ne(tru["true_count"].shift()) | (tru["time"].diff() > 8.0)).to_numpy()
    change_time = np.maximum.accumulate(np.where(changed, tru["time"].to_numpy(), -np.inf))
    est["since_change"] = est["time"].to_numpy() - change_time[idx]
    stable = est[est["since_change"] >= settle]
    if stable.empty:
        raise SystemExit("not enough settled data yet")
    err = stable["count"] - stable["true"]
    out = {
        "samples": int(len(stable)),
        "minutes": float(len(stable) * 3 / 60),
        "exact_match": float((err == 0).mean()),
        "within_1": float((err.abs() <= 1).mean()),
        "mae": float(err.abs().mean()),
        "bias": float(err.mean()),
        "rmse": float(math.sqrt((err ** 2).mean())),
    }
    pres_true, pres_est = stable["true"] > 0, stable["count"] > 0
    tp, fp = int((pres_true & pres_est).sum()), int((~pres_true & pres_est).sum())
    fn, tn = int((pres_true & ~pres_est).sum()), int((~pres_true & ~pres_est).sum())
    out["presence"] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                       "accuracy": (tp + tn) / max(tp + fp + fn + tn, 1),
                       "recall": tp / max(tp + fn, 1), "precision": tp / max(tp + fp, 1)}
    by = []
    for k, g in stable.groupby("true"):
        e = g["count"] - g["true"]
        by.append({"true": int(k), "samples": int(len(g)), "mean_estimate": float(g["count"].mean()),
                   "exact": float((e == 0).mean()), "within_1": float((e.abs() <= 1).mean())})
    out["by_true_count"] = by
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default=str(BASE / "logs"))
    ap.add_argument("--settle", type=float, default=15.0)
    ap.add_argument("--since", type=float, default=0.0)
    ap.add_argument("--save", help="write the result as JSON")
    a = ap.parse_args()
    r = evaluate(a.logs, a.settle, a.since)
    print(f"{r['samples']} settled estimates ({r['minutes']:.1f} min)")
    print(f"  exactly right      {r['exact_match']:.0%}")
    print(f"  within one device  {r['within_1']:.0%}")
    print(f"  mean absolute error {r['mae']:.2f}   bias {r['bias']:+.2f}   rmse {r['rmse']:.2f}")
    p = r["presence"]
    print(f"  'is anyone there?' accuracy {p['accuracy']:.0%} (caught {p['recall']:.0%} of occupied periods, "
          f"{p['precision']:.0%} of its alarms were right; false alarms {p['fp']}, misses {p['fn']})")
    print("  by true count:")
    for b in r["by_true_count"]:
        print(f"    true {b['true']}: mean estimate {b['mean_estimate']:.2f}, exact {b['exact']:.0%}, "
              f"within 1: {b['within_1']:.0%}  (n={b['samples']})")
    if a.save:
        Path(a.save).write_text(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
