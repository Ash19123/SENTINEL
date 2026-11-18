"""
Export the labelled traffic windows of the recordings as a small, privacy-safe CSV.

The raw captures contain network identifiers, so they are not published. This script turns each recording into
5-second windows (a new window every second) with the five features the detector uses and the ground truth:

    python experiments/export_dataset.py --runs experiments/data/runA experiments/data/runB experiments/data/runC_soak \
        --out datasets/sentinel_windows.csv

Columns
  run                 recording name
  t_end_s             end of the window, seconds since the recording started
  packet_count, bytes_sent, bytes_received, connection_count, duration_seconds   the five features
  phase               "baseline" (the first four minutes, used for learning) or "test"
  in_burst            1 if the window overlaps a commanded burst, else 0
  burst_id            index of that burst within the recording (blank outside bursts)
"""

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_rules import Run  # noqa: E402

W, HOP = 5.0, 1.0


def export(path):
    run = Run(path)
    rows, t = [], run.t0 + W
    while t <= run.end + 1e-9:
        feats = run.features(t - W, t)
        burst = next((i for i, b in enumerate(run.bursts) if t - W < b["end"] and t > b["onset"]), None)
        rows.append({"run": run.name, "t_end_s": round(t - run.t0, 1),
                     "packet_count": int(feats[0]), "bytes_sent": int(feats[1]), "bytes_received": int(feats[2]),
                     "connection_count": int(feats[3]), "duration_seconds": W,
                     "phase": "baseline" if t <= run.base_end + 1e-9 else "test",
                     "in_burst": int(burst is not None), "burst_id": "" if burst is None else burst})
        t += HOP
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    df = pd.concat([export(p) for p in a.runs], ignore_index=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"{len(df)} windows -> {a.out}")
    print(df.groupby(["run", "phase"]).agg(windows=("in_burst", "size"), burst_windows=("in_burst", "sum")))


if __name__ == "__main__":
    main()
