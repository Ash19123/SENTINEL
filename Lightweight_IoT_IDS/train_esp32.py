"""
Train the Isolation Forest on the ESP32's own normal traffic, as captured by
Wireshark:  python wireshark_ids.py --collect   (leave it running ~3 minutes)
Then:       python train_esp32.py
"""

import sys
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "ai_engine"))

from train_model import train_detector  # noqa: E402

path = BASE_DIR / "datasets" / "esp32_normal.csv"
if not path.exists():
    sys.exit("No baseline yet. Run `python wireshark_ids.py --collect` first.")

data = pd.read_csv(path)
print(f"Baseline windows: {len(data)}")
print(data.describe().loc[["mean", "std", "min", "max"]].round(1).to_string())

# 5%: puts the threshold inside the normal range so real floods fall clearly outside it;
# wireshark_ids.py additionally needs 2 consecutive flagged windows before alerting.
window = float(data["duration_seconds"].median()) if "duration_seconds" in data else None
train_detector(data, contamination=0.05, window_seconds=window)
