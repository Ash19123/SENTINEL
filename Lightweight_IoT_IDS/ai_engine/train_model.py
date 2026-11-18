
"""
Project: Lightweight IoT Network Intrusion and Anomaly Detector
Module: Isolation Forest model training
"""

from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from preprocessing import REQUIRED_FEATURES, preprocess_data

# Range check that complements the Isolation Forest: a tree ensemble cannot extrapolate, so a window
# far outside anything seen in training (e.g. 300 packets against a baseline maximum of 34) can look
# 'normal' to it. Any of the first four features above ENVELOPE_RATIO x its baseline maximum is flagged.
# 2.0 was the smallest margin with no false flags on either real recording (see experiments/).
ENVELOPE_RATIO = 2.0
ENVELOPE_FEATURES = REQUIRED_FEATURES[:4]   # duration_seconds is constant, so excluded


# Project directories
PROJECT_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_DIR / "models"
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"


def train_detector(
    data: pd.DataFrame,
    contamination: float = 0.02,
    window_seconds: float = None,
):
    """
    Train an Isolation Forest anomaly detector.

    Input:
        Clean normal-behaviour training observations.

    contamination:
        Provisional expected anomaly proportion used
        by Isolation Forest to set its decision threshold.
    """

    if not 0 < contamination <= 0.5:
        raise ValueError("Contamination must be between 0 and 0.5.")

    # Prepare network traffic features
    X = preprocess_data(data)

    if len(X) < 20:
        raise ValueError(
            "At least 20 observations are required for this initial model."
        )

    # Build the machine-learning pipeline
    detector = Pipeline([
        ("scaler", StandardScaler()),
        (
            "isolation_forest",
            IsolationForest(
                n_estimators=200,
                contamination=contamination,
                random_state=42
            )
        )
    ])

    # Train the model
    detector.fit(X)

    # Save the trained model and feature information
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    model_package = {
        "model": detector,
        "features": list(X.columns),
        "contamination": contamination,
        "window_seconds": window_seconds,
        "envelope_features": ENVELOPE_FEATURES,
        "envelope_max": [float(v) for v in X[ENVELOPE_FEATURES].max()],
        "envelope_ratio": ENVELOPE_RATIO,
    }

    joblib.dump(model_package, MODEL_PATH)

    print("Model training completed.")
    print(f"Training observations: {len(X)}")
    print(f"Model saved at: {MODEL_PATH}")

    return detector


def load_detector():
    """Load a previously trained model."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Trained model not found. Train the model first."
        )

    return joblib.load(MODEL_PATH)


if __name__ == "__main__":
    print("IoT Isolation Forest Training Module")
    print("Training function is ready.")
    print("Waiting for a validated network traffic dataset.")
