
"""
Project: Lightweight IoT Network Intrusion and Anomaly Detector
Module: Anomaly Detection
Purpose: Identify unusual IoT network observations.
"""

from pathlib import Path

import numpy as np
import pandas as pd

from preprocessing import preprocess_data
from train_model import load_detector


def detect_anomalies(data: pd.DataFrame) -> pd.DataFrame:
    """
    Analyse network observations using the trained model.

    Output:
        prediction:  1 = Normal, -1 = Anomaly
        status: Normal or Potential Anomaly
        anomaly_score: Higher values indicate more unusual observations.
    """

    # Load the saved model package
    model_package = load_detector()

    model = model_package["model"]
    expected_features = model_package["features"]

    # Prepare incoming observations
    X = preprocess_data(data)

    # Ensure feature order matches training
    X = X[expected_features]

    # Predict normal or anomalous behaviour
    predictions = model.predict(X)

    # Isolation Forest decision scores
    decision_scores = model.decision_function(X)

    # Convert scores so higher means more anomalous
    anomaly_scores = -decision_scores

    # Range check (hybrid detector). Models saved before it existed simply skip it.
    exceeded = np.zeros(len(X), dtype=bool)
    if model_package.get("envelope_max"):
        limits = np.array(model_package["envelope_max"]) * model_package.get("envelope_ratio", 2.0)
        exceeded = (X[model_package["envelope_features"]].to_numpy() > limits).any(axis=1)
        predictions = np.where(exceeded, -1, predictions)
        # a window outside the training range is at least as unusual as the model's saturated top score
        anomaly_scores = np.where(exceeded, np.maximum(anomaly_scores, 0.25), anomaly_scores)

    results = pd.DataFrame({
        "prediction": predictions,
        "anomaly_score": anomaly_scores,
        "range_exceeded": exceeded,
        "status": [
            "Potential Anomaly" if prediction == -1 else "Normal"
            for prediction in predictions
        ]
    }, index=data.index)

    return results


if __name__ == "__main__":
    print("IoT Anomaly Detection Module")
    print("Detection function loaded successfully.")
    print("Waiting for a trained model and network observations.")
