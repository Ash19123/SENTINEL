
"""
Project: Lightweight IoT Network Intrusion and Anomaly Detector
Module: Model Evaluation
Purpose: Measure anomaly detection performance.
"""

from pathlib import Path

import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score
)

from preprocessing import preprocess_data
from train_model import load_detector


def evaluate_detector(
    test_data: pd.DataFrame,
    label_column: str = "label"
) -> dict:
    """
    Evaluate the trained detector against labelled test data.

    Labels:
        0 = Normal
        1 = Anomaly

    The test data must not have been used for training.
    """

    if label_column not in test_data.columns:
        raise ValueError(
            f"Missing required label column: {label_column}"
        )

    # Separate true labels from network features
    y_true = pd.to_numeric(
        test_data[label_column],
        errors="coerce"
    )

    if y_true.isna().any():
        raise ValueError("Test labels contain missing or invalid values.")

    if not set(y_true.unique()).issubset({0, 1}):
        raise ValueError("Labels must contain only 0 (normal) or 1 (anomaly).")

    y_true = y_true.astype(int)

    if len(y_true) == 0:
        raise ValueError("Test dataset is empty.")

    if len(y_true.unique()) < 2:
        raise ValueError(
            "Evaluation requires both normal and anomalous observations."
        )

    # Prepare test features
    X = preprocess_data(test_data)

    # Load trained model
    model_package = load_detector()
    model = model_package["model"]

    X = X[model_package["features"]]

    # Obtain model predictions
    raw_predictions = model.predict(X)

    # Convert Isolation Forest output:
    # +1 = Normal (0)
    # -1 = Anomaly (1)
    y_pred = (raw_predictions == -1).astype(int)

    # Higher scores represent more anomalous observations
    anomaly_scores = -model.decision_function(X)

    # Calculate confusion matrix
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    # Calculate evaluation metrics
    accuracy = accuracy_score(y_true, y_pred)

    precision = precision_score(
        y_true, y_pred, zero_division=0
    )

    recall = recall_score(
        y_true, y_pred, zero_division=0
    )

    f1 = f1_score(
        y_true, y_pred, zero_division=0
    )

    false_positive_rate = (
        fp / (fp + tn) if (fp + tn) > 0 else 0.0
    )

    # ROC-AUC is calculated using anomaly scores
    roc_auc = roc_auc_score(
        y_true,
        anomaly_scores
    )

    results = {
        "observations": len(y_true),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": false_positive_rate,
        "roc_auc": roc_auc,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp)
    }

    print("\n========== AI MODEL EVALUATION ==========")

    for metric, value in results.items():
        if isinstance(value, float):
            print(f"{metric}: {value:.4f}")
        else:
            print(f"{metric}: {value}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=["Normal", "Anomaly"],
            zero_division=0
        )
    )

    # Save evaluation results
    project_dir = Path(__file__).resolve().parent.parent
    logs_dir = project_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    pd.DataFrame([results]).to_csv(
        logs_dir / "model_evaluation.csv",
        index=False
    )

    print("Evaluation results saved to logs/model_evaluation.csv")

    return results


if __name__ == "__main__":
    print("IoT Model Evaluation Module")
    print("Evaluation function loaded successfully.")
    print("Waiting for labelled test observations and a trained model.")
