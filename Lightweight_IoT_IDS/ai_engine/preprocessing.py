
"""
Project: Lightweight IoT Network Intrusion and Anomaly Detector
Module: Data preprocessing
Purpose: Validate and prepare network traffic features for ML.
"""

import pandas as pd

# Features selected for our initial network dataset
REQUIRED_FEATURES = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "connection_count",
    "duration_seconds",
]


def validate_data(data: pd.DataFrame) -> pd.DataFrame:
    """Check that the required network features exist."""

    missing = [
        feature for feature in REQUIRED_FEATURES
        if feature not in data.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    return data.copy()


def preprocess_data(data: pd.DataFrame) -> pd.DataFrame:
    """Clean and prepare network features."""

    data = validate_data(data)

    # Keep only the required numerical features
    data = data[REQUIRED_FEATURES].copy()

    # Convert values to numeric
    for column in REQUIRED_FEATURES:
        data[column] = pd.to_numeric(
            data[column], errors="coerce"
        )

    # Replace invalid or missing values
    data = data.fillna(0)

    # Network measurements cannot be negative
    for column in REQUIRED_FEATURES:
        if (data[column] < 0).any():
            raise ValueError(
                f"Negative values found in {column}"
            )

    return data


if __name__ == "__main__":
    print("IoT Network Data Preprocessing Module")
    print("Module loaded successfully.")
    print("Required features:", REQUIRED_FEATURES)
