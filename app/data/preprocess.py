"""
preprocess.py
--------------
Lightweight preprocessing utilities for the HawkEye SOC alert dataset
(alerts.csv, produced by generate_dataset.py).

This module intentionally does ONLY basic data-engineering steps:
loading, cleaning, encoding the severity column, and sorting by time.

Out of scope by design (see project rules):
    - No alert correlation / incident linking logic.
    - No prediction, scoring, or modeling of any kind.
    - No sklearn (or any ML library) usage.
    - No API layer.

Functions:
    load_dataset(path)    -> pd.DataFrame
    clean_data(df)        -> pd.DataFrame
    encode_severity(df)   -> pd.DataFrame
    sort_by_timestamp(df) -> pd.DataFrame
"""

import os
import pandas as pd

DEFAULT_DATASET_PATH = os.path.join(os.path.dirname(__file__), "alerts.csv")

EXPECTED_COLUMNS = [
    "timestamp", "user", "device", "ip_address", "alert_type",
    "severity", "source", "root_cause", "incident_id",
]

# Ordinal severity mapping used by encode_severity(). Plain dict lookup --
# no sklearn LabelEncoder/OrdinalEncoder involved.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def load_dataset(path: str = DEFAULT_DATASET_PATH) -> pd.DataFrame:
    """Load the raw alerts CSV into a pandas DataFrame.

    Parameters
    ----------
    path : str
        Path to the alerts CSV file. Defaults to alerts.csv sitting
        alongside this module.

    Returns
    -------
    pd.DataFrame
        The dataset as read by pandas (only pandas' own dtype
        inference is applied -- no cleaning happens here).
    """
    df = pd.read_csv(path)
    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Basic cleaning of the raw dataset.

    Steps performed:
        1. Strip stray whitespace from column names.
        2. Strip whitespace from every string (object) column.
        3. Parse 'timestamp' into a proper datetime dtype.
        4. Normalize empty/missing 'incident_id' values to the literal
           string 'NONE' (alerts not part of any incident).
        5. Drop exact duplicate rows.
        6. Drop rows whose timestamp failed to parse (corrupt records).

    Parameters
    ----------
    df : pd.DataFrame
        Raw dataset, e.g. as returned by load_dataset().

    Returns
    -------
    pd.DataFrame
        A cleaned copy of the dataset (input is not mutated).
    """
    df = df.copy()

    df.columns = [c.strip() for c in df.columns]

    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].astype(str).str.strip()

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    if "incident_id" in df.columns:
        empty_mask = df["incident_id"].isna() | df["incident_id"].astype(str).str.strip().isin(["", "NONE", "none", "nan", "NaN"])
        if empty_mask.any():
            # Assign unique incident ID per row so benign/unassigned events do not collapse into one training incident
            df.loc[empty_mask, "incident_id"] = [f"BENIGN-{i+1:05d}" for i in range(empty_mask.sum())]

    df = df.drop_duplicates()

    if "timestamp" in df.columns:
        df = df[df["timestamp"].notna()]

    df = df.reset_index(drop=True)
    return df


def encode_severity(df: pd.DataFrame) -> pd.DataFrame:
    """Add a numeric ordinal encoding of the 'severity' column.

    Mapping: low=1, medium=2, high=3, critical=4. Any unrecognized or
    missing severity value is encoded as 0. Implemented as a plain
    dictionary mapping -- sklearn is not used.

    Parameters
    ----------
    df : pd.DataFrame
        Dataset containing a 'severity' column.

    Returns
    -------
    pd.DataFrame
        A copy of the dataset with an added 'severity_encoded' column.
    """
    df = df.copy()
    if "severity" in df.columns:
        df["severity_encoded"] = (
            df["severity"].str.lower().map(SEVERITY_ORDER).fillna(0).astype(int)
        )
    return df


def sort_by_timestamp(df: pd.DataFrame) -> pd.DataFrame:
    """Sort the dataset chronologically (ascending) by 'timestamp'.

    Parameters
    ----------
    df : pd.DataFrame
        Dataset containing a 'timestamp' column. If it is not already
        a datetime dtype, it will be parsed.

    Returns
    -------
    pd.DataFrame
        A copy of the dataset sorted ascending by timestamp, with the
        index reset.
    """
    df = df.copy()
    if "timestamp" in df.columns:
        if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    return df


if __name__ == "__main__":
    # Simple manual smoke test when run directly:
    #   python preprocess.py
    raw = load_dataset()
    cleaned = clean_data(raw)
    encoded = encode_severity(cleaned)
    result = sort_by_timestamp(encoded)
    print(result.head())
    print(f"Rows: {len(result)} | Columns: {list(result.columns)}")
