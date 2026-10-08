"""
HawkEye SOC — Dataset Generation & Preprocessing
===================================================
Synthetic SOC alert dataset generation (``generate_dataset.py``) and
lightweight preprocessing utilities (``preprocess.py``) for
``alerts.csv``.

This directory also serves as the backend's data directory (see
``app/config.py`` — ``ALERTS_CSV_PATH``).

Integration note: this __init__.py was added during backend integration
so the dataset engine is importable as ``app.data``. No business logic
was added, removed, or changed.
"""

from .preprocess import load_dataset, clean_data, encode_severity, sort_by_timestamp

__all__ = [
    "load_dataset",
    "clean_data",
    "encode_severity",
    "sort_by_timestamp",
]
