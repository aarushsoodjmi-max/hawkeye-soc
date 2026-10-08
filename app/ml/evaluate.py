"""
HawkEye SOC — Model Evaluation Suite
======================================
Comprehensive evaluation utility for the trained root-cause classifier.

Calculates:
  • Accuracy
  • Macro Precision, Macro Recall, Macro F1
  • Per-Class Precision, Recall, F1, and Support
  • Confusion Matrix (formatted table)
  • Top Feature Importances
  • Attack Simulator Validation across all operational scenarios:
      credential_theft, phishing, malware, insider_threat, ransomware
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.preprocessing import LabelEncoder

# Local modules
sys.path.insert(0, str(Path(__file__).parent))
from feature_engineering import FEATURE_COLUMNS, aggregate_incident_features, engineer_features

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("hawkeye.evaluate")


def evaluate_model(
    clf: Any,
    label_encoder: LabelEncoder,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    feature_names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Compute and log comprehensive evaluation metrics for a fitted classifier.
    """
    class_names = list(label_encoder.classes_)
    y_pred = clf.predict(X_test)

    # Core scores
    acc = float(accuracy_score(y_test, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )

    log.info("Test Accuracy:       %.4f (%.1f%%)", acc, acc * 100)
    log.info("Test Macro Precision: %.4f", p_macro)
    log.info("Test Macro Recall:    %.4f", r_macro)
    log.info("Test Macro F1:        %.4f", f1_macro)

    # Classification report
    labels = list(range(len(class_names)))
    report = classification_report(
        y_test,
        y_pred,
        labels=labels,
        target_names=class_names,
        zero_division=0,
    )
    log.info("Classification Report:\n%s", report)

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    _log_confusion_matrix(cm, class_names)

    # Feature importances
    fi_dict = {}
    if hasattr(clf, "feature_importances_") and feature_names:
        fi = clf.feature_importances_
        pairs = sorted(zip(feature_names, fi), key=lambda x: x[1], reverse=True)
        _log_feature_importances(fi, feature_names)
        fi_dict = {name: round(float(val), 4) for name, val in pairs[:15]}

    return {
        "accuracy": acc,
        "macro_precision": float(p_macro),
        "macro_recall": float(r_macro),
        "macro_f1": float(f1_macro),
        "report": report,
        "confusion_matrix": cm.tolist(),
        "feature_importances": fi_dict,
    }


def per_class_metrics(
    clf: Any,
    label_encoder: LabelEncoder,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
) -> list[dict[str, Any]]:
    """Return precision, recall, F1, and support for each class."""
    class_names = list(label_encoder.classes_)
    y_pred = clf.predict(X_test)

    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, y_pred, labels=list(range(len(class_names))), zero_division=0
    )

    return [
        {
            "class": class_names[i],
            "precision": round(float(precision[i]), 4),
            "recall": round(float(recall[i]), 4),
            "f1": round(float(f1[i]), 4),
            "support": int(support[i]),
        }
        for i in range(len(class_names))
    ]


def evaluate_simulator_scenarios(clf: Any, label_encoder: LabelEncoder) -> dict[str, dict[str, Any]]:
    """Evaluate against the 5 AttackSimulator scenarios."""
    try:
        root_dir = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(root_dir))
        from app.simulator import AttackSimulator
    except Exception as e:
        log.warning("Could not load AttackSimulator: %s", e)
        return {}

    sim = AttackSimulator(seed=42)
    scenarios = ["credential_theft", "phishing", "malware", "insider_threat", "ransomware"]
    results = {}

    log.info("--- Evaluating Simulator Scenarios ---")
    for sc in scenarios:
        sdf = sim.generate_scenario(sc)
        sim_df = sdf.rename(columns={
            "event_type": "alert_type",
            "username": "user",
            "hostname": "device",
            "src_ip": "ip_address",
            "dst_ip": "destination_ip",
        })
        feats = aggregate_incident_features(sim_df)
        feat_df = pd.DataFrame([feats])[FEATURE_COLUMNS].astype(float)

        proba = clf.predict_proba(feat_df)[0]
        idx = int(np.argmax(proba))
        pred_label = label_encoder.classes_[idx]
        conf = float(proba[idx])

        status = "ML-supported root cause" if conf >= 0.70 else "Low-confidence ML prediction"
        requires_analyst = conf < 0.70

        class_dist = {
            str(c): round(float(p), 4) for c, p in zip(label_encoder.classes_, proba)
        }

        results[sc] = {
            "prediction": pred_label,
            "confidence": round(conf, 4),
            "confidence_status": status,
            "requires_analyst_verification": requires_analyst,
            "probabilities": class_dist,
        }
        log.info(
            "Scenario: %-18s -> Prediction: %-20s (Confidence: %.4f | Status: %s)",
            sc, pred_label, conf, status
        )

    return results


def _log_confusion_matrix(cm: np.ndarray, class_names: list[str]) -> None:
    col_width = max(len(name) for name in class_names) + 2
    header_row = f"{'Actual ↓':<{col_width}}" + "".join(
        f"{name:^{col_width}}" for name in class_names
    )
    separator = "-" * len(header_row)
    rows = [header_row, separator]
    for i, row_label in enumerate(class_names):
        row_str = f"{row_label:<{col_width}}" + "".join(
            f"{val:^{col_width}}" for val in cm[i]
        )
        rows.append(row_str)
    log.info("Confusion Matrix:\n%s", "\n".join(rows))


def _log_feature_importances(importances: np.ndarray, feature_names: list[str], top_n: int = 12) -> None:
    pairs = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:top_n]
    lines = [f"  {'Feature':<30} Importance"]
    lines.append("  " + "-" * 42)
    for name, imp in pairs:
        bar = "█" * int(imp * 40)
        lines.append(f"  {name:<30} {imp:.4f}  {bar}")
    log.info("Top-%d Feature Importances:\n%s", top_n, "\n".join(lines))


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HawkEye SOC — evaluate root-cause model")
    parser.add_argument(
        "--model",
        default=str(Path(__file__).parent / "root_cause_model.pkl"),
        help="Path to saved model bundle (.pkl)",
    )
    parser.add_argument(
        "--data",
        default=str(Path(__file__).parent.parent / "data" / "alerts.csv"),
        help="Path to evaluation data CSV",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    log.info("Loading model bundle from: %s", args.model)
    bundle = joblib.load(args.model)
    clf = bundle["model"]
    le = bundle["label_encoder"]
    feat_cols = bundle.get("feature_columns", FEATURE_COLUMNS)

    log.info("Loading evaluation dataset: %s", args.data)
    raw_df = pd.read_csv(args.data)
    engineered = engineer_features(raw_df)

    if "root_cause" not in engineered.columns:
        log.error("Evaluation CSV must contain 'root_cause' column.")
        sys.exit(1)

    X = engineered[feat_cols].astype(float)
    y = le.transform(engineered["root_cause"])

    metrics = evaluate_model(clf, le, X, y, feature_names=feat_cols)
    per_class = per_class_metrics(clf, le, X, y)
    sim_eval = evaluate_simulator_scenarios(clf, le)

    log.info("Evaluation Complete. Final accuracy: %.4f, Macro F1: %.4f", metrics["accuracy"], metrics["macro_f1"])


if __name__ == "__main__":
    main()
