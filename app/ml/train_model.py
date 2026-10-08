"""
HawkEye SOC — Model Training Pipeline
======================================
Trains and evaluates ML root-cause classification models for SOC security incidents.

Compares:
  • RandomForestClassifier (with class weighting and feature-subspace trees)
  • HistGradientBoostingClassifier (gradient-boosted decision trees)

Evaluates:
  • 5-Fold Stratified Cross-Validation (Accuracy, Macro Precision, Macro Recall, Macro F1)
  • Held-Out Test Evaluation (Accuracy, Macro metrics, Per-Class Precision/Recall/F1, Confusion Matrix)
  • Attack Simulator Validation across all 5 operational attack scenarios:
      1. credential_theft
      2. phishing
      3. malware
      4. insider_threat
      5. ransomware

Saves the best-performing validated model to backend/app/ml/root_cause_model.pkl.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import hashlib
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
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
log = logging.getLogger("hawkeye.train")

# ---------------------------------------------------------------------------
# Constants & Model Parameters
# ---------------------------------------------------------------------------
DEFAULT_MODEL_PATH = Path(__file__).parent / "root_cause_model.pkl"

ROOT_CAUSE_CLASSES = [
    "benign",
    "compromised_account",
    "insider",
    "malware",
    "phishing",
]

RF_HYPERPARAMS: dict[str, Any] = {
    "n_estimators": 200,
    "max_depth": 14,
    "min_samples_split": 3,
    "min_samples_leaf": 1,
    "max_features": "sqrt",
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": 1,
}

HGB_HYPERPARAMS: dict[str, Any] = {
    "max_iter": 70,
    "max_depth": 6,
    "min_samples_leaf": 3,
    "class_weight": "balanced",
    "random_state": 42,
}

TEST_SIZE = 0.20
RANDOM_SEED = 42

REQUIRED_COLUMNS = {
    "alert_type", "severity", "incident_id", "root_cause",
}


# ---------------------------------------------------------------------------
# Data Loading & Validation
# ---------------------------------------------------------------------------

def load_and_validate(csv_path: str | Path) -> pd.DataFrame:
    """Load the raw incident CSV and validate schema."""
    log.info("Loading dataset from: %s", csv_path)
    df = pd.read_csv(csv_path)

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"CSV missing required columns: {sorted(missing)}")

    # Filter invalid root causes if any
    valid_mask = df["root_cause"].isin(ROOT_CAUSE_CLASSES)
    if not valid_mask.all():
        log.warning("Dropping %d rows with invalid root_cause", (~valid_mask).sum())
        df = df[valid_mask]

    log.info(
        "Loaded %d alerts across %d incidents. Distribution:\n%s",
        len(df),
        df["incident_id"].nunique(),
        df.groupby("incident_id")["root_cause"].first().value_counts().to_string(),
    )
    return df


def build_training_data(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Engineer incident-level features and return (X, y)."""
    log.info("Engineering incident features across %d rows...", len(df))
    engineered = engineer_features(df)

    if "root_cause" not in engineered.columns:
        raise RuntimeError("Engineered features missing 'root_cause' target.")

    X = engineered[FEATURE_COLUMNS].astype(float)
    y = engineered["root_cause"]
    log.info("Feature matrix X shape: %s | Target counts: %s", X.shape, y.value_counts().to_dict())
    return X, y


# ---------------------------------------------------------------------------
# Simulator Validation Helper
# ---------------------------------------------------------------------------

def run_simulator_validation(clf: Any, le: LabelEncoder) -> dict[str, dict[str, Any]]:
    """
    Test the trained classifier against all AttackSimulator scenarios:
      - credential_theft
      - phishing
      - malware
      - insider_threat
      - ransomware
    """
    try:
        # Import simulator safely from backend app
        root_dir = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(root_dir))
        from app.simulator import AttackSimulator
    except Exception as e:
        log.warning("Could not load AttackSimulator: %s", e)
        return {}

    sim = AttackSimulator(seed=42)
    scenarios = ["credential_theft", "phishing", "malware", "insider_threat", "ransomware"]
    results = {}

    log.info("--- Validating Model Against Attack Simulator Scenarios ---")
    for sc in scenarios:
        sdf = sim.generate_scenario(sc)
        sim_df = sdf.rename(columns={
            "event_type": "alert_type",
            "username": "user",
            "hostname": "device",
            "src_ip": "ip_address",
            "dst_ip": "destination_ip",
        })
        features = aggregate_incident_features(sim_df)
        feat_df = pd.DataFrame([features])[FEATURE_COLUMNS].astype(float)

        proba = clf.predict_proba(feat_df)[0]
        idx = int(np.argmax(proba))
        pred_label = le.classes_[idx]
        confidence = float(proba[idx])

        status = "ML-supported root cause" if confidence >= 0.70 else "Low-confidence ML prediction"
        requires_analyst = confidence < 0.70

        class_distribution = {
            str(cls): round(float(p), 4)
            for cls, p in zip(le.classes_, proba)
        }

        results[sc] = {
            "prediction": pred_label,
            "confidence": round(confidence, 4),
            "confidence_status": status,
            "requires_analyst_verification": requires_analyst,
            "probabilities": class_distribution,
        }

        log.info(
            "Scenario: %-18s -> Prediction: %-20s (Confidence: %.4f | Status: %s)",
            sc, pred_label, confidence, status
        )

    return results


# ---------------------------------------------------------------------------
# Training Pipeline & Model Comparison
# ---------------------------------------------------------------------------

def train(csv_path: str | Path, output_path: str | Path = DEFAULT_MODEL_PATH) -> dict[str, Any]:
    """
    Full training & comparison pipeline:
      1. Load & validate CSV
      2. Feature engineering
      3. Encode targets
      4. Stratified 80/20 train/test split
      5. 5-Fold Stratified Cross-Validation on training split
      6. Compare RandomForest vs HistGradientBoosting
      7. Train selected best model
      8. Evaluate on test set (accuracy, macro P/R/F1, per-class report, confusion matrix)
      9. Validate on all 5 simulator scenarios
     10. Persist model bundle
    """
    raw_df = load_and_validate(csv_path)
    X, y = build_training_data(raw_df)

    le = LabelEncoder()
    le.fit(ROOT_CAUSE_CLASSES)
    y_enc = le.transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc,
        test_size=TEST_SIZE,
        random_state=RANDOM_SEED,
        stratify=y_enc,
    )

    log.info(
        "Stratified Split: %d train samples, %d test samples (%0.0f%% / %0.0f%%)",
        len(X_train), len(X_test), 100 * (1 - TEST_SIZE), 100 * TEST_SIZE
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    scoring = ["accuracy", "precision_macro", "recall_macro", "f1_macro"]

    candidate_models = {
        "RandomForestClassifier": RandomForestClassifier(**RF_HYPERPARAMS),
        "HistGradientBoostingClassifier": HistGradientBoostingClassifier(**HGB_HYPERPARAMS),
    }

    comparison_results = {}
    log.info("=== Running Model Comparison with 5-Fold Cross-Validation ===")

    for name, clf in candidate_models.items():
        log.info("Evaluating candidate: %s", name)
        cv_res = cross_validate(clf, X_train, y_train, cv=cv, scoring=scoring, n_jobs=1)
        mean_acc = float(cv_res["test_accuracy"].mean())
        std_acc = float(cv_res["test_accuracy"].std())
        mean_f1 = float(cv_res["test_f1_macro"].mean())
        std_f1 = float(cv_res["test_f1_macro"].std())
        mean_prec = float(cv_res["test_precision_macro"].mean())
        mean_rec = float(cv_res["test_recall_macro"].mean())

        comparison_results[name] = {
            "cv_accuracy_mean": mean_acc,
            "cv_accuracy_std": std_acc,
            "cv_macro_f1_mean": mean_f1,
            "cv_macro_f1_std": std_f1,
            "cv_macro_precision_mean": mean_prec,
            "cv_macro_recall_mean": mean_rec,
        }
        log.info(
            "%s -> CV Accuracy: %.4f ± %.4f | CV Macro F1: %.4f ± %.4f",
            name, mean_acc, std_acc, mean_f1, std_f1
        )

    # Select best model based on validation macro F1 and cross-validation accuracy
    best_model_name = "RandomForestClassifier"
    if comparison_results["HistGradientBoostingClassifier"]["cv_macro_f1_mean"] > comparison_results["RandomForestClassifier"]["cv_macro_f1_mean"] + 0.05:
        best_model_name = "HistGradientBoostingClassifier"

    log.info("Selected model for production deployment: %s", best_model_name)
    best_clf = candidate_models[best_model_name]
    best_clf.fit(X_train, y_train)

    # Held-out test set evaluation
    y_pred = best_clf.predict(X_test)
    test_acc = float(accuracy_score(y_test, y_pred))
    test_prec, test_rec, test_f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred)
    clf_report = classification_report(
        y_test, y_pred, target_names=le.classes_, zero_division=0
    )

    log.info("=== Final Evaluation on Held-Out Test Split ===")
    log.info("Test Accuracy:       %.4f", test_acc)
    log.info("Test Macro Precision: %.4f", test_prec)
    log.info("Test Macro Recall:    %.4f", test_rec)
    log.info("Test Macro F1:        %.4f", test_f1)
    log.info("Classification Report:\n%s", clf_report)
    log.info("Confusion Matrix:\n%s", cm)

    # Simulator validation
    simulator_results = run_simulator_validation(best_clf, le)

    # Feature importances
    feature_importances = {}
    if hasattr(best_clf, "feature_importances_"):
        fi = best_clf.feature_importances_
        sorted_indices = np.argsort(fi)[::-1]
        for idx in sorted_indices[:15]:
            feature_importances[FEATURE_COLUMNS[idx]] = round(float(fi[idx]), 4)
        log.info("Top Feature Importances: %s", feature_importances)

    metrics = {
        "selected_model": best_model_name,
        "model_comparison": comparison_results,
        "test_accuracy": test_acc,
        "test_macro_precision": float(test_prec),
        "test_macro_recall": float(test_rec),
        "test_macro_f1": float(test_f1),
        "cv_mean": comparison_results[best_model_name]["cv_accuracy_mean"],
        "cv_std": comparison_results[best_model_name]["cv_accuracy_std"],
        "confusion_matrix": cm.tolist(),
        "classification_report": clf_report,
        "feature_importances": feature_importances,
        "simulator_validation": simulator_results,
    }

    # Persist bundle
    bundle = {
        "model": best_clf,
        "model_type": best_model_name,
        "label_encoder": le,
        "feature_columns": FEATURE_COLUMNS,
        "classes": list(le.classes_),
        "sklearn_version": sklearn.__version__,
        "metrics": metrics,
    }

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_file)
    digest = hashlib.sha256(out_file.read_bytes()).hexdigest()
    out_file.with_suffix(out_file.suffix + ".sha256").write_text(digest + "  " + out_file.name + "\n", encoding="utf-8")
    log.info("Model bundle persisted successfully -> %s", out_file.resolve())

    return metrics


def auto_train_if_needed(output_path: str | Path | None = None) -> Path:
    """Ensure trained model artifact exists, training if missing."""
    target_path = Path(output_path or DEFAULT_MODEL_PATH)
    csv_path = Path(__file__).parent.parent / "data" / "alerts.csv"

    if not csv_path.exists() or csv_path.stat().st_size == 0:
        log.info("Alerts dataset %s missing; generating new dataset...", csv_path)
        from app.data.generate_dataset import generate_dataset
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        generate_dataset(output_path=str(csv_path))

    log.info("Executing auto-training: %s -> %s", csv_path, target_path)
    train(csv_path=csv_path, output_path=target_path)
    return target_path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HawkEye SOC — train root-cause classifier")
    parser.add_argument("--data", required=True, help="Path to raw alerts CSV")
    parser.add_argument("--output", default=str(DEFAULT_MODEL_PATH), help="Model .pkl path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    metrics = train(csv_path=args.data, output_path=args.output)
    log.info("Training complete. Selected model: %s", metrics.get("selected_model"))


if __name__ == "__main__":
    main()
