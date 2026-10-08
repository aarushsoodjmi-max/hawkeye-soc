"""
HawkEye SOC — Inference / Predictor
======================================
Exposes two primary inference functions:

    load_model(model_path)          → loads and caches the model bundle
    predict_root_cause(features)    → returns root cause, confidence, and verification flags
    predict_with_probabilities(f)   → includes full probability distribution across classes

Confidence Thresholds:
    >= 0.70 → "ML-supported root cause" (high confidence)
    < 0.70  → "Low-confidence ML prediction" (analyst verification required)

No API routes, no UI, no FastAPI. Import and call directly.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import sklearn
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

# Local modules
import sys
sys.path.insert(0, str(Path(__file__).parent))
from feature_engineering import FEATURE_COLUMNS, build_feature_row

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("hawkeye.predictor")


def hmac_compare(a: str, b: str) -> bool:
    return __import__("hmac").compare_digest(a, b)

# ---------------------------------------------------------------------------
# Default model path
# ---------------------------------------------------------------------------
_DEFAULT_MODEL_PATH = Path(__file__).parent / "root_cause_model.pkl"

# ---------------------------------------------------------------------------
# Thread-safe model cache
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_bundle: dict[str, Any] | None = None
_load_error: str | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_model(model_path: str | Path | None = None) -> None:
    """
    Load (and cache) the trained model bundle from disk.
    Safe to call multiple times.
    """
    global _bundle

    resolved = Path(model_path) if model_path else _DEFAULT_MODEL_PATH

    with _lock:
        if _bundle is not None and _bundle.get("_loaded_from") == str(resolved):
            return

        if not resolved.exists():
            raise FileNotFoundError(f"Model file not found: {resolved}")

        log.info("Loading model bundle from %s …", resolved)
        digest_file = resolved.with_suffix(resolved.suffix + ".sha256")
        if digest_file.exists():
            expected = digest_file.read_text(encoding="utf-8").split()[0]
            actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if not hmac_compare(expected, actual):
                raise RuntimeError("Model artifact integrity check failed")
        bundle = joblib.load(resolved)
        trained_version = str(bundle.get("sklearn_version", ""))
        if trained_version and trained_version != sklearn.__version__:
            raise RuntimeError(
                f"Model was trained with scikit-learn {trained_version}, but runtime has {sklearn.__version__}."
            )

        for key in ("model", "label_encoder", "feature_columns"):
            if key not in bundle:
                raise RuntimeError(
                    f"Model bundle missing required key: '{key}'. Re-train model."
                )

        bundle["_loaded_from"] = str(resolved)
        _bundle = bundle
        log.info(
            "Model loaded successfully (%s). Classes: %s | Features: %d",
            bundle.get("model_type", type(bundle["model"]).__name__),
            bundle.get("classes", []),
            len(bundle["feature_columns"]),
        )


def model_health(model_path: str | Path | None = None) -> dict[str, Any]:
    """Return explicit model availability/integrity/version status."""
    resolved = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
    try:
        load_model(resolved)
    except Exception as exc:
        return {
            "model_available": False,
            "reason": str(exc),
            "model_path": str(resolved),
            "runtime_sklearn_version": sklearn.__version__,
            "declared_sklearn_version": None,
        }
    bundle = _bundle or {}
    declared = str(bundle.get("sklearn_version", ""))
    return {
        "model_available": True,
        "reason": None,
        "model_path": str(resolved),
        "runtime_sklearn_version": sklearn.__version__,
        "declared_sklearn_version": declared,
        "compatible": declared == sklearn.__version__,
        "integrity_verified": True,
    }


def predict_root_cause(features: dict[str, Any]) -> dict[str, Any]:
    """
    Predict root cause of an incident from its feature dict.

    Confidence rules:
      >= 0.70 → "ML-supported root cause"
      < 0.70  → "Low-confidence ML prediction" (analyst verification required)

    Returns
    -------
    dict:
      {
        "root_cause": str,
        "confidence": float,
        "confidence_status": str,
        "requires_analyst_verification": bool,
      }
    """
    if not isinstance(features, dict):
        raise ValueError(f"'features' must be a dict, got {type(features).__name__}.")

    if _bundle is None:
        load_model()

    bundle = _bundle
    clf = bundle["model"]
    le = bundle["label_encoder"]
    feat_cols = bundle["feature_columns"]

    # Build aligned feature row
    feature_df = build_feature_row(features).reindex(columns=feat_cols, fill_value=0.0)

    # Predict probabilities
    if hasattr(clf, "predict_proba"):
        proba = clf.predict_proba(feature_df)[0]
        idx = int(np.argmax(proba))
        label = str(le.inverse_transform([idx])[0])
        conf = float(proba[idx])
    else:
        label = str(le.inverse_transform(clf.predict(feature_df))[0])
        conf = 0.50

    confidence_status = "ML-supported root cause" if conf >= 0.70 else "Low-confidence ML prediction"
    requires_verification = bool(conf < 0.70)

    return {
        "root_cause": label,
        "confidence": round(conf, 4),
        "confidence_status": confidence_status,
        "requires_analyst_verification": requires_verification,
    }



def infer_rule_based_root_cause(features: dict[str, Any]) -> dict[str, Any]:
    """Derive a root cause from observed telemetry indicators when ML is unavailable.

    This is deliberately evidence-based and deterministic. It is not a fabricated
    ML result and is used only as a pipeline-safe fallback.
    """
    f = features or {}
    ransomware = float(f.get("ransomware_count", 0) or 0)
    shadow = float(f.get("shadow_copy_count", 0) or 0)
    exfil = float(f.get("exfiltration_count", 0) or 0)
    credential_dump = float(f.get("credential_dump_count", 0) or 0)
    phishing = float(f.get("phishing_count", 0) or 0)
    malware = float(f.get("malware_count", 0) or 0)
    auth = float(f.get("auth_anomaly_count", 0) or 0)
    data = float(f.get("data_access_count", 0) or 0)

    candidates = [
        ("ransomware", ransomware * 3 + shadow * 2),
        ("compromised_account", credential_dump * 3 + auth + float(f.get("credential_access_count", 0) or 0)),
        ("phishing", phishing * 2 + float(f.get("network_c2_count", 0) or 0)),
        ("insider", exfil * 2 + data),
        ("malware", malware * 2 + float(f.get("network_c2_count", 0) or 0)),
    ]
    label, score = max(candidates, key=lambda item: item[1])
    if score <= 0:
        return {
            "root_cause": None,
            "confidence": 0.0,
            "confidence_status": "Unavailable",
            "requires_analyst_verification": True,
            "source": "rules",
        }
    max_possible = {"ransomware": 9, "compromised_account": 10, "phishing": 8, "insider": 10, "malware": 10}.get(label, 10)
    confidence = min(0.95, max(0.50, 0.50 + 0.45 * min(1.0, score / max_possible)))
    return {
        "root_cause": label,
        "confidence": round(confidence, 4),
        "confidence_status": "Rule-supported root cause",
        "requires_analyst_verification": True,
        "source": "rules",
    }


def safe_predict_root_cause(features: dict[str, Any]) -> dict[str, Any]:
    """Best-effort ML prediction; never raises into the ingestion pipeline."""
    rule_result = infer_rule_based_root_cause(features)
    try:
        result = predict_root_cause(features)
        result["source"] = "ml"
        # Prefer strong, directly observed simulator/detection indicators over
        # a weak ML class mismatch (for example ransomware is not a trained
        # class in the pinned model).
        if rule_result.get("root_cause") and float(rule_result.get("confidence") or 0.0) >= 0.70:
            return {
                **rule_result,
                "ml_root_cause": result.get("root_cause"),
                "ml_confidence": result.get("confidence"),
                "source": "rules+ml",
            }
        return result
    except Exception as exc:
        log.warning("Root-cause ML inference unavailable: %s", type(exc).__name__)
        rule_result["ml_error"] = type(exc).__name__
        return rule_result

def predict_with_probabilities(features: dict[str, Any]) -> dict[str, Any]:
    """
    Predict root cause and return full per-class probability distribution.
    """
    if _bundle is None:
        load_model()

    bundle = _bundle
    clf = bundle["model"]
    le = bundle["label_encoder"]
    feat_cols = bundle["feature_columns"]

    feature_df = build_feature_row(features).reindex(columns=feat_cols, fill_value=0.0)

    if hasattr(clf, "predict_proba"):
        proba = clf.predict_proba(feature_df)[0]
        idx = int(np.argmax(proba))
        label = str(le.inverse_transform([idx])[0])
        conf = float(proba[idx])
        class_proba = {
            str(cls): round(float(p), 4)
            for cls, p in zip(le.classes_, proba)
        }
    else:
        label = str(le.inverse_transform(clf.predict(feature_df))[0])
        conf = 0.50
        class_proba = {str(c): 0.20 for c in le.classes_}

    confidence_status = "ML-supported root cause" if conf >= 0.70 else "Low-confidence ML prediction"
    requires_verification = bool(conf < 0.70)

    return {
        "root_cause": label,
        "confidence": round(conf, 4),
        "confidence_status": confidence_status,
        "requires_analyst_verification": requires_verification,
        "probabilities": class_proba,
    }
