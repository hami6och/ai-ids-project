#!/usr/bin/env python3
"""
AI-IDS — Prediction Engine
===========================
Loads trained models and exposes a predict() function
that each detector calls after extract_features().

Usage in detectors :
    from ai.predict import predict

    features = extract_features(ip)
    if features:
        result = predict("syn", features)
        if result["is_attack"]:
            print(f"🤖 AI [{result['confidence']:.0%}] {result['alert_type']}")

Standalone check :
    python ai/predict.py
"""

import pickle
from pathlib import Path
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import AI_THRESHOLD, MODELS_DIR as _MODELS_DIR

# =========================
# CONFIG
# =========================
MODELS_DIR   = Path(_MODELS_DIR)    # confidence required to flag as attack
                       # raise to 0.90 to reduce false positives
                       # lower to 0.70 to catch more attacks

# =========================
# MODEL REGISTRY
# Loaded once at startup, cached in memory
# =========================
_registry: dict = {}

def _load_model(detector: str) -> dict | None:
    """Load a model from disk into the registry."""
    path = MODELS_DIR / f"{detector}_model.pkl"
    if not path.exists():
        return None
    try:
        with open(path, "rb") as f:
            data = pickle.load(f)
        _registry[detector] = data
        return data
    except Exception as e:
        print(f"⚠️  Failed to load model for {detector}: {e}")
        return None

def _get_model(detector: str) -> dict | None:
    """Return cached model or load from disk."""
    if detector not in _registry:
        _load_model(detector)
    return _registry.get(detector)

# =========================
# PREDICT
# Core function called by every detector
# =========================
def predict(detector: str, features: dict, threshold: float = None) -> dict:
    """
    Run AI prediction on a feature vector.

    Parameters
    ----------
    detector : str
        "syn" | "arp" | "icmp" | "dns" | "bruteforce" | "ftp" | "dhcp"
    features : dict
        Feature dict returned by extract_features() in the detector

    Returns
    -------
    dict :
        is_attack   : bool   — True if AI confidence >= AI_THRESHOLD
        confidence  : float  — P(attack) from the model (0.0 → 1.0)
        alert_type  : str    — "AI_SYN", "AI_DNS" etc, or "NO_MODEL"
        detector    : str    — which detector called this
        status      : str    — "predicted" | "no_model" | "error"
    """
    model_data = _get_model(detector)

    if model_data is None:
        return {
            "is_attack"  : False,
            "confidence" : 0.0,
            "alert_type" : "NO_MODEL",
            "detector"   : detector,
            "status"     : "no_model"
        }

    model        = model_data["model"]
    feature_cols = model_data["feature_cols"]

    # build feature vector in training order
    # missing features default to 0 — same as during training
    vector = []
    for col in feature_cols:
        val = features.get(col, 0)
        try:
            vector.append(float(val) if val is not None else 0.0)
        except (TypeError, ValueError):
            vector.append(0.0)

    try:
        import pandas as pd
        # pass DataFrame with column names to suppress sklearn warning
        # and ensure feature order matches training exactly
        df_input   = pd.DataFrame([vector], columns=feature_cols)
        proba      = model.predict_proba(df_input)[0]
        confidence   = round(float(proba[1]), 4)
        _threshold   = threshold if threshold is not None else AI_THRESHOLD
        is_attack    = confidence >= _threshold

        return {
            "is_attack"  : is_attack,
            "confidence" : confidence,
            "alert_type" : f"AI_{detector.upper()}" if is_attack else "normal",
            "detector"   : detector,
            "status"     : "predicted"
        }

    except Exception as e:
        return {
            "is_attack"  : False,
            "confidence" : 0.0,
            "alert_type" : "ERROR",
            "detector"   : detector,
            "status"     : f"error: {e}"
        }

# =========================
# PRELOAD ALL MODELS
# Call once in manager.py before sniff() starts
# so all models are warm before packets arrive
# =========================
def preload_all():
    """Load all available models into memory at startup."""
    detectors = ["syn", "arp", "icmp", "dns", "bruteforce", "ftp", "dhcp"]
    loaded    = []
    skipped   = []

    for det in detectors:
        if _load_model(det):
            loaded.append(det)
        else:
            skipped.append(det)

    print(f"🤖 AI models loaded  : {loaded}")
    if skipped:
        print(f"   No model for     : {skipped} (rule-based only)")

# =========================
# BATCH PREDICT
# Used by evaluate.py
# =========================
def predict_batch(detector: str, feature_list: list) -> list:
    return [predict(detector, f) for f in feature_list]

# =========================
# STANDALONE CHECK
# python ai/predict.py
# =========================
if __name__ == "__main__":
    print("🔍 AI-IDS Prediction Engine — Model Status\n")

    detectors = ["syn", "arp", "icmp", "dns", "bruteforce", "ftp", "dhcp"]

    for det in detectors:
        path = MODELS_DIR / f"{det}_model.pkl"
        if not path.exists():
            print(f"  ❌ {det:<12} — no model (run train.py first)")
            continue

        data = _load_model(det)
        if data is None:
            print(f"  ❌ {det:<12} — failed to load")
            continue

        model        = data["model"]
        feature_cols = data["feature_cols"]
        size_kb      = round(path.stat().st_size / 1024, 1)

        print(f"  ✅ {det:<12} — {len(feature_cols)} features | "
              f"{model.n_estimators} trees | {size_kb} KB")
        print(f"     features : {feature_cols}")

        # sanity test — zero vector should return low confidence
        test = predict(det, {})
        print(f"     zero-vec : confidence={test['confidence']:.4f} "
              f"is_attack={test['is_attack']}\n")

    print(f"Threshold : {AI_THRESHOLD} "
          f"(>= {AI_THRESHOLD:.0%} confidence to flag as attack)")