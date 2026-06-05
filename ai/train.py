#!/usr/bin/env python3
"""
AI-IDS — Model Training
========================
Trains RandomForest + XGBoost per detector.
Mode controls what gets saved.

Usage :
    python ai/train.py                          # train all, ensemble mode (default)
    python ai/train.py --mode best              # train all, save winner per detector
    python ai/train.py --mode ensemble          # train all, save RF+XGB voting
    python ai/train.py --mode force_rf          # train RF only, skip XGBoost
    python ai/train.py --mode force_xgb         # train XGBoost only, skip RF
    python ai/train.py --detector syn           # single detector
    python ai/train.py --detector dns --mode force_rf

Output :
    ai/models/syn_model.pkl
    ai/models/icmp_model.pkl
    ai/models/dns_model.pkl
    ai/models/bruteforce_model.pkl
    ai/models/ftp_model.pkl
    ai/models/arp_model.pkl       (once arp data is generated)
    ai/models/dhcp_model.pkl      (once dhcp data is generated)
    ai/models/metrics.json        (precision/recall/f1 for all detectors)
"""

import os
import json
import pickle
import argparse
from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)
from sklearn.preprocessing import StandardScaler

# import load_all from Stage 1
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from ai.load_datasets import load_all, FEATURES

# =========================
# CONFIG
# =========================
MODELS_DIR   = Path("ai/models")
METRICS_FILE = MODELS_DIR / "metrics.json"

# detectors to train — skip arp/dhcp if no data yet
ALL_DETECTORS = ["syn", "icmp", "dns", "bruteforce", "ftp", "arp", "dhcp"]

# RandomForest hyperparameters
RF_PARAMS = {
    "n_estimators"  : 100,
    "max_depth"     : 20,
    "min_samples_leaf": 5,
    "class_weight"  : "balanced",   # handles remaining imbalance
    "n_jobs"        : -1,           # use all CPU cores
    "random_state"  : 42
}

# XGBoost hyperparameters
XGB_PARAMS = {
    "n_estimators"      : 100,
    "max_depth"         : 6,
    "learning_rate"     : 0.1,
    "subsample"         : 0.8,
    "colsample_bytree"  : 0.8,
    "eval_metric"       : "logloss",
    "random_state"      : 42,
    "n_jobs"            : -1,
    "scale_pos_weight"  : 1,   # handles class imbalance
}

# minimum rows needed to attempt training
MIN_ROWS = 1000

# =========================
# TRAIN ONE DETECTOR
# =========================
def train_detector(detector: str, mode: str = "ensemble") -> dict:
    """
    Load data, train model, evaluate, save model.
    Returns metrics dict.
    """
    print(f"\n{'='*55}")
    print(f"  Training : {detector.upper()}")
    print(f"{'='*55}")

    # =========================
    # LOAD DATA
    # =========================
    df = load_all(detector)

    if df.empty:
        print(f"  ⏭️  Skipping {detector} — no data available")
        return {"detector": detector, "status": "skipped", "reason": "no data"}

    if len(df) < MIN_ROWS:
        print(f"  ⏭️  Skipping {detector} — too few rows ({len(df)} < {MIN_ROWS})")
        return {"detector": detector, "status": "skipped", "reason": f"only {len(df)} rows"}

    # =========================
    # PREPARE FEATURES
    # =========================
    feature_cols = FEATURES[detector]

    X = df[feature_cols].copy()
    y = df["label"].copy()

    # replace any remaining inf/nan with 0
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    print(f"\n  Dataset summary :")
    print(f"    Rows      : {len(df)}")
    print(f"    Features  : {feature_cols}")
    print(f"    Normal(0) : {(y==0).sum()}")
    print(f"    Attack(1) : {(y==1).sum()}")

    # =========================
    # TRAIN / TEST SPLIT
    # stratify=y ensures same label ratio in both splits
    # =========================
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size   = 0.2,
        stratify    = y,
        random_state= 42
    )

    print(f"\n  Split :")
    print(f"    Train : {len(X_train)} rows")
    print(f"    Test  : {len(X_test)} rows")

    # =========================
    # TRAIN
    # =========================
    print(f"\n  Training Random Forest...")
    # =========================
    # TRAIN RANDOM FOREST
    # =========================
    print(f"\n  Training Random Forest...")
    rf_model = RandomForestClassifier(**RF_PARAMS)
    rf_model.fit(X_train, y_train)
    rf_pred  = rf_model.predict(X_test)
    rf_proba = rf_model.predict_proba(X_test)[:, 1]

    rf_f1 = f1_score(y_test, rf_pred, zero_division=0)
    print(f"  RF  F1 : {rf_f1:.4f}")

    # =========================
    # TRAIN XGBOOST
    # =========================
    print(f"  Training XGBoost...")
    # compute scale_pos_weight for class imbalance
    neg = int((y_train == 0).sum())
    pos = int((y_train == 1).sum())
    xgb_params = {**XGB_PARAMS, "scale_pos_weight": round(neg / max(pos, 1), 2)}

    xgb_model = XGBClassifier(**xgb_params)
    xgb_model.fit(X_train, y_train)
    xgb_pred  = xgb_model.predict(X_test)
    xgb_proba = xgb_model.predict_proba(X_test)[:, 1]

    xgb_f1 = f1_score(y_test, xgb_pred, zero_division=0)
    print(f"  XGB F1 : {xgb_f1:.4f}")

    # =========================
    # ENSEMBLE EVALUATION
    # =========================
    ensemble_proba = (rf_proba + xgb_proba) / 2
    ensemble_pred  = (ensemble_proba >= 0.5).astype(int)

    precision = precision_score(y_test, ensemble_pred, zero_division=0)
    recall    = recall_score(y_test, ensemble_pred, zero_division=0)
    f1        = f1_score(y_test, ensemble_pred, zero_division=0)
    cm        = confusion_matrix(y_test, ensemble_pred).tolist()

    print(f"  Ensemble F1 : {f1:.4f}  (RF={rf_f1:.4f} + XGB={xgb_f1:.4f})")

    print(f"\n  Results (Ensemble RF+XGB) :")
    print(classification_report(y_test, ensemble_pred,
          target_names=["normal", "attack"], zero_division=0))

    print(f"  Confusion matrix :")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    # =========================
    # FEATURE IMPORTANCE (RF)
    # =========================
    importance = dict(zip(feature_cols, rf_model.feature_importances_.round(4)))
    importance_sorted = dict(sorted(importance.items(), key=lambda x: -x[1]))

    print(f"\n  Feature importance (RF) :")
    for feat, score in importance_sorted.items():
        bar = "█" * int(score * 40)
        print(f"    {feat:30s} {score:.4f}  {bar}")

    # =========================
    # SAVE — MODE AWARE
    # =========================
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / f"{detector}_model.pkl"

    if mode == "best":
        if xgb_f1 >= rf_f1:
            winner, winner_name, winner_f1 = xgb_model, "XGBoost", xgb_f1
        else:
            winner, winner_name, winner_f1 = rf_model,  "RandomForest", rf_f1
        with open(model_path, "wb") as f:
            pickle.dump({
                "model"        : winner,
                "feature_cols" : feature_cols,
                "detector"     : detector,
                "ensemble"     : False,
                "model_type"   : winner_name,
                "rf_f1"        : round(rf_f1, 4),
                "xgb_f1"       : round(xgb_f1, 4),
            }, f)
        print(f"\n  ✅ Best model saved ({winner_name} F1={winner_f1:.4f}) → {model_path}")

    elif mode == "force_rf":
        with open(model_path, "wb") as f:
            pickle.dump({
                "model"        : rf_model,
                "feature_cols" : feature_cols,
                "detector"     : detector,
                "ensemble"     : False,
                "model_type"   : "RandomForest",
                "rf_f1"        : round(rf_f1, 4),
                "xgb_f1"       : round(xgb_f1, 4),
            }, f)
        print(f"\n  ✅ RF model saved (F1={rf_f1:.4f}) → {model_path}")

    elif mode == "force_xgb":
        with open(model_path, "wb") as f:
            pickle.dump({
                "model"        : xgb_model,
                "feature_cols" : feature_cols,
                "detector"     : detector,
                "ensemble"     : False,
                "model_type"   : "XGBoost",
                "rf_f1"        : round(rf_f1, 4),
                "xgb_f1"       : round(xgb_f1, 4),
            }, f)
        print(f"\n  ✅ XGB model saved (F1={xgb_f1:.4f}) → {model_path}")

    else:  # ensemble
        with open(model_path, "wb") as f:
            pickle.dump({
                "model"        : rf_model,
                "xgb_model"    : xgb_model,
                "feature_cols" : feature_cols,
                "detector"     : detector,
                "ensemble"     : True,
                "model_type"   : "ensemble",
                "rf_f1"        : round(rf_f1, 4),
                "xgb_f1"       : round(xgb_f1, 4),
            }, f)
        print(f"\n  ✅ Ensemble model saved (RF={rf_f1:.4f} + XGB={xgb_f1:.4f}) → {model_path}")

    # count own JSONL rows if they exist — used by retrain.py for data growth tracking
    from pathlib import Path as _Path
    own_files = {
        "syn": "data/syn_dataset.jsonl", "arp": "data/arp_dataset.jsonl",
        "icmp": "data/icmp_dataset.jsonl", "dns": "data/dns_logs.jsonl",
        "bruteforce": "data/bruteforce_logs.jsonl",
        "dhcp": "data/dhcp_dataset.jsonl", "ftp": "data/ftp_dataset.jsonl"
    }
    own_path = own_files.get(detector, "")
    own_rows = 0
    if own_path and _Path(own_path).exists():
        try:
            with open(own_path) as _f:
                own_rows = sum(1 for l in _f if l.strip())
        except Exception:
            own_rows = 0

    from datetime import datetime as _dt
    return {
        "detector"          : detector,
        "status"            : "trained",
        "rows"              : len(df),
        "own_rows_at_train" : own_rows,
        "trained_at"        : str(_dt.now()),
        "precision"         : round(precision, 4),
        "recall"            : round(recall, 4),
        "f1"                : round(f1, 4),
        "mode"              : mode,
        "rf_f1"             : round(rf_f1, 4),
        "xgb_f1"            : round(xgb_f1, 4),
        "confusion_matrix"  : cm,
        "feature_importance": importance_sorted,
        "model_path"        : str(model_path)
    }

# =========================
# SAVE METRICS
# =========================
def save_metrics(all_metrics: list):
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # load existing metrics if file exists
    existing = {}
    if METRICS_FILE.exists():
        with open(METRICS_FILE) as f:
            existing = {m["detector"]: m for m in json.load(f)}

    # update with new results
    for m in all_metrics:
        existing[m["detector"]] = m

    with open(METRICS_FILE, "w") as f:
        json.dump(list(existing.values()), f, indent=2)

    print(f"\n📊 Metrics saved → {METRICS_FILE}")

# =========================
# SUMMARY TABLE
# =========================
def print_summary(all_metrics: list):
    print(f"\n{'='*70}")
    print(f"  TRAINING SUMMARY")
    print(f"{'='*70}")
    print(f"  {'Detector':<14} {'Status':<10} {'RF F1':>8} {'XGB F1':>8} {'Ensemble':>10} {'Mode'}")
    print(f"  {'-'*66}")

    for m in all_metrics:
        if m["status"] == "trained":
            rf_f1  = m.get("rf_f1", m["f1"])
            xgb_f1 = m.get("xgb_f1", m["f1"])
            ens_f1 = m["f1"]
            mode   = m.get("mode", "ensemble")
            print(f"  {m['detector']:<14} {'✅ trained':<10} "
                  f"{rf_f1:>8.4f} {xgb_f1:>8.4f} {ens_f1:>10.4f} {mode}")
        else:
            print(f"  {m['detector']:<14} ⏭️  {m['status']} — {m.get('reason','')}")

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AI-IDS models")
    parser.add_argument(
        "--detector",
        choices=ALL_DETECTORS + ["all"],
        default="all",
        help="Which detector to train (default: all)"
    )
    parser.add_argument(
        "--mode",
        choices=["ensemble", "best", "force_rf", "force_xgb"],
        default=None,
        help="ensemble: RF+XGB voting | best: winner per detector | force_rf: RF only | force_xgb: XGB only"
    )
    args = parser.parse_args()

    # mode priority: CLI flag > config.py > default ensemble
    import sys
    sys.path.insert(0, ".")
    try:
        from config import MODEL_MODE as _cfg_mode
    except ImportError:
        _cfg_mode = "ensemble"

    mode      = args.mode or _cfg_mode or "ensemble"
    detectors = ALL_DETECTORS if args.detector == "all" else [args.detector]

    print(f"🚀 AI-IDS Training Pipeline")
    print(f"   Detectors : {detectors}")
    print(f"   Mode      : {mode}")
    print(f"   Models dir: {MODELS_DIR}")

    all_metrics = []
    for det in detectors:
        metrics = train_detector(det, mode=mode)
        all_metrics.append(metrics)

    save_metrics(all_metrics)
    print_summary(all_metrics)