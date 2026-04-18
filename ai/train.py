#!/usr/bin/env python3
"""
AI-IDS — Model Training
========================
Trains one Random Forest model per detector and saves it to ai/models/.

Usage :
    python ai/train.py                    # train all detectors
    python ai/train.py --detector syn     # train one detector
    python ai/train.py --detector dns     # train dns only

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

# minimum rows needed to attempt training
MIN_ROWS = 1000

# =========================
# TRAIN ONE DETECTOR
# =========================
def train_detector(detector: str) -> dict:
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
    model = RandomForestClassifier(**RF_PARAMS)
    model.fit(X_train, y_train)

    # =========================
    # EVALUATE
    # =========================
    y_pred = model.predict(X_test)

    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    cm        = confusion_matrix(y_test, y_pred).tolist()

    print(f"\n  Results :")
    print(classification_report(y_test, y_pred,
          target_names=["normal", "attack"], zero_division=0))

    print(f"  Confusion matrix :")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    # =========================
    # FEATURE IMPORTANCE
    # =========================
    importance = dict(zip(
        feature_cols,
        model.feature_importances_.round(4)
    ))
    importance_sorted = dict(
        sorted(importance.items(), key=lambda x: -x[1])
    )

    print(f"\n  Feature importance :")
    for feat, score in importance_sorted.items():
        bar = "█" * int(score * 40)
        print(f"    {feat:30s} {score:.4f}  {bar}")

    # =========================
    # SAVE MODEL
    # =========================
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / f"{detector}_model.pkl"

    with open(model_path, "wb") as f:
        pickle.dump({
            "model"        : model,
            "feature_cols" : feature_cols,
            "detector"     : detector,
        }, f)

    print(f"\n  ✅ Model saved → {model_path}")

    return {
        "detector"    : detector,
        "status"      : "trained",
        "rows"        : len(df),
        "precision"   : round(precision, 4),
        "recall"      : round(recall, 4),
        "f1"          : round(f1, 4),
        "confusion_matrix": cm,
        "feature_importance": importance_sorted,
        "model_path"  : str(model_path)
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
    print(f"\n{'='*55}")
    print(f"  TRAINING SUMMARY")
    print(f"{'='*55}")
    print(f"  {'Detector':<14} {'Status':<10} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print(f"  {'-'*52}")

    for m in all_metrics:
        if m["status"] == "trained":
            print(f"  {m['detector']:<14} {'✅ trained':<10} "
                  f"{m['precision']:>10.4f} {m['recall']:>8.4f} {m['f1']:>8.4f}")
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
    args = parser.parse_args()

    detectors = ALL_DETECTORS if args.detector == "all" else [args.detector]

    print(f"🚀 AI-IDS Training Pipeline")
    print(f"   Detectors : {detectors}")
    print(f"   Models dir: {MODELS_DIR}")

    all_metrics = []
    for det in detectors:
        metrics = train_detector(det)
        all_metrics.append(metrics)

    save_metrics(all_metrics)
    print_summary(all_metrics)