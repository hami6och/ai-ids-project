#!/usr/bin/env python3
"""
AI-IDS — Retraining Pipeline
==============================
Intelligent retraining that :
  1. Checks if enough new own data has accumulated since last train
  2. Respects USE_OWN_DATA flag from config.py
  3. Retrains only detectors that have new data
  4. Compares new F1 against saved baseline
  5. Only replaces models if performance held or improved
  6. Prints a full before/after comparison report

Usage :
    python ai/retrain.py                         # check all, retrain if needed
    python ai/retrain.py --force                 # retrain regardless of data growth
    python ai/retrain.py --detector dns          # retrain one detector only
    python ai/retrain.py --check-only            # just show status, no training

USE_OWN_DATA toggle :
    Set USE_OWN_DATA = True in config.py when your lab JSONL data is ready.
    The pipeline will mix own data with external datasets automatically.
    own data rows are weighted by OWN_DATA_WEIGHT (default 3x repetition).
"""

import os
import sys
import json
import pickle
import argparse
import shutil
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

sys.path.insert(0, str(Path(__file__).parent.parent))
from ai.load_datasets import load_all, FEATURES, load_own
from ai.train import RF_PARAMS

# =========================
# CONFIG
# =========================
MODELS_DIR       = Path("ai/models")
METRICS_FILE     = MODELS_DIR / "metrics.json"
RETRAIN_LOG      = MODELS_DIR / "retrain_log.json"
DATA_SNAPSHOT    = MODELS_DIR / "data_snapshot.json"  # row counts at last train
BACKUP_DIR       = MODELS_DIR / "backup"

MIN_NEW_ROWS     = 500    # minimum new rows to trigger retrain
F1_TOLERANCE     = 0.005  # allow up to 0.5% F1 drop (rounding noise)

# detectors that use own JSONL data
OWN_DATA_DETECTORS = ["arp", "dhcp", "syn", "icmp", "dns", "bruteforce", "ftp"]

# own data JSONL file mapping
OWN_DATA_FILES = {
    "syn"        : "data/syn_dataset.jsonl",
    "arp"        : "data/arp_dataset.jsonl",
    "icmp"       : "data/icmp_dataset.jsonl",
    "dns"        : "data/dns_logs.jsonl",
    "bruteforce" : "data/bruteforce_logs.jsonl",
    "dhcp"       : "data/dhcp_dataset.jsonl",
    "ftp"        : "data/ftp_dataset.jsonl",
}

# =========================
# DATA SNAPSHOT — track row counts
# =========================
def load_snapshot() -> dict:
    """Load saved row counts from last training run."""
    if DATA_SNAPSHOT.exists():
        with open(DATA_SNAPSHOT) as f:
            return json.load(f)
    return {}

def save_snapshot(counts: dict):
    """Save current row counts as the new baseline."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATA_SNAPSHOT, "w") as f:
        json.dump({**counts, "saved_at": str(datetime.now())}, f, indent=2)

def count_own_rows(detector: str) -> int:
    """Count rows in the detector's own JSONL file."""
    path = OWN_DATA_FILES.get(detector)
    if not path or not Path(path).exists():
        return 0
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0

def get_data_growth(detector: str, snapshot: dict) -> int:
    """How many new rows since last training."""
    current  = count_own_rows(detector)
    previous = snapshot.get(f"{detector}_own_rows", 0)
    return current - previous

# =========================
# MODEL BACKUP
# =========================
def backup_model(detector: str):
    """Back up existing model before replacing it."""
    model_path = MODELS_DIR / f"{detector}_model.pkl"
    if not model_path.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup  = BACKUP_DIR / f"{detector}_model_{ts}.pkl"
    shutil.copy(model_path, backup)
    print(f"  💾 Backed up → {backup.name}")

# =========================
# LOAD BASELINE METRICS
# =========================
def load_baseline() -> dict:
    """Load saved F1 scores from last training."""
    if not METRICS_FILE.exists():
        return {}
    with open(METRICS_FILE) as f:
        metrics = json.load(f)
    return {m["detector"]: m for m in metrics if m.get("status") == "trained"}

# =========================
# RETRAIN ONE DETECTOR
# With USE_OWN_DATA support
# =========================
def retrain_detector(detector: str, use_own_data: bool,
                     own_data_weight: int) -> dict:
    """
    Retrain one detector. If use_own_data=True, mix own JSONL
    data into the training set with own_data_weight repetitions.
    """
    print(f"\n{'='*55}")
    print(f"  Retraining : {detector.upper()}")
    if use_own_data:
        print(f"  Own data   : ENABLED (weight={own_data_weight}x)")
    print(f"{'='*55}")

    # load external datasets
    df = load_all(detector, own_weight=own_data_weight if use_own_data else 0)

    if df.empty:
        return {"detector": detector, "status": "skipped", "reason": "no data"}

    feature_cols = FEATURES[detector]
    X = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
    y = df["label"]

    print(f"\n  Dataset : {len(df)} rows | "
          f"normal={int((y==0).sum())} attack={int((y==1).sum())}")
    if use_own_data:
        own_count = len(df[df["dataset_source"] == "lab_own"])
        print(f"  Own data : {own_count} rows included")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print(f"  Training Random Forest ({len(X_train)} train, {len(X_test)} test)...")
    model = RandomForestClassifier(**RF_PARAMS)
    model.fit(X_train, y_train)

    y_pred    = model.predict(X_test)
    precision = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
    recall    = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
    f1        = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)

    print(f"  Results   : precision={precision} recall={recall} F1={f1}")

    importance = dict(zip(feature_cols, model.feature_importances_.round(4)))
    importance = dict(sorted(importance.items(), key=lambda x: -x[1]))

    return {
        "detector"          : detector,
        "status"            : "trained",
        "rows"              : len(df),
        "precision"         : precision,
        "recall"            : recall,
        "f1"                : f1,
        "model_object"      : model,
        "feature_cols"      : feature_cols,
        "feature_importance": importance,
    }

# =========================
# SAVE MODEL IF IMPROVED
# =========================
def save_if_improved(result: dict, baseline: dict) -> str:
    """
    Compare new F1 against baseline. Save only if improved or held.
    Returns "saved", "rejected", or "new" (no baseline to compare).
    """
    detector = result["detector"]
    new_f1   = result["f1"]
    model    = result.pop("model_object")
    features = result.pop("feature_cols")

    model_path = MODELS_DIR / f"{detector}_model.pkl"

    if detector not in baseline:
        # no baseline — always save
        backup_model(detector)
        with open(model_path, "wb") as f:
            pickle.dump({"model": model, "feature_cols": features,
                         "detector": detector}, f)
        print(f"  ✅ Saved (no baseline to compare)")
        return "new"

    old_f1 = baseline[detector].get("f1", 0)
    delta  = new_f1 - old_f1

    if new_f1 >= old_f1 - F1_TOLERANCE:
        backup_model(detector)
        with open(model_path, "wb") as f:
            pickle.dump({"model": model, "feature_cols": features,
                         "detector": detector}, f)
        if delta >= 0:
            print(f"  ✅ Saved — F1 improved: {old_f1:.4f} → {new_f1:.4f} (+{delta:.4f})")
        else:
            print(f"  ✅ Saved — F1 held: {old_f1:.4f} → {new_f1:.4f} ({delta:.4f}, within tolerance)")
        return "saved"
    else:
        print(f"  ❌ Rejected — F1 dropped: {old_f1:.4f} → {new_f1:.4f} ({delta:.4f})")
        print(f"     Old model kept. Check your data quality.")
        return "rejected"

# =========================
# STATUS CHECK
# =========================
def check_status(detectors: list) -> dict:
    """Show current data status without retraining."""
    snapshot = load_snapshot()
    baseline = load_baseline()

    print(f"\n{'='*55}")
    print(f"  RETRAIN STATUS CHECK")
    print(f"{'='*55}")
    print(f"  {'Detector':<14} {'Own rows':<12} {'New rows':<12} {'Baseline F1':<12} {'Ready?'}")
    print(f"  {'-'*60}")

    status = {}
    for det in detectors:
        own_rows   = count_own_rows(det)
        new_rows   = get_data_growth(det, snapshot)
        base_f1    = baseline.get(det, {}).get("f1", "—")
        ready      = new_rows >= MIN_NEW_ROWS
        base_str   = f"{base_f1:.4f}" if isinstance(base_f1, float) else base_f1
        ready_str  = "✅ YES" if ready else f"❌ need {MIN_NEW_ROWS - new_rows} more"
        print(f"  {det:<14} {own_rows:<12} {new_rows:<12} {base_str:<12} {ready_str}")
        status[det] = {"own_rows": own_rows, "new_rows": new_rows, "ready": ready}

    return status

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-IDS Retraining Pipeline")
    parser.add_argument("--detector",   choices=OWN_DATA_DETECTORS + ["all"],
                        default="all")
    parser.add_argument("--force",      action="store_true",
                        help="Retrain regardless of data growth")
    parser.add_argument("--check-only", action="store_true",
                        help="Show status only, no training")
    args = parser.parse_args()

    detectors = OWN_DATA_DETECTORS if args.detector == "all" else [args.detector]

    # load config
    sys.path.insert(0, ".")
    try:
        from config import USE_OWN_DATA, OWN_DATA_WEIGHT
    except ImportError:
        USE_OWN_DATA     = False
        OWN_DATA_WEIGHT  = 3

    print(f"""
╔══════════════════════════════════════════════════════╗
║            AI-IDS RETRAINING PIPELINE                ║
║  USE_OWN_DATA   : {str(USE_OWN_DATA):<34}║
║  OWN_DATA_WEIGHT: {str(OWN_DATA_WEIGHT):<34}║
║  MIN_NEW_ROWS   : {str(MIN_NEW_ROWS):<34}║
╚══════════════════════════════════════════════════════╝
""")

    if args.check_only:
        check_status(detectors)
        sys.exit(0)

    snapshot = load_snapshot()
    baseline = load_baseline()

    # decide which detectors actually need retraining
    to_retrain = []
    skipped    = []

    for det in detectors:
        if args.force:
            to_retrain.append(det)
        else:
            growth = get_data_growth(det, snapshot)
            own    = count_own_rows(det)
            # retrain if: enough new own data OR USE_OWN_DATA just enabled
            if growth >= MIN_NEW_ROWS or (USE_OWN_DATA and own > 0):
                to_retrain.append(det)
            else:
                skipped.append(det)

    if not to_retrain:
        print("ℹ️  No detectors need retraining.")
        print(f"   All detectors have < {MIN_NEW_ROWS} new rows since last train.")
        print(f"   Use --force to retrain anyway, or --check-only to see status.")
        check_status(detectors)
        sys.exit(0)

    print(f"  Retraining : {to_retrain}")
    if skipped:
        print(f"  Skipping   : {skipped} (not enough new data)")

    # retrain
    results     = []
    saved_count = 0
    new_snapshot = dict(snapshot)

    for det in to_retrain:
        result = retrain_detector(det, USE_OWN_DATA, OWN_DATA_WEIGHT)

        if result["status"] == "trained":
            outcome = save_if_improved(result, baseline)
            result["outcome"] = outcome
            if outcome in ("saved", "new"):
                saved_count += 1
                # update snapshot
                new_snapshot[f"{det}_own_rows"] = count_own_rows(det)
        results.append(result)

    # save updated snapshot and metrics
    save_snapshot(new_snapshot)

    # update metrics file
    existing_metrics = {m["detector"]: m for m in
                        (json.load(open(METRICS_FILE)) if METRICS_FILE.exists() else [])}
    for r in results:
        if r["status"] == "trained":
            clean = {k: v for k, v in r.items()
                     if k not in ("model_object", "feature_cols")}
            clean["trained_at"] = str(datetime.now())
            clean["used_own_data"] = USE_OWN_DATA
            existing_metrics[r["detector"]] = clean
    with open(METRICS_FILE, "w") as f:
        json.dump(list(existing_metrics.values()), f, indent=2)

    # print summary
    print(f"""
╔══════════════════════════════════════════════════════╗
║                 RETRAIN COMPLETE                     ║
╠══════════════════════════════════════════════════════╣""")
    for r in results:
        if r["status"] == "trained":
            base_f1 = baseline.get(r["detector"], {}).get("f1", 0)
            delta   = r["f1"] - base_f1
            sign    = "+" if delta >= 0 else ""
            print(f"║  {r['detector']:<12} F1: {base_f1:.4f} → {r['f1']:.4f} "
                  f"({sign}{delta:.4f}) {r.get('outcome',''):<10}║")
        else:
            print(f"║  {r['detector']:<12} skipped — {r.get('reason',''): <30}║")
    print(f"║                                                      ║")
    print(f"║  Models saved : {saved_count:<36}║")
    print(f"╚══════════════════════════════════════════════════════╝")