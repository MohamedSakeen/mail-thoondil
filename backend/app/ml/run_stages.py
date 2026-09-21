"""
Checkpointed stage runner for the multi-dataset training pipeline.

Each stage persists its intermediates under app/ml/_cache/ so the full
training can run in separate, short-lived process invocations and resume
after interruptions.

Stages:
    prepare   — load all CSVs, dedupe, balance, save rows.pkl + counts.json
    extract   — feature extraction in shards (resumable per shard)
    vectorize — fit TF-IDF, build combined sparse matrix, save X/y + vectorizer
    train     — fit XGBoost on the train split, evaluate, save model + metrics
    finalize  — CV on subsample, assemble and write model_metadata.json

Usage:
    cd backend
    python -m app.ml.run_stages prepare
    python -m app.ml.run_stages extract --shard 0 --nshards 4
    python -m app.ml.run_stages vectorize
    python -m app.ml.run_stages train
    python -m app.ml.run_stages finalize
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
import time
from typing import Any

import numpy as np

from app.ml.training import (
    FEATURE_NAMES,
    balance_classes,
    dedupe_rows,
    extract_features_from_row,
    load_all_datasets,
)

_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_cache")
# Models live at project root /models/ (same dir model.py loads from)
_MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "models"))
_TFIDF_PATH = os.path.join(_MODEL_DIR, "tfidf_vectorizer.pkl")
_MODEL_PATH = os.path.join(_MODEL_DIR, "xgboost_model.pkl")
_METADATA_PATH = os.path.join(_MODEL_DIR, "model_metadata.json")

_TEST_SIZE = 0.2
_RANDOM_STATE = 42


def _ensure_cache() -> str:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    return _CACHE_DIR


# ---------------------------------------------------------------------------
# Stage 1: prepare
# ---------------------------------------------------------------------------

def stage_prepare() -> None:
    _ensure_cache()
    t0 = time.time()
    rows = load_all_datasets()
    rows = dedupe_rows(rows)
    rows = balance_classes(rows, random_state=_RANDOM_STATE)

    n_phish = sum(r["label"] for r in rows)
    n_legit = len(rows) - n_phish
    source_counts: dict[str, int] = {}
    for r in rows:
        source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1

    counts = {
        "n_samples": len(rows),
        "n_phishing": n_phish,
        "n_legitimate": n_legit,
        "scale_pos_weight": n_legit / max(1, n_phish),
        "source_counts": source_counts,
    }
    with open(os.path.join(_CACHE_DIR, "rows.pkl"), "wb") as f:
        pickle.dump(rows, f, protocol=pickle.HIGHEST_PROTOCOL)
    with open(os.path.join(_CACHE_DIR, "counts.json"), "w") as f:
        json.dump(counts, f, indent=2)

    print(json.dumps(counts, indent=2))
    print(f"prepare done in {time.time() - t0:.1f}s")


# ---------------------------------------------------------------------------
# Stage 2: extract (sharded)
# ---------------------------------------------------------------------------

def stage_extract(shard: int, nshards: int) -> None:
    t0 = time.time()
    with open(os.path.join(_CACHE_DIR, "rows.pkl"), "rb") as f:
        rows = pickle.load(f)

    n = len(rows)
    per = (n + nshards - 1) // nshards
    start, end = shard * per, min((shard + 1) * per, n)
    if start >= end:
        print(f"shard {shard}: empty range, skipping")
        return

    feats = [extract_features_from_row(r) for r in rows[start:end]]
    eng = np.array([list(f.values()) for f in feats], dtype=np.float32)
    labels = np.array([r["label"] for r in rows[start:end]], dtype=np.int8)
    texts = [f"{r.get('subject', '')}\n{r.get('body', '')}" for r in rows[start:end]]

    eng_path = os.path.join(_CACHE_DIR, f"eng_{shard}.npy")
    y_path = os.path.join(_CACHE_DIR, f"y_{shard}.npy")
    txt_path = os.path.join(_CACHE_DIR, f"texts_{shard}.pkl")
    np.save(eng_path, eng)
    np.save(y_path, labels)
    with open(txt_path, "wb") as f:
        pickle.dump(texts, f, protocol=pickle.HIGHEST_PROTOCOL)

    del rows
    print(f"shard {shard}: rows {start}..{end} -> eng {eng.shape}, saved in {time.time() - t0:.1f}s")


def stage_extract_all(nshards: int) -> None:
    for shard in range(nshards):
        stage_extract(shard, nshards)


# ---------------------------------------------------------------------------
# Stage 3: vectorize
# ---------------------------------------------------------------------------

def stage_vectorize() -> None:
    from scipy.sparse import csr_matrix, hstack, save_npz
    from sklearn.feature_extraction.text import TfidfVectorizer

    t0 = time.time()
    shards = sorted(
        int(fn.split("_")[1].split(".")[0])
        for fn in os.listdir(_CACHE_DIR)
        if fn.startswith("eng_") and fn.endswith(".npy")
    )
    if not shards:
        raise RuntimeError("No extracted shards found — run 'extract' first")

    eng = np.vstack([np.load(os.path.join(_CACHE_DIR, f"eng_{s}.npy")) for s in shards])
    y = np.concatenate([np.load(os.path.join(_CACHE_DIR, f"y_{s}.npy")) for s in shards])
    texts: list[str] = []
    for s in shards:
        with open(os.path.join(_CACHE_DIR, f"texts_{s}.pkl"), "rb") as f:
            texts.extend(pickle.load(f))
    print(f"loaded {len(texts)} rows, eng {eng.shape}")

    vectorizer = TfidfVectorizer(
        max_features=10_000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        strip_accents="unicode",
        min_df=2,
        max_df=0.95,
    )
    text_features = vectorizer.fit_transform(texts).astype(np.float32)
    print(f"TF-IDF: vocab {len(vectorizer.vocabulary_)}, matrix {text_features.shape}")

    combined = hstack([text_features, csr_matrix(eng)]).tocsr()
    combined.sort_indices()

    os.makedirs(_MODEL_DIR, exist_ok=True)
    with open(_TFIDF_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    save_npz(os.path.join(_CACHE_DIR, "X.npz"), combined)
    np.save(os.path.join(_CACHE_DIR, "y.npy"), y)
    print(f"saved {_TFIDF_PATH} + X.npz {combined.shape} in {time.time() - t0:.1f}s")


# ---------------------------------------------------------------------------
# Stage 4: train
# ---------------------------------------------------------------------------

def stage_train() -> None:
    from scipy.sparse import load_npz
    from sklearn.metrics import (
        accuracy_score, classification_report, confusion_matrix,
        precision_recall_fscore_support, roc_auc_score,
    )
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier

    t0 = time.time()
    X = load_npz(os.path.join(_CACHE_DIR, "X.npz"))
    y = np.load(os.path.join(_CACHE_DIR, "y.npy"))
    with open(os.path.join(_CACHE_DIR, "counts.json")) as f:
        counts = json.load(f)
    print(f"X {X.shape}, y {y.shape}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=_TEST_SIZE, random_state=_RANDOM_STATE, stratify=y
    )
    print(f"train {X_train.shape[0]}, test {X_test.shape[0]}")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        reg_alpha=0.1,
        reg_lambda=1.0,
        scale_pos_weight=counts["scale_pos_weight"],
        tree_method="hist",
        eval_metric="logloss",
        random_state=_RANDOM_STATE,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(X_train, y_train)
    print(f"fit done in {time.time() - t0:.1f}s")

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    roc_auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n{'='*40}\nEVALUATION\n{'='*40}")
    print(f"Accuracy:  {accuracy:.4f}\nPrecision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}\nF1:        {f1:.4f}\nROC-AUC:   {roc_auc:.4f}")
    print(f"Confusion matrix:\n{cm}")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    with open(_MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    metrics = {
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "confusion_matrix": cm.tolist(),
        "n_features": int(X.shape[1]),
        "train_rows": int(X_train.shape[0]),
        "test_rows": int(X_test.shape[0]),
        "fit_seconds": round(time.time() - t0, 1),
    }
    with open(os.path.join(_CACHE_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(_CACHE_DIR, "feature_importances.json"), "w") as f:
        json.dump(model.feature_importances_.tolist(), f)
    print(f"saved {_MODEL_PATH} + metrics.json in {time.time() - t0:.1f}s total")


# ---------------------------------------------------------------------------
# Stage 5: finalize (CV + metadata)
# ---------------------------------------------------------------------------

def stage_finalize(cv_folds: int = 3, cv_max_samples: int = 30_000) -> None:
    from scipy.sparse import load_npz
    from sklearn.model_selection import cross_val_score, train_test_split
    from xgboost import XGBClassifier

    t0 = time.time()
    with open(os.path.join(_CACHE_DIR, "counts.json")) as f:
        counts = json.load(f)
    with open(os.path.join(_CACHE_DIR, "metrics.json")) as f:
        metrics = json.load(f)

    cv_mean = cv_std = None
    try:
        X = load_npz(os.path.join(_CACHE_DIR, "X.npz"))
        y = np.load(os.path.join(_CACHE_DIR, "y.npy"))
        if X.shape[0] > cv_max_samples:
            X, _dx, y, _dy = train_test_split(
                X, y, train_size=cv_max_samples, random_state=_RANDOM_STATE, stratify=y
            )
            print(f"CV on stratified subsample of {cv_max_samples}")
        model = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            reg_alpha=0.1,
            reg_lambda=1.0,
            scale_pos_weight=counts["scale_pos_weight"],
            tree_method="hist",
            eval_metric="logloss",
            random_state=_RANDOM_STATE,
            n_jobs=-1,
            verbosity=0,
        )
        cv_scores = cross_val_score(model, X, y, cv=cv_folds, scoring="f1", n_jobs=-1)
        cv_mean, cv_std = float(np.mean(cv_scores)), float(np.std(cv_scores))
        print(f"CV F1: {[f'{s:.4f}' for s in cv_scores]} -> {cv_mean:.4f} ± {cv_std:.4f}")
    except Exception as exc:
        print(f"WARNING: CV failed ({exc}) — metadata will have null CV values")

    # Feature importances from the trained model
    importances: list[float] = []
    imp_path = os.path.join(_CACHE_DIR, "feature_importances.json")
    if os.path.exists(imp_path):
        with open(imp_path) as f:
            importances = json.load(f)

    n_tfidf = metrics["n_features"] - len(FEATURE_NAMES)
    metadata = {
        "version": "xgboost-v2-multi",
        "model_type": "XGBClassifier",
        "n_samples": counts["n_samples"],
        "n_features": metrics["n_features"],
        "n_tfidf_features": n_tfidf,
        "n_engineered_features": len(FEATURE_NAMES),
        "test_size": _TEST_SIZE,
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "roc_auc": metrics["roc_auc"],
        "cv_f1_mean": round(cv_mean, 4) if cv_mean is not None else None,
        "cv_f1_std": round(cv_std, 4) if cv_std is not None else None,
        "confusion_matrix": metrics["confusion_matrix"],
        "feature_names": FEATURE_NAMES,
        "datasets": sorted(counts["source_counts"].keys()),
        "source_counts": counts["source_counts"],
        "class_balance": {"phishing": counts["n_phishing"], "legitimate": counts["n_legitimate"]},
        "scale_pos_weight": round(counts["scale_pos_weight"], 4),
        "dataset_size": counts["n_samples"],
        "deduplicated": True,
        "class_balanced": True,
    }
    with open(_METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"saved {_METADATA_PATH}")

    # Print engineered-feature importance ranking
    if importances:
        eng_imps = sorted(zip(FEATURE_NAMES, importances[n_tfidf:]), key=lambda x: x[1], reverse=True)
        print("\nTop 15 engineered features:")
        for name, imp in eng_imps[:15]:
            print(f"  {name:35s} {imp:.4f} {'█' * int(imp * 100)}")
    print(f"finalize done in {time.time() - t0:.1f}s")


# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Checkpointed training stage runner")
    parser.add_argument("stage", choices=["prepare", "extract", "vectorize", "train", "finalize"])
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--nshards", type=int, default=4)
    args = parser.parse_args()

    if args.stage == "prepare":
        stage_prepare()
    elif args.stage == "extract":
        stage_extract(args.shard, args.nshards)
    elif args.stage == "vectorize":
        stage_vectorize()
    elif args.stage == "train":
        stage_train()
    elif args.stage == "finalize":
        stage_finalize()


if __name__ == "__main__":
    main()
