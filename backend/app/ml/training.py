"""
ML Training Pipeline — multi-dataset.

Loads every CSV in datasets/ (CEAS_08, Enron, Ling, SpamAssasin,
TREC_05/06/07), extracts features using our analyzers, trains TF-IDF +
XGBoost, evaluates, and persists.

Two schemas are supported (auto-detected per file):
  full:  sender, receiver, date, subject, body, label, urls  (CEAS, TREC, SpamAssasin)
  text:  subject, body, label                                (Enron, Ling)

Usage:
    cd backend
    python -m app.ml.training
"""

from __future__ import annotations

import csv
import json
import os
import pickle
import re
import sys
import hashlib
from typing import Any

import numpy as np

# Increase CSV field size limit for large email bodies
csv.field_size_limit(sys.maxsize)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_DATASETS_DIR = os.path.abspath(os.path.join(_ROOT, "..", "datasets"))
_DEFAULT_DATASET = os.path.join(_DATASETS_DIR, "Phishing_Email.csv", "CEAS_08.csv")
_MODEL_DIR = os.path.join(_ROOT, "..", "models")
_TFIDF_PATH = os.path.join(_MODEL_DIR, "tfidf_vectorizer.pkl")
_MODEL_PATH = os.path.join(_MODEL_DIR, "xgboost_model.pkl")
_METADATA_PATH = os.path.join(_MODEL_DIR, "model_metadata.json")


# ---------------------------------------------------------------------------
# 1. Data Loading — multi-dataset, schema auto-detection
# ---------------------------------------------------------------------------

FULL_SCHEMA = {"sender", "receiver", "date", "subject", "body", "label", "urls"}
TEXT_SCHEMA = {"subject", "body", "label"}


def _detect_schema(fieldnames: list[str]) -> str:
    """Classify a CSV header as 'full' (has sender/receiver/urls) or 'text'."""
    cols = {c.strip().lower() for c in fieldnames if c}
    if FULL_SCHEMA.issubset(cols):
        return "full"
    if TEXT_SCHEMA.issubset(cols):
        return "text"
    raise ValueError(f"Unrecognized CSV schema with columns: {sorted(cols)}")


def load_dataset(path: str | None = None) -> list[dict[str, Any]]:
    """Load a single dataset CSV (either schema) into unified row dicts."""
    path = path or _DEFAULT_DATASET
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}")

    rows: list[dict[str, Any]] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        schema = _detect_schema(reader.fieldnames or [])
        for row in reader:
            label = (row.get("label") or "").strip()
            if label not in ("0", "1"):
                continue
            rows.append({
                "sender": row.get("sender") or "",
                "receiver": row.get("receiver") or "",
                "date": row.get("date") or "",
                "subject": row.get("subject") or "",
                "body": row.get("body") or "",
                "label": int(label),
                "urls_count": row.get("urls") or "0",
                "source": os.path.basename(path),
                "schema": schema,
            })

    print(f"Loaded {len(rows):>7} emails from {os.path.basename(path)} ({schema} schema)")
    n_phish = sum(r["label"] for r in rows)
    print(f"          Phishing: {n_phish}, Legitimate: {len(rows) - n_phish}")
    return rows


def load_all_datasets(datasets_dir: str | None = None) -> list[dict[str, Any]]:
    """Load and concatenate every CSV in datasets_dir (recursive)."""
    datasets_dir = datasets_dir or _DATASETS_DIR
    csv_paths: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(datasets_dir):
        for fn in filenames:
            if fn.lower().endswith(".csv") and "vectorized" not in fn.lower():
                csv_paths.append(os.path.join(dirpath, fn))
    if not csv_paths:
        raise FileNotFoundError(f"No dataset CSVs found in {datasets_dir}")

    all_rows: list[dict[str, Any]] = []
    for path in sorted(csv_paths):
        try:
            all_rows.extend(load_dataset(path))
        except Exception as exc:
            print(f"  WARNING: skipping {path}: {exc}")

    print(f"\nTotal loaded: {len(all_rows)} emails from {len(csv_paths)} files")
    return all_rows


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop near-duplicate emails (same subject+body hash), keeping first."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        key = hashlib.md5(
            f"{row.get('subject', '')}\x00{row.get('body', '')}".encode("utf-8", "replace")
        ).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    dropped = len(rows) - len(unique)
    print(f"Dedupe: {len(rows)} -> {len(unique)} rows ({dropped} duplicates removed)")
    return unique


def balance_classes(
    rows: list[dict[str, Any]], random_state: int = 42
) -> list[dict[str, Any]]:
    """Downsample the majority class to a 1:1 ratio."""
    rng = np.random.RandomState(random_state)
    phish = [r for r in rows if r["label"] == 1]
    legit = [r for r in rows if r["label"] == 0]
    n = min(len(phish), len(legit))
    if n == 0:
        print("WARNING: cannot balance classes (one class is empty)")
        return rows

    phish_idx = rng.choice(len(phish), size=n, replace=False) if len(phish) > n else range(len(phish))
    legit_idx = rng.choice(len(legit), size=n, replace=False) if len(legit) > n else range(len(legit))
    balanced = [phish[i] for i in phish_idx] + [legit[i] for i in legit_idx]
    rng.shuffle(balanced)
    print(f"Balance: using {n} phishing + {n} legitimate = {len(balanced)} rows")
    return balanced


# ---------------------------------------------------------------------------
# 2. Feature Extraction (mirrors our analyzer pipeline)
# ---------------------------------------------------------------------------

# Keyword patterns (same as config.py)
_URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin\s+\d+\b",
    r"\bact\s+now\b", r"\basap\b", r"\btime\s+sensitive\b",
    r"\bexpires?\b", r"\blast\s+chance\b",
]
_CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bverify\s+(your\s+)?account\b",
    r"\bsign\s+in\b", r"\blogin\b", r"\bcredentials?\b",
    r"\bconfirm\s+your\s+identity\b", r"\bupdate\s+your\s+information\b",
    r"\baccount\s+verification\b", r"\benter\s+your\b",
]
_FINANCIAL_PATTERNS = [
    r"\bpayment\b", r"\binvoice\b", r"\bwire\s+transfer\b",
    r"\bbank\b", r"\bbitcoin\b", r"\bcrypto\b", r"\bpay\s+now\b",
    r"\brefund\b", r"\baccount\s+number\b",
]
_THREAT_PATTERNS = [
    r"\bsuspend\w*\b", r"\bterminate\w*\b", r"\blocked\b",
    r"\blegal\s+action\b", r"\bpenalty\b", r"\bdeactivate\w*\b",
    r"\bwill\s+be\s+clos", r"\brestrict\w*\b",
]
_AUTHORITY_PATTERNS = [
    r"\bsecurity\s+team\b", r"\badministrator\b",
    r"\bsupport\s+team\b", r"\bIT\s+department\b",
    r"\bhelpdesk\b", r"\bsystem\s+admin\b", r"\bnoreply\b",
    r"\bcompliance\b",
]
_CALL_TO_ACTION_PATTERNS = [
    r"\bclick\s+(here|below|the)\b", r"\bverify\b",
    r"\bopen\s+the\b", r"\bdownload\b", r"\bconfirm\b",
    r"\bfollow\s+(this|the)\b", r"\bupdate\s+now\b",
]

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_EXECUTABLE_EXTS = {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1"}
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
_SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq"}


def _score_patterns(patterns: list[str], text: str) -> float:
    if not text:
        return 0.0
    hits = sum(1 for p in patterns if re.search(p, text, re.I))
    return min(1.0, hits / max(1, len(patterns) * 0.5))


def _domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().strip()


def extract_features_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """Extract the same feature set our pipeline produces, from a CSV row."""
    body = row.get("body", "")
    subject = row.get("subject", "")
    sender = row.get("sender", "")
    combined_text = f"{subject}\n{body}"

    # Basic text stats
    words = re.findall(r"\b\w+\b", combined_text, re.UNICODE)
    word_count = len(words)
    alpha_chars = sum(c.isalpha() for c in combined_text)
    upper_chars = sum(c.isupper() for c in combined_text)

    # URL extraction from body
    urls = _URL_RE.findall(body)
    url_count = len(urls)

    # URL features
    url_has_ip = False
    url_has_punycode = False
    url_has_shortener = False
    url_has_at = False
    url_has_https = False
    url_avg_length = 0.0
    url_suspicious_keywords = 0

    for url in urls:
        url = url.rstrip(".,);]}")
        if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
            url_has_ip = True
        if "xn--" in url:
            url_has_punycode = True
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            host = (p.hostname or "").lower()
            if host in _SHORTENERS:
                url_has_shortener = True
            if "@" in url:
                url_has_at = True
            if p.scheme == "https":
                url_has_https = True
            for tld in _SUSPICIOUS_TLDS:
                if host.endswith(tld):
                    url_suspicious_keywords += 1
        except Exception:
            pass

    if urls:
        url_avg_length = np.mean([len(u) for u in urls])

    # Sender domain features (empty sender (Enron/Ling) -> neutral zeros)
    from_domain = _domain(sender)
    domain_digit_ratio = sum(c.isdigit() for c in from_domain) / max(1, len(from_domain))
    domain_hyphen_count = from_domain.count("-")
    domain_length = len(from_domain)

    # Sender local part
    localpart = sender.rsplit("@", 1)[0].lower() if "@" in sender else ""
    local_is_numeric = localpart.isdigit() if localpart else False

    # Content analysis scores
    urgency = _score_patterns(_URGENCY_PATTERNS, combined_text)
    credential = _score_patterns(_CREDENTIAL_PATTERNS, combined_text)
    financial = _score_patterns(_FINANCIAL_PATTERNS, combined_text)
    threat = _score_patterns(_THREAT_PATTERNS, combined_text)
    authority = _score_patterns(_AUTHORITY_PATTERNS, combined_text)
    cta = _score_patterns(_CALL_TO_ACTION_PATTERNS, combined_text)
    phishing_sum = min(1.0, (urgency + credential + financial + threat + authority) / 3.0)

    return {
        # Text stats
        "word_count": word_count,
        "uppercase_ratio": upper_chars / max(1, alpha_chars),
        "digit_ratio": sum(c.isdigit() for c in combined_text) / max(1, len(combined_text)),
        "avg_word_length": np.mean([len(w) for w in words]) if words else 0,
        "sentence_count": max(1, len(re.findall(r"[.!?]+", combined_text))),
        # URL features
        "url_count": url_count,
        "url_has_ip": int(url_has_ip),
        "url_has_punycode": int(url_has_punycode),
        "url_has_shortener": int(url_has_shortener),
        "url_has_at": int(url_has_at),
        "url_has_https": int(url_has_https),
        "url_avg_length": url_avg_length,
        "url_suspicious_keywords": url_suspicious_keywords,
        # Sender features
        "domain_length": domain_length,
        "domain_digit_ratio": domain_digit_ratio,
        "domain_hyphen_count": domain_hyphen_count,
        "local_is_numeric": int(local_is_numeric),
        # NLP scores
        "urgency_score": urgency,
        "credential_request_score": credential,
        "financial_request_score": financial,
        "threat_score": threat,
        "authority_impersonation_score": authority,
        "call_to_action_score": cta,
        "phishing_indicator_sum": phishing_sum,
    }


# Feature names in order (matches extract_features_from_row output order)
FEATURE_NAMES = list(extract_features_from_row({
    "body": "", "subject": "", "sender": ""
}).keys())


# ---------------------------------------------------------------------------
# 3. Training
# ---------------------------------------------------------------------------

def train(
    datasets_dir: str | None = None,
    test_size: float = 0.2,
    random_state: int = 42,
    cv_folds: int = 3,
    cv_max_samples: int = 30_000,
) -> dict[str, Any]:
    """Full training pipeline: load → extract → train → evaluate → persist."""

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        classification_report, confusion_matrix, roc_auc_score,
        precision_recall_fscore_support, accuracy_score,
    )
    from xgboost import XGBClassifier
    from scipy.sparse import hstack, csr_matrix

    print("=" * 60)
    print("PHISHING MAIL DETECTOR — ML TRAINING PIPELINE (multi-dataset)")
    print("=" * 60)

    # Step 1: Load data
    print("\n[1/6] Loading datasets...")
    rows = load_all_datasets(datasets_dir)
    rows = dedupe_rows(rows)
    rows = balance_classes(rows, random_state=random_state)

    n_phish = sum(r["label"] for r in rows)
    n_legit = len(rows) - n_phish
    scale_pos_weight = n_legit / max(1, n_phish)
    print(f"  scale_pos_weight: {scale_pos_weight:.4f}")

    # Per-source counts for metadata
    source_counts: dict[str, int] = {}
    for r in rows:
        source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1

    # Step 2: Extract features
    print("\n[2/6] Extracting features...")
    texts = []
    labels = []
    engineered_features = []

    for i, row in enumerate(rows):
        text = f"{row.get('subject', '')}\n{row.get('body', '')}"
        texts.append(text)
        labels.append(row["label"])
        engineered_features.append(extract_features_from_row(row))

        if (i + 1) % 10000 == 0:
            print(f"  Processed {i + 1}/{len(rows)} emails...")

    labels = np.array(labels)
    eng_array = np.array([list(f.values()) for f in engineered_features], dtype=np.float64)
    print(f"  Extracted {eng_array.shape[1]} engineered features from {len(texts)} emails")

    # Step 3: TF-IDF
    print("\n[3/6] Building TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=10_000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        strip_accents="unicode",
        min_df=2,
        max_df=0.95,
    )
    text_features = vectorizer.fit_transform(texts)
    print(f"  TF-IDF vocabulary size: {len(vectorizer.vocabulary_)}")
    print(f"  Text feature matrix: {text_features.shape}")

    # Combine text + engineered features
    combined = hstack([text_features, csr_matrix(eng_array)]).tocsr()
    print(f"  Combined feature matrix: {combined.shape}")

    # Step 4: Split and train
    print("\n[4/6] Training XGBoost model...")
    X_train, X_test, y_train, y_test = train_test_split(
        combined, labels, test_size=test_size, random_state=random_state, stratify=labels
    )
    print(f"  Train: {X_train.shape[0]} samples, Test: {X_test.shape[0]} samples")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        reg_alpha=0.1,
        reg_lambda=1.0,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        random_state=random_state,
        n_jobs=-1,
        verbosity=0,
    )

    model.fit(X_train, y_train)
    print("  Model trained successfully!")

    # Step 5: Evaluate
    print("\n[5/6] Evaluating model...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    roc_auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n  {'='*40}")
    print(f"  EVALUATION RESULTS")
    print(f"  {'='*40}")
    print(f"  Accuracy:    {accuracy:.4f}")
    print(f"  Precision:   {precision:.4f}")
    print(f"  Recall:      {recall:.4f}")
    print(f"  F1 Score:    {f1:.4f}")
    print(f"  ROC-AUC:     {roc_auc:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"  {'':15} Predicted")
    print(f"  {'':15} Legit  Phish")
    print(f"  Actual Legit  {cm[0][0]:>6} {cm[0][1]:>6}")
    print(f"  Actual Phish  {cm[1][0]:>6} {cm[1][1]:>6}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Cross-validation (on a stratified subsample to keep runtime sane)
    if cv_folds >= 2:
        print(f"  Running {cv_folds}-fold cross-validation...")
        cv_X, cv_y = combined, labels
        if combined.shape[0] > cv_max_samples:
            from sklearn.model_selection import train_test_split as _tts
            cv_X, _discard_X, cv_y, _discard_y = _tts(
                combined, labels, train_size=cv_max_samples,
                random_state=random_state, stratify=labels,
            )
            print(f"  (on stratified subsample of {cv_max_samples} rows)")
        cv_scores = cross_val_score(model, cv_X, cv_y, cv=cv_folds, scoring="f1", n_jobs=-1)
        print(f"  CV F1 scores: {[f'{s:.4f}' for s in cv_scores]}")
        print(f"  CV F1 mean:   {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")
        cv_mean, cv_std = float(np.mean(cv_scores)), float(np.std(cv_scores))
    else:
        print("  Skipping cross-validation (cv_folds < 2)")
        cv_mean, cv_std = None, None

    # Step 6: Persist
    print("\n[6/6] Saving model...")
    os.makedirs(_MODEL_DIR, exist_ok=True)

    with open(_TFIDF_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    print(f"  Saved TF-IDF vectorizer: {_TFIDF_PATH}")

    with open(_MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"  Saved XGBoost model: {_MODEL_PATH}")

    metadata = {
        "version": "xgboost-v2-multi",
        "model_type": "XGBClassifier",
        "n_samples": len(texts),
        "n_features": int(combined.shape[1]),
        "n_tfidf_features": int(text_features.shape[1]),
        "n_engineered_features": int(eng_array.shape[1]),
        "test_size": test_size,
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "cv_f1_mean": round(cv_mean, 4) if cv_mean is not None else None,
        "cv_f1_std": round(cv_std, 4) if cv_std is not None else None,
        "confusion_matrix": cm.tolist(),
        "feature_names": FEATURE_NAMES,
        "datasets": sorted(source_counts.keys()),
        "source_counts": dict(sorted(source_counts.items())),
        "class_balance": {"phishing": int(n_phish), "legitimate": int(n_legit)},
        "scale_pos_weight": round(float(scale_pos_weight), 4),
        "dataset_size": len(texts),
        "deduplicated": True,
        "class_balanced": True,
    }
    with open(_METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Saved metadata: {_METADATA_PATH}")

    # Feature importance
    print("\n  Top 15 most important features:")
    importances = model.feature_importances_
    # TF-IDF features are first, engineered features are last
    eng_start = text_features.shape[1]
    eng_importances = list(zip(FEATURE_NAMES, importances[eng_start:]))
    eng_importances.sort(key=lambda x: x[1], reverse=True)
    for name, imp in eng_importances[:15]:
        bar = "█" * int(imp * 100)
        print(f"    {name:35s} {imp:.4f} {bar}")

    # Show top TF-IDF features
    tfidf_importances = importances[:eng_start]
    top_tfidf_idx = np.argsort(tfidf_importances)[-10:][::-1]
    feature_names_tfidf = vectorizer.get_feature_names_out()
    print("\n  Top 10 TF-IDF features:")
    for idx in top_tfidf_idx:
        name = feature_names_tfidf[idx]
        imp = tfidf_importances[idx]
        bar = "█" * int(imp * 500)
        print(f"    {name:35s} {imp:.4f} {bar}")

    print(f"\n{'='*60}")
    print(f"TRAINING COMPLETE")
    print(f"{'='*60}")
    print(f"  Model: XGBoost (n_estimators=300, max_depth=6)")
    print(f"  Features: {combined.shape[1]} ({text_features.shape[1]} TF-IDF + {eng_array.shape[1]} engineered)")
    print(f"  F1: {f1:.4f} | ROC-AUC: {roc_auc:.4f} | Accuracy: {accuracy:.4f}")
    print(f"  Saved to: {_MODEL_DIR}/")

    return metadata


if __name__ == "__main__":
    train()
