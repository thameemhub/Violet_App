"""
Zenithal — train Engine 1 (phishing URL XGBoost classifier).

Data priority:
  1. training/data/phishing_urls.csv  (column 'url', label 1)
     training/data/benign_urls.csv    (column 'url', label 0)
  2. A single training/data/urls.csv with columns 'url','label'
  3. Synthetic generator (runs with zero setup for the demo).

Public datasets to drop in (any works):
  - PhishTank / OpenPhish feeds, URLhaus  -> phishing_urls.csv
  - Tranco top list                       -> benign_urls.csv
  - Kaggle "Phishing_Legitimate_full" / feature-engineered URL CSVs
"""

import json
import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config  # noqa: E402
from app.ml.features_url import FEATURE_NAMES, extract_url_features  # noqa: E402

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "walmart.com",
    "paypal.com", "chase.com", "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "flipkart.com", "irctc.co.in", "incometax.gov.in", "zoom.us", "adobe.com",
    "spotify.com", "dropbox.com", "slack.com", "stripe.com", "medium.com",
]
PHISH_PATTERNS = [
    "http://paypa1-secure.{tld}/login/verify",
    "http://amaz0n-billing.{tld}/account/update",
    "http://sbi-verify-{word}.{tld}/netbanking/login",
    "http://hdfc-secure-{word}.{tld}/account/confirm",
    "http://micros0ft-alert.{tld}/signin",
    "http://{ip}/paypal/login.php",
    "http://{ip}/sbi/verify",
    "http://secure-update-{word}.{tld}/account",
    "http://verify-identity-{word}.{tld}/confirm",
    "http://account-suspended-{word}.{tld}/restore",
    "http://irctc-refund-{word}.{tld}/claim",
    "http://incometax-refund-{word}.{tld}/process",
    "https://bit.ly/{word}{word}",
    "http://login-verify-{word}.{tld}/auth",
    "http://free-gift-{word}.{tld}/claim",
]
RISKY_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "buzz", "top", "click", "link"]
WORDS = ["user", "secure", "now", "alert", "info", "help", "verify", "update", "sbi", "in"]


def synth(n=2500):
    rng = np.random.default_rng(42)
    legit, phish = [], []
    for _ in range(n):
        d = rng.choice(LEGIT_DOMAINS)
        path = rng.choice(["", "/", "/about", "/login", "/products", "/help", "/search?q=x", "/account"])
        legit.append(f"https://{'www.' if rng.random() > 0.5 else ''}{d}{path}")
    for _ in range(n):
        p = rng.choice(PHISH_PATTERNS)
        ip = f"{rng.integers(1,255)}.{rng.integers(1,255)}.{rng.integers(1,255)}.{rng.integers(1,255)}"
        phish.append(p.format(tld=rng.choice(RISKY_TLDS), word=rng.choice(WORDS), ip=ip))
    urls = legit + phish
    labels = [0] * len(legit) + [1] * len(phish)
    return urls, labels


def load_data():
    p = os.path.join(DATA_DIR, "phishing_urls.csv")
    b = os.path.join(DATA_DIR, "benign_urls.csv")
    combined = os.path.join(DATA_DIR, "urls.csv")

    urls, labels = None, None
    if os.path.exists(p) and os.path.exists(b):
        pf = pd.read_csv(p)["url"].dropna().tolist()
        bf = pd.read_csv(b)["url"].dropna().tolist()
        print(f"[*] Real data: {len(bf)} benign + {len(pf)} phishing")
        urls, labels = bf + pf, [0] * len(bf) + [1] * len(pf)
    elif os.path.exists(combined):
        df = pd.read_csv(combined).dropna(subset=["url", "label"])
        print(f"[*] Real data: {len(df)} labelled URLs")
        urls, labels = df["url"].tolist(), df["label"].astype(int).tolist()

    if urls is None:
        print("[*] No CSVs found — generating synthetic training data.")
        return synth()

    # --- Blend synthetic brand-impersonation coverage into real data ---
    # Public feeds (URLhaus = malware URLs, Majestic = homepages) under-represent
    # brand-lookalike phishing (e.g. sbi-verify.top) and deep-path benign URLs.
    # Blending a synthetic slice teaches the model those styles too, so it
    # generalises across malware URLs, real phishing, AND brand impersonation
    # instead of just memorising one feed's quirks.
    s_urls, s_labels = synth(n=3000)
    urls += s_urls
    labels += s_labels
    n1 = sum(labels)
    print(f"[*] + synthetic blend -> {len(urls)} total ({len(labels)-n1} benign / {n1} phishing)")
    return urls, labels


def main():
    print("=" * 60, "\nZenithal — URL Classifier Training\n", "=" * 60, sep="")
    urls, labels = load_data()

    X, y = [], []
    for u, lab in zip(urls, labels):
        f = extract_url_features(u)
        X.append([f[k] for k in FEATURE_NAMES])
        y.append(lab)
    X, y = np.array(X), np.array(y)
    print(f"[*] Feature matrix: {X.shape}")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                          eval_metric="logloss", random_state=42, verbosity=0)
    model.fit(Xtr, ytr)

    pred = model.predict(Xte)
    print("\nTEST RESULTS")
    print(f"  Accuracy : {accuracy_score(yte, pred):.4f}")
    print(f"  Precision: {precision_score(yte, pred):.4f}")
    print(f"  Recall   : {recall_score(yte, pred):.4f}")
    print(f"  F1       : {f1_score(yte, pred):.4f}")
    print(classification_report(yte, pred, target_names=["Legit", "Phishing"]))

    imp = model.feature_importances_
    print("Top features:", [FEATURE_NAMES[i] for i in np.argsort(imp)[::-1][:8]])

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, config.URL_MODEL_PATH)
    config.URL_FEATURE_NAMES_PATH.write_text(json.dumps(FEATURE_NAMES, indent=2))
    print(f"\n[OK] Saved -> {config.URL_MODEL_PATH}")

    print("\nSanity:")
    for u in ["http://sbi-verify-now.top/netbanking/login", "https://google.com",
              "http://192.168.1.1/paypal/login.php", "https://github.com/user/repo"]:
        f = extract_url_features(u)
        prob = model.predict_proba([[f[k] for k in FEATURE_NAMES]])[0][1]
        print(f"  {prob*100:5.1f}%  {u}")


if __name__ == "__main__":
    main()
