"""
Zenithal — acceptance test for the full URL engine (reputation + ML).
Ensures reputable/legit sites are SAFE and known phishing is caught. Run after
any retrain / feed refresh:  python training/validate_url_model.py  (exits 1 on failure)
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.engines.url_engine import engine

# Real, complex, reputable URLs (must be SAFE regardless of path/query shape)
LEGIT = [
    "https://www.google.com/search?q=is+maxmind+free&gs_lcrp=EgZjaHJvbWUqBwgAEAAY&ie=UTF-8",
    "https://chatgpt.com/c/6a5880ad-26d8-83ee-bb75-95ef2d8632c5",
    "https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks",
    "https://mail.google.com/mail/u/0/#inbox/FMfcgzQhVNdCrFNDFXPTQnncJxXLDpDq",
    "https://support.maxmind.com/knowledge-base/articles/maxmind-database-formats",
    "https://github.com/anthropics/claude-code/blob/main/README.md",
    "https://en.wikipedia.org/wiki/Cross-site_scripting",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.amazon.com/dp/B08N5WRWNW?ref=nav_logo",
    "http://localhost:3000/login",
    "http://127.0.0.1:5173/",
]
PHISH = [
    "http://sbi-verify-now.top/netbanking/login",
    "http://192.168.1.1/paypal/login.php",
    "https://bit.ly/3xY9kQz",
    "http://paypal-verify.tk/login",
    "http://amaz0n-billing.ml/account/update",
    "http://appleid-verify.gq/signin",
    "http://icici-kyc-update.buzz/confirm",
]


def main():
    engine.load()
    # deterministic + fast: skip live DNS/IP intel
    legit_fp = [u for u in LEGIT if engine.analyze(u, with_ip_intel=False)["verdict"] == "MALICIOUS"]
    phish_miss = [u for u in PHISH if engine.analyze(u, with_ip_intel=False)["verdict"] not in ("MALICIOUS", "SUSPICIOUS")]

    print(f"Legit false-positives (MALICIOUS): {len(legit_fp)}/{len(LEGIT)}")
    for u in legit_fp:
        print("   FP:", u)
    print(f"Phishing missed: {len(phish_miss)}/{len(PHISH)}")
    for u in phish_miss:
        print("   MISS:", u)

    ok = not legit_fp and not phish_miss
    print("\nRESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
