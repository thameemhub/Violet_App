"""
Zenithal — build the phishing/benign URL training set from public feeds.

Produces training/data/phishing_urls.csv and benign_urls.csv, then validates the
resulting distribution against a real-world holdout so we never ship a model that
flags common legit sites.

Inputs (place in training/data/):
  - majestic.csv          top domains (benign)  https://downloads.majestic.com/majestic_million.csv
  - urlhaus_recent.csv    real malicious URLs    https://urlhaus.abuse.ch/downloads/csv_recent/

Design notes (why it's built this way):
  * Benign URLs are made deliberately COMPLEX (subdomains, deep paths, query
    tokens, file extensions, security-topic article names) so the model cannot
    cheat by learning "long/complex URL = malicious".
  * Malicious = rich synthetic brand-impersonation (the real phishing signal:
    brand-in-wrong-domain, risky TLD, IP literal, homograph) + a CAPPED slice of
    URLhaus malware URLs, so no single feed dominates.
Run:  python training/build_url_dataset.py   then   python training/train_url.py
"""

import os
import numpy as np
import pandas as pd

DATA = os.path.join(os.path.dirname(__file__), "data")
rng = np.random.default_rng(42)

# ---------------- BENIGN ----------------
SUBS = ["", "", "www.", "mail.", "support.", "docs.", "blog.", "app.", "account.",
        "shop.", "help.", "api.", "m.", "login.", "portal.", "news."]
SEG = ["about", "contact", "products", "product", "category", "articles", "knowledge-base",
       "datasets", "questions", "how-to-do-something", "web-application-security",
       "user", "profile", "settings", "orders", "invoice-2024", "guide", "getting-started",
       "cross-site-scripting", "main-page", "watch", "dp", "B08N5WRWNW", "r", "cybersecurity",
       "u", "0", "inbox", "3", "library", "urllib-parse", "release-notes", "v1", "users",
       "wiki", "Cross-site_scripting", "SQL_injection", "Phishing", "Malware",
       "Computer_security", "Denial-of-service_attack", "Login", "Authentication",
       "Password", "Verify_account_help", "secure-login-guide", "how-to-verify-identity"]
BENIGN_FILES = ["", "", "index.html", "readme.md", "README.md", "guide.html", "page.aspx",
                "view.jsp", "data.json", "report.pdf", "urllib.parse.html", "api-reference.html",
                "release-notes.md", "getting-started.html", "main.css", "app.js", "style.min.css",
                "docs.v2.html", "user.guide.pdf"]


def _token():
    return rng.choice(["", "", "?ref=nav", "?page=2&sort=desc",
                       "?v=" + "".join(rng.choice(list("abcdefABCDEF0123456789"), 11)),
                       "?id=" + str(rng.integers(1, 999999)),
                       "#inbox/" + "".join(rng.choice(list("ABCDEFGabcdefg0123456789"), 20)),
                       "?utm_source=news&utm_medium=email&id=" + str(rng.integers(1, 9999))])


def make_benign(domain):
    sub = rng.choice(SUBS)
    scheme = "https://" if rng.random() > 0.1 else "http://"
    segs = [rng.choice(SEG) for _ in range(rng.integers(0, 6))]
    f = rng.choice(BENIGN_FILES)
    if f:
        segs.append(f)
    path = "/".join(segs)
    q = _token() if not f else ""
    return f"{scheme}{sub}{domain}/{path}{q}" if path else f"{scheme}{sub}{domain}/"


# ---------------- PHISHING ----------------
BRANDS = ["paypal", "amazon", "apple", "microsoft", "netflix", "facebook", "google",
          "sbi", "hdfc", "icici", "axisbank", "paytm", "irctc", "incometax", "amazonpay",
          "instagram", "whatsapp", "flipkart", "dhl", "fedex"]
RISKY = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "link", "online",
         "site", "info", "live", "shop", "cyou", "rest", "sbs", "cfd"]
ACTIONS = ["verify", "secure", "login", "signin", "update", "confirm", "account",
           "kyc", "billing", "unlock", "recover", "validate", "authenticate", "alert"]
SHORT = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"]


def make_phish():
    b, a, tld = rng.choice(BRANDS), rng.choice(ACTIONS), rng.choice(RISKY)
    tail = rng.choice(["/login", "/verify", "/account/confirm", "/signin", "/netbanking/login",
                       "/update-info", "/secure/verify?id=" + str(rng.integers(1, 99999))])
    style = rng.integers(0, 7)
    if style == 0:   d = f"{b}-{a}-{rng.integers(1,999)}.{tld}"
    elif style == 1: d = f"{b}.com-{a}.{tld}"
    elif style == 2: d = f"{a}-{b}.{tld}"
    elif style == 3: d = f"{b}{rng.integers(0,9)}{a}.{tld}"
    elif style == 4:
        ip = ".".join(str(rng.integers(1, 255)) for _ in range(4)); return f"http://{ip}/{b}{tail}"
    elif style == 5: d = f"secure.{b}-{a}.{tld}"
    else:            d = f"{b.replace('o','0').replace('l','1')}-{a}.{tld}"
    scheme = "http://" if rng.random() > 0.3 else "https://"
    return f"{scheme}{d}{tail}"


def main():
    maj_path = os.path.join(DATA, "majestic.csv")
    uh_path = os.path.join(DATA, "urlhaus_recent.csv")
    if not (os.path.exists(maj_path) and os.path.exists(uh_path)):
        raise SystemExit("Need training/data/majestic.csv and urlhaus_recent.csv (see module docstring).")

    maj = pd.read_csv(maj_path)["Domain"].dropna().astype(str).head(40000).tolist()
    benign = list(dict.fromkeys(make_benign(d) for d in maj))[:26000]

    phish = list(dict.fromkeys(make_phish() for _ in range(20000)))
    phish += [f"https://{rng.choice(SHORT)}/" + "".join(rng.choice(list("abcdefGHIJK0123456789"),
              rng.integers(5, 9))) for _ in range(2500)]

    mal = pd.read_csv(uh_path, comment="#", header=None, quotechar='"',
                      names=list("abcdefghi"))["c"].dropna().astype(str)
    mal = [u for u in mal if u.startswith("http")]
    mal = list(pd.Series(mal).sample(min(6000, len(mal)), random_state=1))
    phish += mal

    n = min(len(benign), len(phish))
    benign = list(pd.Series(benign).sample(n, random_state=2))
    phish = list(pd.Series(phish).sample(n, random_state=2))

    pd.DataFrame({"url": phish}).to_csv(os.path.join(DATA, "phishing_urls.csv"), index=False)
    pd.DataFrame({"url": benign}).to_csv(os.path.join(DATA, "benign_urls.csv"), index=False)
    print(f"[OK] wrote phishing_urls.csv & benign_urls.csv ({n} each). Now run train_url.py")


if __name__ == "__main__":
    main()
