"""
Zenithal  - URL-Attack Payload Detection
Detects attacks *delivered through URLs* hitting a server: SQL injection,
XSS, path/directory traversal, command injection, and LFI/RFI.

Two complementary layers:
  1. Signature layer   - high-precision curated regex for known payloads.
                        Gives crisp, explainable hits for the demo.
  2. ML vectorizer     - char n-gram TF-IDF used by the trained classifier
                        (train_payload.py) to catch obfuscated/novel payloads.

`detect_payload()` fuses both and returns the attack type, matched evidence,
and a 0-100 risk score, all decoded (handles %xx and +) so obfuscation is
peeled away before matching.
"""

import re
from urllib.parse import unquote_plus

# --- Signature layer ------------------------------------------------------
# Each entry: (attack_type, human_label, compiled_regex)
_SIGNATURES: list[tuple[str, str, "re.Pattern[str]"]] = [
    # --- SQL Injection ---
    ("SQLi", "UNION SELECT statement", re.compile(r"union\s+(all\s+)?select", re.I)),
    ("SQLi", "Boolean tautology (OR 1=1)", re.compile(r"(\bor\b|\band\b)\s+[\w'\"]+\s*=\s*[\w'\"]+", re.I)),
    ("SQLi", "SQL comment / stacked query", re.compile(r"(--|#|;)\s*($|\w)|/\*.*?\*/", re.I)),
    ("SQLi", "SQL meta-function", re.compile(r"\b(sleep|benchmark|waitfor\s+delay|extractvalue|updatexml|load_file|group_concat)\s*\(", re.I)),
    ("SQLi", "Quote-based injection", re.compile(r"['\"]\s*(or|and)\s*['\"]?\d", re.I)),
    # --- Cross-Site Scripting ---
    ("XSS", "<script> tag injection", re.compile(r"<\s*script[^>]*>", re.I)),
    ("XSS", "JavaScript event handler", re.compile(r"on(error|load|click|mouseover|focus)\s*=", re.I)),
    ("XSS", "javascript: URI", re.compile(r"javascript\s*:", re.I)),
    ("XSS", "HTML tag injection", re.compile(r"<\s*(img|svg|iframe|body|object|embed)[^>]*(onerror|onload|src)\s*=", re.I)),
    ("XSS", "DOM sink call", re.compile(r"(alert|prompt|confirm|eval|document\.cookie)\s*\(", re.I)),
    # --- Path / Directory Traversal ---
    ("Traversal", "Directory traversal sequence", re.compile(r"(\.\.[\\/]){2,}|\.\.[\\/]\.\.", re.I)),
    ("Traversal", "Sensitive file access", re.compile(r"(etc/passwd|etc/shadow|boot\.ini|win\.ini|/proc/self)", re.I)),
    # --- Command Injection ---
    ("CmdInjection", "Shell command chaining", re.compile(r"(;|\||&&|\|\|)\s*(cat|ls|id|whoami|uname|nc|curl|wget|ping|bash|sh)\b", re.I)),
    ("CmdInjection", "Command substitution", re.compile(r"(\$\(|`).*(\)|`)", re.I)),
    # --- LFI / RFI ---
    ("LFI_RFI", "PHP wrapper / remote include", re.compile(r"(php://|data://|expect://|file://|https?://[^\s]+\.(txt|php)\?)", re.I)),
]

# Attack types ordered by severity for scoring / display
ATTACK_SEVERITY: dict[str, float] = {
    "SQLi": 95.0,
    "CmdInjection": 95.0,
    "LFI_RFI": 88.0,
    "Traversal": 85.0,
    "XSS": 80.0,
}

ATTACK_LABELS: dict[str, str] = {
    "SQLi": "SQL Injection",
    "XSS": "Cross-Site Scripting (XSS)",
    "Traversal": "Path/Directory Traversal",
    "CmdInjection": "Command Injection",
    "LFI_RFI": "Local/Remote File Inclusion",
    "BENIGN": "No attack detected",
}


def normalize(raw: str) -> str:
    """URL-decode (repeatedly) so obfuscated payloads are exposed."""
    prev = raw
    for _ in range(3):  # peel nested encoding, e.g. %2527 -> %27 -> '
        cur = unquote_plus(prev)
        if cur == prev:
            break
        prev = cur
    return prev


def signature_scan(request_target: str) -> list[dict]:
    """
    Run the signature layer over a request target (path + query string).
    Returns a list of hits: {attack_type, label, evidence}.
    """
    decoded = normalize(request_target)
    hits: list[dict] = []
    seen: set[str] = set()
    for attack_type, label, pattern in _SIGNATURES:
        m = pattern.search(decoded)
        if m and attack_type not in seen:
            seen.add(attack_type)
            evidence = m.group(0).strip()[:120]
            hits.append({
                "attack_type": attack_type,
                "label": label,
                "evidence": evidence,
            })
    return hits


def detect_payload(request_target: str, ml_predict=None) -> dict:
    """
    Fuse signature + optional ML detection for a single request target.

    Args:
        request_target: the raw path?query of an HTTP request.
        ml_predict: optional callable(decoded_str) -> (is_attack: bool,
                    attack_type: str, proba: float). Supplied by payload_engine
                    when the trained model is available.

    Returns dict:
        {is_attack, attack_type, label, score, evidence[], detected_by}
    """
    decoded = normalize(request_target)
    sig_hits = signature_scan(request_target)

    ml_type, ml_proba, ml_is_attack = None, 0.0, False
    if ml_predict is not None:
        try:
            ml_is_attack, ml_type, ml_proba = ml_predict(decoded)
        except Exception:
            ml_is_attack = False

    # --- Fuse ---
    if sig_hits:
        # Signature is high precision -> trust its type, take max severity.
        primary = max(sig_hits, key=lambda h: ATTACK_SEVERITY.get(h["attack_type"], 50))
        attack_type = primary["attack_type"]
        base = ATTACK_SEVERITY.get(attack_type, 80.0)
        # ML agreement nudges confidence up.
        score = min(100.0, base + (5.0 if ml_is_attack else 0.0))
        detected_by = "signature+ml" if ml_is_attack else "signature"
        return {
            "is_attack": True,
            "attack_type": attack_type,
            "label": ATTACK_LABELS.get(attack_type, attack_type),
            "score": round(score, 1),
            "evidence": [f"{h['label']}: `{h['evidence']}`" for h in sig_hits],
            "detected_by": detected_by,
        }

    if ml_is_attack and ml_proba >= 0.5:
        attack_type = ml_type or "SQLi"
        return {
            "is_attack": True,
            "attack_type": attack_type,
            "label": ATTACK_LABELS.get(attack_type, "Anomalous request"),
            "score": round(float(ml_proba) * 100, 1),
            "evidence": ["ML anomaly: request pattern matches known attack payloads"],
            "detected_by": "ml",
        }

    return {
        "is_attack": False,
        "attack_type": "BENIGN",
        "label": ATTACK_LABELS["BENIGN"],
        "score": round(float(ml_proba) * 100, 1) if ml_predict else 0.0,
        "evidence": [],
        "detected_by": "none",
    }
