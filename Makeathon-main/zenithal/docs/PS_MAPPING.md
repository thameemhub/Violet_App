# SIH25229 — Problem-Statement Mapping

**Problem:** *Identification of URL Based Attacks from IP Data* · Cybersecurity · Software.

This document maps every phrase of the problem statement to a concrete,
built-and-tested feature. Use it as the judging-panel cheat sheet.

---

## 1. "Identification of URL Based Attacks"

URL-based attacks are **not only phishing links**. Zenithal covers both families:

### A. Client-side — malicious / phishing URLs (Engine 1)
| Capability | Where |
|---|---|
| 38 lexical + host features (length, entropy, TLD risk, brand keywords, IP-literal, shortener, encoded chars…) | `app/ml/features_url.py` |
| XGBoost classifier (+ heuristic fallback) | `app/engines/url_engine.py`, `training/train_url.py` |
| Verdict: SAFE / SUSPICIOUS / MALICIOUS with 0–100 score | `app/config.py::score_to_verdict` |

### B. Server-side — attacks delivered through request URLs (Engine 2)
| Attack class | Detection |
|---|---|
| **SQL injection** | signature + ML |
| **Cross-site scripting (XSS)** | signature + ML |
| **Path / directory traversal** | signature + ML |
| **Command injection** | signature + ML |
| **LFI / RFI** | signature + ML |

- High-precision **signature layer** (`app/ml/features_payload.py`) with
  obfuscation-decoding (handles `%xx`, nested encoding, `+`).
- **Char n-gram TF-IDF classifier** (`training/train_payload.py`) for novel /
  obfuscated payloads, trainable on the **HTTP CSIC 2010** benchmark.

---

## 2. "from IP Data"

IP data is the differentiator — used for detection, not decoration.

| IP-data capability | Where |
|---|---|
| **Geolocation** (country / city / lat-lon) → world map | `app/engines/ip_intel.py::lookup_ip` |
| **ASN + hosting organisation** | same |
| **Hosting classification** (bulletproof / tor / hosting / residential) | same |
| **Reputation** (malicious / suspicious / clean) | same |
| **Reverse DNS (PTR)** consistency check | `ip_intel.reverse_dns` |
| **IP↔domain correlation** — resolve domain, compare *brand-implied country* vs *actual hosting country* → flag mismatch | `ip_intel.correlate_domain` |
| **Attacker-IP aggregation** — group server attacks by source IP; profile volume, technique diversity, request velocity, infra risk → ranked attacker score | `app/engines/payload_engine.py::_build_attacker_profiles` |
| **Attacker geo-map** — every attacker IP plotted from real coordinates | dashboard `panels/AttackerMap.jsx` |

Backends tried in order: **MaxMind GeoLite2** (live) → **bundled offline
reference** (demo-safe) → deterministic fallback (map never empty). No fabricated
geo is ever used to *assert* an IP-domain mismatch (integrity safeguard).

---

## 3. Explainability (why judges can trust it)

Every verdict returns ranked, plain-language reasons — IP-data reasons first.
Examples produced by the running system:

- *"IP-domain mismatch: 'sbi-verify.top' mimics a brand expected in IN, but is
  hosted in Russia (RU). Legitimate sites are not hosted here."*
- *"5 malicious requests from 45.135.232.17: 5× SQLi. Source network flagged
  malicious: Chang Way Technologies (bulletproof) (Russia)."*

Code: `app/engines/explain.py`.

---

## 4. Non-functional coverage (from the PPT)

| Claim | Status |
|---|---|
| Messaging-aware (WhatsApp/SMS URL scanning) | ✅ `/analyze/message` + WhatsApp Guard panel + MV3 extension |
| Multi-layer AI (ML + signatures + reasoning) | ✅ two engines, fused scoring |
| Real-time | ✅ WebSocket live feed, sub-second |
| Scalable | ✅ stateless engines + SQLite→Postgres path; Docker compose |
| Runs offline / demo-reliable | ✅ pre-trained models + offline IP reference; no external API required |

---

## 5. Real training data & measured accuracy

Both models are trained on **real, public datasets** (not synthetic):

| Model | Data | Result |
|---|---|---|
| **Engine 2 — server attacks** | HTTP **CSIC 2010** (61,065 real requests) + benign augmentation | **95.4%** accuracy; correctly separates attacks from normal traffic |
| **Engine 1 — phishing URLs** | **URLhaus** (real malicious) + **Majestic Million** (real benign) + brand-impersonation synthesis | **<1% false-positive rate on 6,000 unseen legit sites** (0.85% flagged MALICIOUS, 97.8% SAFE); 0 misses on a real-world holdout |
| **IP geolocation** | MaxMind **GeoLite2** City + ASN | Live per-IP country / city / ASN / org |

Reproduce: `python training/build_url_dataset.py` → `train_url.py` / `train_payload.py`
→ `validate_url_model.py` (acceptance test: legit must be SAFE, phishing MALICIOUS).

### Detection architecture (how real anti-phishing works)

A purely structural ML model can never be reliable on its own — legit URLs are
structurally wild (Google search, ChatGPT sessions, JWT tokens). So, exactly like
Google Safe Browsing / Microsoft SmartScreen, Zenithal decides by **reputation
first, ML only for the unknown**:

1. **Allowlist** — registered domain in the global top-1M reputable sites
   (Majestic, minus shorteners & public-hosting platforms) → **SAFE**, no matter
   how unusual the path/query is. Fixes google.com, chatgpt.com, github.com, etc.
2. **Blocklist** — exact host on a live threat feed (URLhaus) → **MALICIOUS**.
3. **ML (XGBoost, domain-focused)** — only for domains in neither list, i.e. the
   zero-day case where ML actually adds value. Loopback/private IPs are treated
   as local dev resources unless they serve a fake brand page.

Lists are rebuilt from public feeds by `training/build_reputation.py` and refresh
on the `update_feeds.py` schedule (999,950 reputable domains + ~6,000 malicious
hosts currently loaded). **No LLM/SLM is needed** — URL classification is a
reputation + gradient-boosting problem, and an LLM would be slower, costlier, and
would not fix the reputation gap.

**Engineering note we're proud of:** an early model over-flagged long legit URLs
(Gmail, Kaggle) because malware-feed URLs are long and top-site benign URLs were
short — the model learned "complex = bad". We fixed the ML with complexity-matched
benign data, then added the reputation layer above so common sites are decided by
reputation, not structure.

- PCAP ingestion is designed-for but access-log analysis is the shipped P0 path
  (more robust for a live demo).
