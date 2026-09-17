"""
Zenithal — Engine 2: URL-attack detection from IP data (server logs / PCAP).

Ingests web-server access logs (Apache/Nginx common & combined format) or a
plain list of request lines, classifies each request URL for SQLi / XSS /
traversal / command-injection / LFI-RFI, then aggregates detections by source
IP into ranked attacker profiles enriched with IP intelligence.

This is the literal reading of SIH25229: "Identification of URL Based Attacks
from IP Data".
"""

import re
from collections import defaultdict
from datetime import datetime

import joblib

from app import config
from app.engines import ip_intel
from app.engines.explain import explain_attacker
from app.ml.features_payload import detect_payload

# Apache/Nginx common + combined log:
#   IP - - [10/Oct/2024:13:55:36 +0000] "GET /path?q=x HTTP/1.1" 200 1234 "ref" "ua"
_LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'.*?\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>[^"\s]+)\s+HTTP/[\d.]+"'
    r'\s+(?P<status>\d{3})'
)
_APACHE_TIME = "%d/%b/%Y:%H:%M:%S %z"


class PayloadEngine:
    def __init__(self) -> None:
        self._pipeline = None  # sklearn Pipeline: char TF-IDF -> classifier
        self.loaded = False

    def load(self) -> None:
        if config.PAYLOAD_MODEL_PATH.exists():
            try:
                self._pipeline = joblib.load(config.PAYLOAD_MODEL_PATH)
                self.loaded = True
            except Exception:
                self._pipeline = None
                self.loaded = False

    def _ml_predict(self, decoded: str):
        """Return (is_attack, attack_type, proba). attack_type is None because
        the ML layer is a binary anomaly detector; type comes from signatures."""
        if self._pipeline is None:
            return (False, None, 0.0)
        proba = float(self._pipeline.predict_proba([decoded])[0][1])
        return (proba >= 0.5, None, proba)

    # -- Parsing ----------------------------------------------------------
    def parse_log(self, text: str) -> list[dict]:
        """Parse log text into request rows. Falls back to treating each line
        as a bare 'IP target' or just a target if it isn't standard log format."""
        rows: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LOG_RE.search(line)
            if m:
                rows.append({
                    "ip": m.group("ip"),
                    "time": _parse_time(m.group("time")),
                    "method": m.group("method"),
                    "target": m.group("target"),
                    "status": int(m.group("status")),
                })
                continue
            # Fallback: "IP<space>target" or bare target
            parts = line.split(None, 1)
            if len(parts) == 2 and _looks_like_ip(parts[0]):
                rows.append({"ip": parts[0], "time": None, "method": "GET",
                             "target": parts[1], "status": 0})
            else:
                rows.append({"ip": "0.0.0.0", "time": None, "method": "GET",
                             "target": line, "status": 0})
        return rows

    # -- Analysis ---------------------------------------------------------
    def analyze_log(self, text: str, max_rows: int = 20000) -> dict:
        rows = self.parse_log(text)[:max_rows]
        detections: list[dict] = []
        per_ip: dict[str, dict] = defaultdict(lambda: {
            "attack_types": defaultdict(int), "hits": [], "times": [],
        })

        for row in rows:
            result = detect_payload(row["target"], ml_predict=self._ml_predict)
            if not result["is_attack"]:
                continue
            det = {
                "src_ip": row["ip"],
                "method": row["method"],
                "target": row["target"][:300],
                "attack_type": result["attack_type"],
                "label": result["label"],
                "score": result["score"],
                "evidence": result["evidence"],
                "detected_by": result["detected_by"],
                "time": row["time"].isoformat() if row["time"] else None,
            }
            detections.append(det)
            bucket = per_ip[row["ip"]]
            bucket["attack_types"][result["attack_type"]] += 1
            bucket["hits"].append(det)
            if row["time"]:
                bucket["times"].append(row["time"])

        attackers = self._build_attacker_profiles(per_ip)

        type_breakdown: dict[str, int] = defaultdict(int)
        for d in detections:
            type_breakdown[d["attack_type"]] += 1

        return {
            "total_requests": len(rows),
            "malicious_requests": len(detections),
            "unique_attackers": len(attackers),
            "attack_breakdown": dict(type_breakdown),
            "attackers": attackers,
            "detections": detections,
        }

    def _build_attacker_profiles(self, per_ip: dict) -> list[dict]:
        profiles = []
        for ip, data in per_ip.items():
            times = sorted(data["times"])
            burst = None
            if len(times) >= 2:
                burst = (times[-1] - times[0]).total_seconds()
            attack_types = dict(data["attack_types"])
            total = sum(attack_types.values())
            intel = ip_intel.lookup_ip(ip)

            profile = {
                "ip": ip,
                "intel": intel,
                "total_hits": total,
                "attack_types": attack_types,
                "distinct_techniques": len(attack_types),
                "burst_seconds": burst,
                "first_seen": times[0].isoformat() if times else None,
                "last_seen": times[-1].isoformat() if times else None,
            }
            profile["risk_score"] = _attacker_risk(profile)
            profile["reasons"] = explain_attacker(profile)
            profiles.append(profile)

        profiles.sort(key=lambda p: p["risk_score"], reverse=True)
        return profiles


def _attacker_risk(p: dict) -> float:
    """0-100 attacker-IP risk from volume, technique diversity, velocity, infra."""
    score = 0.0
    score += min(p["total_hits"] * 4, 40)          # volume
    score += p["distinct_techniques"] * 8           # diversity
    intel = p.get("intel", {})
    if intel.get("reputation") == "malicious":
        score += 25
    elif intel.get("hosting_type") in ("bulletproof", "tor"):
        score += 18
    elif intel.get("reputation") == "suspicious":
        score += 10
    burst = p.get("burst_seconds")
    if burst is not None and p["total_hits"] >= 5 and burst > 0:
        if p["total_hits"] / burst > 1:             # >1 req/s = automated
            score += 15
    return round(min(score, 100.0), 1)


def _parse_time(raw: str):
    try:
        return datetime.strptime(raw, _APACHE_TIME)
    except Exception:
        return None


def _looks_like_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


engine = PayloadEngine()
