"""
Zenithal log agent — watch a live web-server log and stream attacks automatically.

Instead of manually uploading a log, point this at your real access log. It
follows the file (like `tail -f`), and whenever new lines are appended it sends
them to Zenithal, which detects URL attacks and lights up the dashboard / fires
alerts. This is the "notify me automatically, no manual work" story.

Usage:
    python integrations/log_agent.py /var/log/nginx/access.log
    python integrations/log_agent.py C:\\logs\\access.log --url http://127.0.0.1:8000

Test locally:
    python integrations/log_agent.py demo/live.log       # then append lines to it
"""

import argparse
import time
import urllib.request
import json
import os


def post_lines(api: str, lines: list[str]) -> dict | None:
    if not lines:
        return None
    data = json.dumps({"text": "\n".join(lines)}).encode()
    req = urllib.request.Request(f"{api}/api/v1/analyze/logtext", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"  [!] could not reach Zenithal: {e}")
        return None


def follow(path: str, api: str, batch_seconds: float = 2.0):
    print(f"[*] Zenithal log agent watching {path}  ->  {api}")
    # start at end of file so we only process NEW traffic
    while not os.path.exists(path):
        print("    waiting for log file to appear...")
        time.sleep(2)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        buffer: list[str] = []
        last = time.time()
        while True:
            line = f.readline()
            if line:
                buffer.append(line.strip())
            else:
                time.sleep(0.3)
            if buffer and (time.time() - last >= batch_seconds):
                report = post_lines(api, buffer)
                if report and report.get("malicious_requests"):
                    print(f"  [!] {report['malicious_requests']} attack(s) from "
                          f"{report['unique_attackers']} IP(s): {report['attack_breakdown']}")
                buffer.clear()
                last = time.time()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile", help="path to the access log to watch")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="Zenithal API base URL")
    args = ap.parse_args()
    try:
        follow(args.logfile, args.url.rstrip("/"))
    except KeyboardInterrupt:
        print("\n[*] stopped.")


if __name__ == "__main__":
    main()
