"""Test script for Community Intelligence API endpoints."""
import httpx
import json
import sys

BASE = "http://127.0.0.1:8000/api/v1/community"
DEVICE_ID = "test-device-001"
TEST_URL = "http://phishing-test.xyz/login"

def test(name, method, path, **kwargs):
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"  {method} {path}")
    try:
        r = getattr(httpx, method.lower())(path, timeout=30, **kwargs)
        print(f"  Status: {r.status_code}")
        data = r.json()
        print(f"  Response: {json.dumps(data, indent=2)}")
        if r.status_code >= 400:
            print("  *** FAILED ***")
            return False
        print("  ✅ PASSED")
        return True
    except Exception as e:
        print(f"  *** ERROR: {e} ***")
        return False

passed = 0
total = 4

# 1. POST /report
if test("Report URL", "POST", f"{BASE}/report",
        json={"device_id": DEVICE_ID, "url": TEST_URL, "reason": "Looks like a phishing page"}):
    passed += 1

# 2. GET /reputation
if test("Get Reputation", "GET", f"{BASE}/reputation",
        params={"url": TEST_URL}):
    passed += 1

# 3. POST /vote-safe
if test("Vote Safe", "POST", f"{BASE}/vote-safe",
        json={"device_id": DEVICE_ID, "url": "https://google.com"}):
    passed += 1

# 4. POST /vote-malicious
if test("Vote Malicious", "POST", f"{BASE}/vote-malicious",
        json={"device_id": DEVICE_ID, "url": TEST_URL}):
    passed += 1

print(f"\n{'='*60}")
print(f"RESULTS: {passed}/{total} endpoints passed")
if passed == total:
    print("✅ All community endpoints working!")
else:
    print("❌ Some endpoints failed")
    sys.exit(1)
