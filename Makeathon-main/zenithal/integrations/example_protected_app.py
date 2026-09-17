"""
Demo: a developer's own app protected by the Zenithal WAF in real time.

Run (with the Zenithal backend already up on :8000):
    cd zenithal
    .venv/Scripts/python -m uvicorn integrations.example_protected_app:app --port 9000

Then try:
    curl "http://127.0.0.1:9000/products?id=5"                 -> 200 OK (normal)
    curl "http://127.0.0.1:9000/products?id=1' OR '1'='1"      -> 403 BLOCKED (SQLi)
    curl "http://127.0.0.1:9000/search?q=<script>alert(1)</script>" -> 403 BLOCKED (XSS)

Each blocked attack also appears on the Zenithal dashboard's attacker map.
"""

from fastapi import FastAPI
from integrations.waf_middleware import ZenithalWAF

app = FastAPI(title="Example Shop (protected by Zenithal WAF)")
app.add_middleware(ZenithalWAF, report_url="http://127.0.0.1:8000", block=True)


@app.get("/")
async def home():
    return {"app": "example shop", "status": "protected by Zenithal WAF"}


@app.get("/products")
async def products(id: int | str = 1):
    return {"product_id": id, "name": "Demo product"}


@app.get("/search")
async def search(q: str = ""):
    return {"query": q, "results": []}
