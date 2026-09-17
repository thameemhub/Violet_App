"""
Zenithal — URL Threat Intelligence from IP Data
FastAPI entrypoint (SIH25229).

Run:  cd backend && python -m uvicorn app.main:app --reload --port 8000
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import config, db
from app.api.routes import router
from app.api.community import community_router
from app.engines.url_engine import engine as url_engine
from app.engines.payload_engine import engine as payload_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("zenithal")

# Optional error monitoring (Sentry) — no-op unless SENTRY_DSN is set.
if config.SENTRY_DSN:
    try:
        import sentry_sdk  # type: ignore
        sentry_sdk.init(dsn=config.SENTRY_DSN, traces_sample_rate=0.1)
        logger.info("Sentry error monitoring enabled")
    except Exception as e:  # pragma: no cover
        logger.warning("Sentry init failed: %s", e)


from app.bot.telegram_bot import get_telegram_app

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    url_engine.load()
    payload_engine.load()
    logger.info("Zenithal ready | url_model=%s payload_model=%s auth=%s",
                url_engine.loaded, payload_engine.loaded, config.REQUIRE_API_KEY)
                
    # Start Telegram Bot
    bot_app = get_telegram_app()
    if bot_app:
        await bot_app.initialize()
        await bot_app.start()
        await bot_app.updater.start_polling()
        logger.info("Telegram Bot started in polling mode.")
        
    yield
    
    # Shutdown Telegram Bot
    if bot_app:
        logger.info("Shutting down Telegram Bot...")
        await bot_app.updater.stop()
        await bot_app.stop()
        await bot_app.shutdown()


app = FastAPI(
    title="Zenithal — URL Threat Intelligence from IP Data",
    description="SIH25229 — detects phishing URLs and server-side URL attacks "
                "(SQLi/XSS/traversal) and correlates them by attacker IP.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix=config.API_PREFIX)
app.include_router(community_router, prefix=f"{config.API_PREFIX}/community")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Never leak a stack trace to clients; log it for monitoring instead."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal error. The incident was logged."})


@app.get("/")
async def root() -> dict:
    return {
        "name": "Zenithal",
        "tagline": "Identification of URL-Based Attacks from IP Data",
        "docs": "/docs",
        "api": config.API_PREFIX,
    }
