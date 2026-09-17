"""
Zenithal — real-time alerting.

Fires a notification the moment a high-risk detection occurs, so users are
warned automatically instead of checking a dashboard. Supports a generic/Slack
webhook and Telegram. All channels are optional (no-op unless configured) and
best-effort (never block or crash a scan). Runs in the background.
"""

import asyncio

import httpx

from app import config

_ORDER = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


def _should_alert(verdict: str) -> bool:
    threshold = _ORDER.get(config.ALERT_MIN_VERDICT, 2)
    return _ORDER.get(verdict, 0) >= threshold


def _format(detection: dict) -> str:
    v = detection.get("verdict", "?")
    emoji = "⛔" if v == "MALICIOUS" else "⚠️"
    parts = [
        f"{emoji} Zenithal alert: {v} ({detection.get('score', '?')}/100)",
        f"Channel: {detection.get('channel', '?')}",
        f"Target: {detection.get('input', '')[:200]}",
    ]
    if detection.get("src_ip"):
        parts.append(f"Source IP: {detection['src_ip']} ({detection.get('country', '')})")
    reasons = detection.get("reasons") or []
    if reasons:
        parts.append("Why: " + reasons[0])
    return "\n".join(parts)


async def _post_webhook(client: httpx.AsyncClient, text: str) -> None:
    # Slack accepts {"text": ...}; most generic webhooks accept JSON too.
    try:
        await client.post(config.ALERT_WEBHOOK_URL, json={"text": text}, timeout=5)
    except Exception:
        pass


async def _post_telegram(client: httpx.AsyncClient, text: str) -> None:
    try:
        url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
        await client.post(url, json={"chat_id": config.TELEGRAM_CHAT_ID, "text": text}, timeout=5)
    except Exception:
        pass


async def _send(detection: dict) -> None:
    text = _format(detection)
    async with httpx.AsyncClient() as client:
        tasks = []
        if config.ALERT_WEBHOOK_URL:
            tasks.append(_post_webhook(client, text))
        if config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID:
            tasks.append(_post_telegram(client, text))
        if tasks:
            await asyncio.gather(*tasks)


def maybe_alert(detection: dict) -> None:
    """Fire-and-forget alert if the verdict is severe enough and a channel is
    configured. Safe to call from request handlers."""
    if not (config.ALERT_WEBHOOK_URL or config.TELEGRAM_BOT_TOKEN):
        return
    if not _should_alert(detection.get("verdict", "SAFE")):
        return
    try:
        asyncio.create_task(_send(detection))
    except RuntimeError:
        pass  # no running loop (e.g. called outside async context)


def enabled() -> bool:
    return bool(config.ALERT_WEBHOOK_URL or (config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID))
