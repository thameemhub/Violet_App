"""
Zenithal — WebSocket hub.
Broadcasts every new detection to all connected dashboards so the SOC feed
and world map update live.
"""

import asyncio
import json

from fastapi import WebSocket


class ConnectionHub:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, event_type: str, data: dict) -> None:
        message = json.dumps({"type": event_type, "data": data}, default=str)
        async with self._lock:
            dead = []
            for ws in self._connections:
                try:
                    await ws.send_text(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._connections.discard(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


hub = ConnectionHub()
