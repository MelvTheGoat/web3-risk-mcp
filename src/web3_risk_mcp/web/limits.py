"""Rate limits and a result cache for the web app.

The checks call free APIs (Etherscan, GoPlus) that have daily limits. These
helpers make sure one visitor, or a bot, cannot use them all up.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from typing import Any

from starlette.requests import Request


class WindowLimiter:
    """Allows at most `limit` events per `window` seconds for each key (for
    example each visitor IP). Old keys are forgotten so memory stays small."""

    def __init__(self, limit: int, window: float, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._events: OrderedDict[str, deque[float]] = OrderedDict()

    def _recent(self, key: str, now: float) -> deque[float]:
        events = self._events.get(key)
        if events is None:
            return deque()
        while events and events[0] <= now - self.window:
            events.popleft()
        return events

    def wait_time(self, key: str, now: float | None = None) -> float:
        """Seconds until `key` may act again. 0 means it may act now."""
        now = time.monotonic() if now is None else now
        events = self._recent(key, now)
        if len(events) < self.limit:
            return 0.0
        return max(0.0, events[0] + self.window - now)

    def record(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        events = self._recent(key, now)
        events.append(now)
        self._events[key] = events
        self._events.move_to_end(key)
        while len(self._events) > self.max_keys:
            self._events.popitem(last=False)


class ResultCache:
    """Keeps finished results for a while. Each entry has its own lifetime."""

    def __init__(self, max_entries: int = 2000) -> None:
        self.max_entries = max_entries
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()

    def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires_at, value = item
        if time.monotonic() >= expires_at:
            del self._data[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: float) -> None:
        if ttl <= 0:
            return
        self._data[key] = (time.monotonic() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)


def client_ip(request: Request, header: str = "") -> str:
    """The visitor's IP address.

    Behind a proxy, the connection comes from the proxy, so the real IP is
    read from a header the proxy sets. Only name a header that the proxy
    always overwrites; otherwise a visitor could fake it to dodge the limits.
    """
    if header:
        value = request.headers.get(header, "").split(",")[0].strip()
        if value:
            return value
    return request.client.host if request.client else "unknown"
