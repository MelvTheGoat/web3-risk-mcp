"""Shared HTTP plumbing used by every data source.

It gives each source four things:

1. A cache, so asking the same question twice does not call the API twice.
2. A rate limiter, so we stay under each provider's request limits.
3. Retries with exponential backoff: wait 0.5s, then 1s, then 2s, and so on,
   before trying a failed call again. Only failures that might go away
   (timeouts, "too many requests", server errors) are retried.
4. Clear error messages that never leak API keys.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from web3_risk_mcp.errors import SourceError

logger = logging.getLogger(__name__)

# Query parameters that hold secrets. They are removed from cache keys and error text.
_SECRET_PARAMS = frozenset({"apikey", "api_key", "key", "token", "access_token"})

_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class TTLCache:
    """A small in-memory cache where each entry expires after `ttl` seconds.

    When the cache is full, the oldest entry is dropped first.
    """

    def __init__(self, ttl: float, max_entries: int = 2048) -> None:
        self.ttl = ttl
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
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: Any) -> None:
        if self.ttl <= 0:
            return
        self._data[key] = (time.monotonic() + self.ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


class RateLimiter:
    """Lets at most `rate` requests through per second, on average.

    This is a "token bucket": the bucket refills at `rate` tokens per second,
    and each request takes one token. If the bucket is empty, we wait.
    """

    def __init__(self, rate: float, burst: int = 1) -> None:
        self.rate = rate
        self.capacity = max(1, burst)
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


def redact(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a copy of the query parameters with secret values hidden."""
    if not params:
        return {}
    return {k: ("***" if k.lower() in _SECRET_PARAMS else v) for k, v in params.items()}


def cache_key(method: str, url: str, params: Mapping[str, Any] | None, body: Any) -> str:
    safe = {k: v for k, v in (params or {}).items() if k.lower() not in _SECRET_PARAMS}
    return json.dumps([method, url, sorted(safe.items()), body], sort_keys=True, default=str)


# A validator looks at a decoded JSON body. It raises SourceError if the body
# is an error in disguise (many APIs return HTTP 200 with an error inside).
Validator = Callable[[Any], None]


class HttpSource:
    """One data source, such as Etherscan, with its own cache and rate limit."""

    def __init__(
        self,
        name: str,
        client: httpx.AsyncClient,
        *,
        requests_per_second: float,
        cache_ttl: float,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_max: float = 8.0,
    ) -> None:
        self.name = name
        self.client = client
        self.cache = TTLCache(cache_ttl)
        self.limiter = RateLimiter(requests_per_second)
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        # Requests for the same thing at the same moment share one network call.
        self._inflight: dict[str, asyncio.Future[Any]] = {}

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        headers: Mapping[str, str] | None = None,
        validate: Validator | None = None,
        use_cache: bool = True,
    ) -> Any:
        """Send a request and return the decoded JSON body.

        Raises SourceError with a plain-English message if it keeps failing.
        """
        key = cache_key(method, url, params, json_body)
        if use_cache:
            cached = self.cache.get(key)
            if cached is not None:
                return cached
            pending = self._inflight.get(key)
            if pending is not None:
                return await asyncio.shield(pending)

        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        if use_cache:
            self._inflight[key] = future
        try:
            data = await self._request_with_retries(
                method, url, params=params, json_body=json_body, headers=headers, validate=validate
            )
        except BaseException as exc:
            if not future.done():
                future.set_exception(exc)
                # Mark the exception as seen so asyncio does not warn when nobody waits.
                future.exception()
            raise
        else:
            if use_cache:
                self.cache.set(key, data)
            future.set_result(data)
            return data
        finally:
            self._inflight.pop(key, None)

    async def _request_with_retries(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None,
        json_body: Any,
        headers: Mapping[str, str] | None,
        validate: Validator | None,
    ) -> Any:
        attempt = 0
        while True:
            retry_after: float | None = None
            try:
                await self.limiter.acquire()
                response = await self.client.request(
                    method, url, params=params, json=json_body, headers=headers
                )
                if response.status_code in _RETRYABLE_STATUS:
                    retry_after = _parse_retry_after(response.headers.get("retry-after"))
                    raise SourceError(
                        self.name,
                        _status_message(response.status_code),
                        retryable=True,
                    )
                if response.status_code >= 400:
                    raise SourceError(self.name, _status_message(response.status_code))
                try:
                    data = response.json()
                except ValueError as exc:
                    raise SourceError(
                        self.name, "The service sent back something that is not valid JSON."
                    ) from exc
                if validate is not None:
                    validate(data)
                return data
            except httpx.TimeoutException as exc:
                error = SourceError(self.name, "The request timed out.", retryable=True)
                error.__cause__ = exc
            except httpx.TransportError as exc:
                error = SourceError(
                    self.name,
                    f"Could not connect ({type(exc).__name__}). "
                    "Check your internet connection or the endpoint URL.",
                    retryable=True,
                )
                error.__cause__ = exc
            except SourceError as exc:
                error = exc

            if not error.retryable or attempt >= self.max_retries:
                if error.retryable and attempt > 0:
                    error = SourceError(
                        self.name,
                        f"{error.message} Gave up after {attempt + 1} tries.",
                        retryable=True,
                    )
                logger.warning("%s request failed: %s %s", self.name, url, redact(params))
                raise error

            delay = retry_after if retry_after is not None else self._backoff(attempt)
            logger.info(
                "%s: %s Retrying in %.1fs (try %d of %d).",
                self.name,
                error.message,
                delay,
                attempt + 2,
                self.max_retries + 1,
            )
            await asyncio.sleep(delay)
            attempt += 1

    def _backoff(self, attempt: int) -> float:
        # Exponential backoff with "jitter" (a little randomness), so many
        # clients that fail together do not all retry at the same instant.
        delay = min(self.backoff_max, self.backoff_base * (2**attempt))
        return delay * random.uniform(0.8, 1.2)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return min(30.0, max(0.0, float(value)))
    except ValueError:
        return None


def _status_message(status: int) -> str:
    if status == 429:
        return "Too many requests (HTTP 429). The rate limit was hit."
    if status in (401, 403):
        return f"Access denied (HTTP {status}). Check that your API key is correct."
    if status == 404:
        return "Not found (HTTP 404)."
    if status >= 500:
        return f"The service had an internal error (HTTP {status})."
    return f"The request failed (HTTP {status})."
