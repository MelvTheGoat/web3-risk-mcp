"""Tools for the evaluation script in eval/.

Two parts:

1. Metrics that measure how well scores separate risky from safe addresses.
2. A "cassette" that records real API responses to a file and plays them back
   later. With a cassette, anyone can re-run the evaluation without API keys
   or network access, and get the same numbers.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

_SECRET_KEYS = {"apikey", "api_key", "key", "token"}

# --- Metrics -----------------------------------------------------------------


@dataclass
class Metrics:
    risky_count: int
    safe_count: int
    roc_auc: float
    threshold: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    accuracy: float
    risky_mean: float
    risky_median: float
    safe_mean: float
    safe_median: float


def roc_auc(risky: list[float], safe: list[float]) -> float:
    """Chance that a random risky address scores higher than a random safe one.

    1.0 is perfect separation, 0.5 is no better than a coin flip. Ties count half.
    """
    if not risky or not safe:
        return float("nan")
    wins = 0.0
    for r in risky:
        for s in safe:
            wins += 1.0 if r > s else 0.5 if r == s else 0.0
    return wins / (len(risky) * len(safe))


def compute_metrics(risky: list[float], safe: list[float], threshold: int = 50) -> Metrics:
    """Metrics for "flag as risky when score >= threshold"."""
    tp = sum(1 for s in risky if s >= threshold)
    fn = len(risky) - tp
    fp = sum(1 for s in safe if s >= threshold)
    tn = len(safe) - fp
    total = len(risky) + len(safe)
    return Metrics(
        risky_count=len(risky),
        safe_count=len(safe),
        roc_auc=round(roc_auc(risky, safe), 3),
        threshold=threshold,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(tp / (tp + fp), 3) if tp + fp else 0.0,
        recall=round(tp / (tp + fn), 3) if tp + fn else 0.0,
        accuracy=round((tp + tn) / total, 3) if total else 0.0,
        risky_mean=round(mean(risky), 1) if risky else 0.0,
        risky_median=round(median(risky), 1) if risky else 0.0,
        safe_mean=round(mean(safe), 1) if safe else 0.0,
        safe_median=round(median(safe), 1) if safe else 0.0,
    )


# --- Cassette (record and replay) ---------------------------------------------


def request_key(request: httpx.Request) -> str:
    """A stable key for a request, with API keys removed."""
    parts = urlsplit(str(request.url))
    query = sorted((k, v) for k, v in parse_qsl(parts.query) if k.lower() not in _SECRET_KEYS)
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    body = request.content.decode() if request.content else ""
    return f"{request.method} {url} {body}"


class Cassette:
    """A file of recorded responses, keyed by request_key()."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[str, dict[str, Any]] = {}
        if path.exists():
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                self.entries = json.load(fh)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(self.path, "wt", encoding="utf-8") as fh:
            json.dump(self.entries, fh, sort_keys=True)


class RecordingTransport(httpx.AsyncBaseTransport):
    """Sends real requests and saves each response into the cassette."""

    def __init__(self, cassette: Cassette) -> None:
        self.cassette = cassette
        self.inner = httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        body = await response.aread()
        if response.status_code < 500 and response.status_code != 429:
            self.cassette.entries[request_key(request)] = {
                "status": response.status_code,
                "body": body.decode("utf-8", errors="replace"),
            }
        return httpx.Response(response.status_code, headers=response.headers, content=body)

    async def aclose(self) -> None:
        await self.inner.aclose()


class ReplayTransport(httpx.AsyncBaseTransport):
    """Answers only from the cassette. Unknown requests get HTTP 404."""

    def __init__(self, cassette: Cassette) -> None:
        self.cassette = cassette
        self.misses: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        entry = self.cassette.entries.get(request_key(request))
        if entry is None:
            self.misses.append(request_key(request))
            return httpx.Response(404, text="Not in cassette")
        return httpx.Response(
            entry["status"],
            content=entry["body"].encode(),
            headers={"content-type": "application/json"},
        )
