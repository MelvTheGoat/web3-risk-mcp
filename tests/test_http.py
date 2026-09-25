import asyncio

import httpx
import pytest
import respx

from web3_risk_mcp.clients.http import HttpSource, RateLimiter, TTLCache, cache_key, redact
from web3_risk_mcp.errors import SourceError

URL = "https://api.example.com/data"


@pytest.fixture
async def source():
    async with httpx.AsyncClient() as client:
        yield HttpSource(
            "Example",
            client,
            requests_per_second=1000,
            cache_ttl=60,
            max_retries=2,
            backoff_base=0.001,
        )


@respx.mock
async def test_returns_json_and_caches_it(source):
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    assert await source.request_json("GET", URL, params={"a": 1}) == {"ok": True}
    assert await source.request_json("GET", URL, params={"a": 1}) == {"ok": True}
    assert route.call_count == 1


@respx.mock
async def test_same_request_at_same_time_makes_one_call(source):
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=[1]))
    results = await asyncio.gather(*(source.request_json("GET", URL) for _ in range(5)))
    assert results == [[1]] * 5
    assert route.call_count == 1


@respx.mock
async def test_retries_on_server_error_then_succeeds(source):
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"ok": 1})]
    )
    assert await source.request_json("GET", URL) == {"ok": 1}
    assert route.call_count == 2


@respx.mock
async def test_retries_on_timeout_then_gives_up_with_clear_message(source):
    route = respx.get(URL).mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(SourceError, match=r"timed out\. Gave up after 3 tries") as info:
        await source.request_json("GET", URL)
    assert info.value.source == "Example"
    assert route.call_count == 3


@respx.mock
async def test_does_not_retry_client_errors(source):
    route = respx.get(URL).mock(return_value=httpx.Response(403))
    with pytest.raises(SourceError, match="Check that your API key"):
        await source.request_json("GET", URL)
    assert route.call_count == 1


@respx.mock
async def test_validator_can_turn_a_200_into_an_error(source):
    respx.get(URL).mock(return_value=httpx.Response(200, json={"status": "0"}))

    def validate(body):
        if body["status"] == "0":
            raise SourceError("Example", "bad body")

    with pytest.raises(SourceError, match="bad body"):
        await source.request_json("GET", URL, validate=validate)


@respx.mock
async def test_failed_calls_are_not_cached(source):
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(404), httpx.Response(200, json={"ok": 1})]
    )
    with pytest.raises(SourceError):
        await source.request_json("GET", URL)
    assert await source.request_json("GET", URL) == {"ok": 1}
    assert route.call_count == 2


@respx.mock
async def test_invalid_json_gives_clear_error(source):
    respx.get(URL).mock(return_value=httpx.Response(200, text="<html>oops</html>"))
    with pytest.raises(SourceError, match="not valid JSON"):
        await source.request_json("GET", URL)


def test_api_keys_are_hidden_from_logs_and_cache_keys():
    params = {"apikey": "SECRET", "address": "0xabc"}
    assert redact(params) == {"apikey": "***", "address": "0xabc"}
    assert "SECRET" not in cache_key("GET", URL, params, None)


def test_ttl_cache_expires_entries(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("web3_risk_mcp.clients.http.time.monotonic", lambda: now[0])
    cache = TTLCache(ttl=10)
    cache.set("k", "v")
    assert cache.get("k") == "v"
    now[0] += 11
    assert cache.get("k") is None


def test_ttl_cache_drops_oldest_when_full():
    cache = TTLCache(ttl=10, max_entries=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert cache.get("a") is None
    assert cache.get("c") == 3


async def test_rate_limiter_spaces_out_requests():
    limiter = RateLimiter(rate=50)
    loop = asyncio.get_running_loop()
    start = loop.time()
    for _ in range(6):
        await limiter.acquire()
    # First call is free, the next five wait about 1/50 s each.
    assert loop.time() - start >= 0.08
