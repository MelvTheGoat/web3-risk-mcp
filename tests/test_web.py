"""Tests for the Arc Safe Send web app.

The app runs with the recorded Arc responses from tests/arc_fixtures.py, so
these tests use real Arc data without the network.
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.arc_fixtures import ACTIVE_WALLET, BLOCKED_WALLET, CASSETTE, EURC, USDC
from web3_risk_mcp.analysis.arc import SendCheck
from web3_risk_mcp.analysis.score import RiskScore
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.evaluation import Cassette, ReplayTransport
from web3_risk_mcp.scoring import RULES_VERSION, ScoreContribution
from web3_risk_mcp.services import Services
from web3_risk_mcp.web.advice import send_advice
from web3_risk_mcp.web.app import create_app
from web3_risk_mcp.web.limits import ResultCache, WindowLimiter
from web3_risk_mcp.web.settings import WebSettings

ARC = get_chain("arc")
CCTP = "0x28b5a0e9c621a5badaa536219b3a228c8168cf5d"


def make_client(settings, **limits) -> TestClient:
    def services_factory() -> Services:
        replay = httpx.AsyncClient(transport=ReplayTransport(Cassette(CASSETTE)))
        services = Services(settings.model_copy(update={"http_max_retries": 0}), client=replay)
        services._owns_client = True  # so the app closes it on shutdown
        return services

    web = WebSettings(_env_file=None, **limits)
    return TestClient(create_app(web, services_factory=services_factory))


@pytest.fixture
def client(settings):
    with make_client(settings) as c:
        yield c


def check(client, address, chain="arc", **headers):
    return client.post("/api/check", json={"address": address, "chain": chain}, headers=headers)


# --- Pages and settings ---------------------------------------------------------


def test_page_and_files_are_served_with_strict_security_headers(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "Arc Safe Send" in page.text
    policy = page.headers["content-security-policy"]
    assert "script-src 'self'" in policy and "frame-ancestors 'none'" in policy
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/healthz").json()["status"] == "ok"


def test_config_puts_arc_first_and_never_leaks_a_private_rpc(settings):
    private = settings.model_copy(update={"rpc_url_arc": "https://rpc.example/SECRET"})
    with make_client(private) as c:
        config = c.get("/api/config").json()
    assert config["default_chain"] == "arc"
    assert config["chains"][0]["key"] == "arc"
    assert config["arc"]["chain_id_hex"] == "0x13b2"
    assert config["arc"]["rpc_url"] == "https://rpc.mainnet.arc.io"
    assert config["arc"]["native_decimals"] == 18
    assert config["rules_version"] == RULES_VERSION
    assert config["attestation_contract"] is None


# --- The check ---------------------------------------------------------------------


def test_blocked_wallet_cannot_be_paid(client):
    response = check(client, BLOCKED_WALLET.upper().replace("0X", "0x"))
    assert response.status_code == 200
    data = response.json()
    assert data["result"]["score"] == 100
    assert data["result"]["level"] == "critical"
    assert data["explorer_url"] == f"https://explorer.arc.io/address/{BLOCKED_WALLET}"
    advice = data["send_advice"]
    assert advice["can_send"] is False
    assert any("blocklist" in m for m in advice["messages"])
    assert data["cached"] is False


def test_ordinary_wallet_can_be_paid_without_extra_confirmation(client):
    data = check(client, ACTIVE_WALLET).json()
    advice = data["send_advice"]
    assert advice["can_send"] is True
    assert advice["needs_confirmation"] is False
    assert any("simulated" in m for m in advice["messages"])


@pytest.mark.parametrize("token", [USDC, EURC])
def test_token_contracts_cannot_be_paid_because_arc_refuses(client, token):
    advice = check(client, token).json()["send_advice"]
    assert advice["can_send"] is False
    assert any("would refuse" in m for m in advice["messages"])


def test_bad_input_gets_a_clear_400(client):
    bad_address = check(client, "hello")
    assert bad_address.status_code == 400
    assert "not a valid address" in bad_address.json()["error"]
    bad_chain = check(client, ACTIVE_WALLET, chain="solana")
    assert bad_chain.status_code == 400
    assert "Unknown chain" in bad_chain.json()["error"]
    no_body = client.post("/api/check", json={})
    assert no_body.status_code == 400
    assert "address" in no_body.json()["error"]


def test_failed_sources_still_give_an_answer_with_low_confidence(client):
    # Nothing for this address is in the recording, so every source fails,
    # just as if every API were down.
    data = check(client, "0x" + "ab" * 20).json()
    result = data["result"]
    assert result["confidence"] == "low"
    assert result["address_type"] == "unknown"
    assert result["data_gaps"]
    assert data["send_advice"]["needs_confirmation"] is True


# --- Cache and limits ----------------------------------------------------------------


def test_cache_answers_repeat_checks_without_using_the_limit(settings):
    with make_client(settings, web_checks_per_minute=1) as c:
        first = check(c, BLOCKED_WALLET)
        again = check(c, BLOCKED_WALLET)
        other = check(c, ACTIVE_WALLET)
    assert first.json()["cached"] is False
    assert again.status_code == 200 and again.json()["cached"] is True
    assert other.status_code == 429
    assert int(other.headers["retry-after"]) > 0
    assert "per minute" in other.json()["error"]


def test_limits_apply_per_visitor_ip_from_the_proxy_header(settings):
    with make_client(settings, web_checks_per_minute=1, web_client_ip_header="true-client-ip") as c:
        assert check(c, BLOCKED_WALLET, **{"true-client-ip": "1.1.1.1"}).status_code == 200
        assert check(c, ACTIVE_WALLET, **{"true-client-ip": "2.2.2.2"}).status_code == 200
        assert check(c, USDC, **{"true-client-ip": "1.1.1.1"}).status_code == 429


def test_daily_limit_is_shared_by_everyone(settings):
    with make_client(settings, web_checks_per_day=1, web_client_ip_header="true-client-ip") as c:
        assert check(c, BLOCKED_WALLET, **{"true-client-ip": "1.1.1.1"}).status_code == 200
        blocked = check(c, ACTIVE_WALLET, **{"true-client-ip": "2.2.2.2"})
    assert blocked.status_code == 429
    assert "daily" in blocked.json()["error"]


def test_window_limiter_and_result_cache(monkeypatch):
    limiter = WindowLimiter(limit=2, window=60)
    limiter.record("a", now=0)
    limiter.record("a", now=10)
    assert limiter.wait_time("a", now=20) == 40
    assert limiter.wait_time("b", now=20) == 0
    assert limiter.wait_time("a", now=61) == 0  # the first event left the window

    clock = [100.0]
    monkeypatch.setattr("web3_risk_mcp.web.limits.time.monotonic", lambda: clock[0])
    cache = ResultCache()
    cache.set("k", "v", ttl=60)
    assert cache.get("k") == "v"
    clock[0] = 161
    assert cache.get("k") is None


# --- Send advice ----------------------------------------------------------------------


def _result(**overrides) -> RiskScore:
    base = {
        "score": 0,
        "level": "low",
        "verdict": "No major red flags in the data we could check.",
        "confidence": "high",
        "contributions": [],
        "points_added": 0,
        "points_removed": 0,
        "decisive_floor_applied": False,
        "chain": "arc",
        "address": "0x" + "22" * 20,
        "address_type": "wallet",
        "checks_run": [],
        "send_check": SendCheck(would_succeed=True, explanation="A test payment goes through."),
    }
    return RiskScore(**{**base, **overrides})


def test_clean_wallet_can_be_paid():
    advice = send_advice(_result(), ARC)
    assert (advice.can_send, advice.needs_confirmation) == (True, False)
    assert advice.messages[0].startswith("No red flags")


def test_high_risk_needs_confirmation_but_is_not_blocked():
    advice = send_advice(_result(score=60, level="high", verdict="Serious red flags."), ARC)
    assert (advice.can_send, advice.needs_confirmation) == (True, True)
    assert advice.messages[0].startswith("High risk (60/100)")


def test_refused_test_payment_blocks_sending():
    refused = SendCheck(
        would_succeed=False, reason="Blocked address", explanation="Arc would refuse it."
    )
    advice = send_advice(_result(send_check=refused), ARC)
    assert advice.can_send is False
    assert "Arc would refuse it." in advice.messages


def test_without_a_simulation_the_known_rules_still_apply():
    zero = send_advice(_result(address="0x" + "0" * 40, send_check=None), ARC)
    assert zero.can_send is False
    blocked = ScoreContribution(
        finding_id="address.usdc_blocklisted",
        title="Blocked by the USDC contract",
        severity="critical",
        points=80,
        counted=True,
        reason="",
        source="RPC",
        rule="rule",
    )
    listed = send_advice(_result(contributions=[blocked], send_check=None), ARC)
    assert listed.can_send is False
    contract = send_advice(_result(address_type="contract", send_check=None), ARC)
    assert (contract.can_send, contract.needs_confirmation) == (True, True)
