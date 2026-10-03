"""Tests for the Arc-only logic.

Most tests replay real Arc mainnet responses recorded in
tests/fixtures/arc_cassette.json.gz (see tests/arc_fixtures.py), so they
check behaviour against real data without any network. The rest use small
hand-made responses to pin one rule each.
"""

import hashlib
import json

import httpx
import pytest
import respx

from tests.arc_fixtures import (
    ACTIVE_WALLET,
    ARC,
    BLOCKED_WALLET,
    CASSETTE,
    EURC,
    RECORDED_AT,
    USDC,
)
from tests.mocks import mock_etherscan, mock_goplus_address, mock_goplus_address_by, mock_rpc
from web3_risk_mcp import labels
from web3_risk_mcp.analysis.address import address_findings
from web3_risk_mcp.analysis.arc import blocklisted_by, other_tokens, without_value
from web3_risk_mcp.analysis.score import score_risk
from web3_risk_mcp.analysis.trace import trace_funds
from web3_risk_mcp.analysis.wallet import get_wallet_profile
from web3_risk_mcp.chains import ARC_SYSTEM_EMITTER, get_chain
from web3_risk_mcp.clients.rpc import SIMULATION_SENDER
from web3_risk_mcp.errors import SourceError
from web3_risk_mcp.evaluation import Cassette, ReplayTransport
from web3_risk_mcp.models import Finding, SourceStatus
from web3_risk_mcp.scoring import (
    DECISIVE_FLOOR,
    FUNCTION_GROUPS,
    LEVELS,
    OWNER_POWER_CAP,
    OWNER_POWER_GROUPS,
    RULES,
    RULES_VERSION,
    SEVERITY_POINTS,
    score_findings,
)
from web3_risk_mcp.services import Services

ETH = get_chain("ethereum")
CCTP_MINTER = "0xfd78ee919681417d192449715b2594ab58f5d002"
FUNDER = "0x9ff2e7b5a9d9f2cdc72deff1dc5aa920be3fbfda"
ZERO = "0x" + "0" * 40
ME = "0x" + "11" * 20
FRIEND = "0x" + "22" * 20
SHOP = "0x" + "33" * 20
NOT_BLOCKED = "0x" + "0" * 64
BLOCKED = "0x" + "0" * 63 + "1"


@pytest.fixture
async def replay(settings):
    """Services that answer only from the recorded Arc responses."""
    transport = ReplayTransport(Cassette(CASSETTE))
    async with httpx.AsyncClient(transport=transport) as client:
        yield Services(settings.model_copy(update={"http_max_retries": 0}), client=client)
    assert transport.misses == [], "A request was not in the cassette. Re-record it."


# --- Real Arc data, replayed --------------------------------------------------


async def test_wallet_blocked_by_usdc_and_eurc_scores_critical(replay):
    result = await score_risk(replay, ARC, BLOCKED_WALLET, now=RECORDED_AT)

    assert result.score == 100
    assert result.level == "critical"
    assert result.confidence == "high"
    by_id = {c.finding_id: c for c in result.contributions}
    assert {"address.usdc_blocklisted", "address.eurc_blocklisted"} <= set(by_id)
    # Same group as "sanctioned", which GoPlus also reports: not counted twice.
    assert by_id["address.usdc_blocklisted"].counted is False
    assert by_id["address.sanctioned"].counted is True
    assert "Blocklist" in {s.source for s in result.sources}
    assert result.rules_version == RULES_VERSION
    # A simulated 1 USDC payment is refused by Arc itself.
    assert result.send_check.would_succeed is False
    assert result.send_check.reason == "Blocked address"
    assert "blocklist" in result.send_check.explanation


async def test_wallet_profile_reads_usdc_from_the_system_stream(replay):
    profile = await get_wallet_profile(replay, ARC, ACTIVE_WALLET, now=RECORDED_AT)

    assert profile.native_symbol == "USDC"
    # 18-decimal native balance, read with eth_getBalance.
    assert profile.native_balance == pytest.approx(0.3016077975079991)
    assert profile.blocklisted_by == []
    # USDC shows once, counted from the system stream. Etherscan also lists the
    # system emitter as a nameless token and repeats ERC-20 transfers under the
    # USDC contract; neither may appear here.
    assert [
        (t.token, t.symbol, t.transfers_in, t.transfers_out) for t in profile.recent_tokens
    ] == [(USDC, "USDC", 32, 19)]
    # This USDC moved through the ERC-20 interface (transferFrom). Plain
    # transactions show those as zero-value calls to the USDC contract, so the
    # amounts below can only come from the system stream, in whole USDC.
    flows = {cp.address: cp for cp in profile.top_counterparties}
    assert flows[FUNDER].received_from_them == 7862.869757
    assert flows[CCTP_MINTER].sent_to_them == 7862.432274
    assert flows[CCTP_MINTER].label == "Circle CCTP: TokenMinterV2"
    assert profile.first_funded_by == FUNDER
    # The wallet received USDC before it sent its first transaction.
    assert profile.activity.first_seen.isoformat() == "2026-09-29T18:01:01+00:00"
    assert any("EIP-7708" in note for note in profile.notes)


async def test_trace_follows_usdc_and_reaches_a_bridge_mint(replay):
    trace = await trace_funds(replay, ARC, ACTIVE_WALLET, hops=2)

    hop1 = {(e.from_address, e.to_address): e for e in trace.edges if e.hop == 1}
    assert hop1[(FUNDER, ACTIVE_WALLET)].transfers == 31
    assert hop1[(FUNDER, ACTIVE_WALLET)].native_value == 7862.869757
    assert hop1[(ACTIVE_WALLET, CCTP_MINTER)].native_value == 7862.432274
    # USDC is not also counted as a token transfer.
    assert all(e.token_transfers == 0 for e in hop1.values())
    nodes = {n.address: n for n in trace.nodes}
    assert nodes[CCTP_MINTER].expanded is False  # Circle's bridge touches everyone.
    # Hop 2 reads the USDC stream too: it sees USDC minted to the funder by a
    # CCTP bridge-in, which no normal transaction list shows.
    mint = next(e for e in trace.edges if e.from_address == ZERO)
    assert mint.to_address == FUNDER
    assert mint.native_value == 1651.443421
    assert nodes[ZERO].label == "USDC mint or burn (Arc)"
    # Every unknown address was checked against the blocklists, and none is blocked.
    assert all(n.blocklisted_by == [] for n in trace.nodes)
    assert {"Etherscan", "GoPlus", "Blocklist"} == {s.source for s in trace.sources}
    assert trace.findings == []


async def test_ordinary_arc_wallet_scores_low(replay):
    result = await score_risk(replay, ARC, ACTIVE_WALLET, now=RECORDED_AT)

    assert result.score == 10
    assert [c.finding_id for c in result.contributions if c.points] == ["wallet.very_new"]
    assert result.confidence == "high"
    assert result.send_check.would_succeed is True
    assert "nothing was sent" in result.send_check.explanation


@pytest.mark.parametrize(("token", "score"), [(USDC, 0), (EURC, 15)])
async def test_token_is_not_flagged_by_its_own_blocklist(replay, token, score):
    # Circle's contracts block their own address so nobody sends tokens to the
    # contract by mistake. That must not look like a sanctions hit.
    result = await score_risk(replay, ARC, token, now=RECORDED_AT)

    assert result.address_type == "token"
    assert not [c for c in result.contributions if c.finding_id.endswith("_blocklisted")]
    assert result.score == score
    # But a USDC payment to either contract is refused: USDC blocks its own
    # address, and the EURC contract does not accept plain USDC.
    assert result.send_check.would_succeed is False
    assert result.send_check.reason == (
        "Blocked address" if token == USDC else "execution reverted"
    )


# --- One rule at a time, with hand-made responses ------------------------------


def test_without_value_and_other_tokens_remove_double_counted_usdc():
    txs = [{"value": "0"}, {"value": "5"}, {"value": None}]
    assert without_value(txs) == [{"value": "0"}, {"value": None}]
    rows = [
        {"contractAddress": ARC_SYSTEM_EMITTER},
        {"contractAddress": USDC},
        {"contractAddress": EURC},
    ]
    assert other_tokens(ARC, rows) == [{"contractAddress": EURC}]
    # On other chains nothing is removed.
    assert other_tokens(ETH, rows) == rows


@respx.mock
async def test_blocklist_read_sends_is_blacklisted_call(services):
    calls = []

    def eth_call(params):
        calls.append(params[0])
        return BLOCKED if params[0]["to"] == USDC else NOT_BLOCKED

    mock_rpc(ARC, {"eth_call": eth_call})

    assert await blocklisted_by(services, ARC, FRIEND) == ["USDC"]
    assert {c["to"] for c in calls} == {USDC, EURC}
    assert all(c["data"] == "0xfe575a87" + "0" * 24 + FRIEND[2:] for c in calls)


@respx.mock
async def test_token_is_never_checked_against_its_own_blocklist(services):
    route = mock_rpc(ARC, {"eth_call": NOT_BLOCKED})

    assert await blocklisted_by(services, ARC, USDC) == []
    assert route.call_count == 1  # Only EURC's list was read.
    assert await blocklisted_by(services, ETH, FRIEND) == []  # No lists off Arc.


@respx.mock
async def test_native_transfers_ask_etherscan_for_the_system_stream(services):
    seen = []
    mock_etherscan({"tokentx": lambda params: seen.append(params) or []})

    assert await services.etherscan.native_transfers(ARC, ME, sort="asc", limit=20) == []
    assert seen[0]["contractaddress"] == ARC_SYSTEM_EMITTER
    assert seen[0]["chainid"] == "5042"
    assert (seen[0]["sort"], seen[0]["offset"]) == ("asc", "20")
    # Other chains have no such stream, so no request is made.
    assert await services.etherscan.native_transfers(ETH, ME) == []
    assert len(seen) == 1


def _usdc_transfer_rows(frm, to, raw_6dp):
    """How Etherscan lists one ERC-20 USDC transfer on Arc: twice."""
    common = {"from": frm, "to": to, "hash": "0xabc", "timeStamp": "1791017169"}
    native = {
        **common,
        "contractAddress": ARC_SYSTEM_EMITTER,
        "value": str(raw_6dp * 10**12),
        "tokenDecimal": "0",
        "tokenSymbol": "",
    }
    erc20 = {
        **common,
        "contractAddress": USDC,
        "value": str(raw_6dp),
        "tokenDecimal": "6",
        "tokenSymbol": "USDC",
    }
    return native, erc20


@respx.mock
async def test_one_usdc_transfer_counts_once_with_18_decimals(services):
    native, erc20 = _usdc_transfer_rows(ME, FRIEND, 487_958_054)  # 487.958054 USDC
    eurc = {"from": SHOP, "to": ME, "contractAddress": EURC, "value": "1000000"}

    def tokentx(params):
        if params.get("contractaddress") == ARC_SYSTEM_EMITTER:
            return [native]
        return [native, erc20, eurc]

    # The transaction itself is a zero-value call to the USDC contract.
    call = {"from": ME, "to": USDC, "value": "0", "isError": "0", "input": "0x23b872dd"}
    mock_etherscan({"txlist": [call], "tokentx": tokentx})
    mock_goplus_address_by({})
    mock_rpc(ARC, {"eth_call": NOT_BLOCKED})

    trace = await trace_funds(services, ARC, ME, hops=1)

    edge = next(e for e in trace.edges if e.to_address == FRIEND)
    assert edge.transfers == 1
    assert edge.native_value == 487.958054
    assert edge.token_transfers == 0
    # EURC is a separate token and is still counted.
    assert next(e for e in trace.edges if e.from_address == SHOP).token_transfers == 1


@respx.mock
async def test_trace_flags_a_counterparty_blocked_by_usdc(services):
    native, _ = _usdc_transfer_rows(FRIEND, ME, 25_000_000)
    # The same row answers both the system-stream and the general token query.
    mock_etherscan({"txlist": [], "tokentx": [native]})
    mock_goplus_address_by({})
    mock_rpc(
        ARC,
        {
            "eth_call": lambda params: (
                BLOCKED
                if params[0]["to"] == USDC and params[0]["data"].endswith(FRIEND[2:])
                else NOT_BLOCKED
            )
        },
    )

    trace = await trace_funds(services, ARC, ME, hops=1)

    assert {n.address: n.blocklisted_by for n in trace.nodes}[FRIEND] == ["USDC"]
    link = trace.risky_links[0]
    assert link.address == FRIEND
    assert "blocked by the USDC contract" in link.reason
    finding = trace.findings[0]
    assert (finding.id, finding.severity) == ("trace.direct.blocklisted", "high")
    assert score_findings(trace.findings, trace.sources).score == 50


@respx.mock
async def test_unreadable_blocklist_lowers_confidence_not_score(services):
    mock_etherscan({})
    mock_goplus_address({})
    mock_rpc(
        ARC,
        {
            "eth_getBalance": "0x0",
            "eth_getTransactionCount": "0x0",
            "eth_getCode": "0x",
            "eth_call": RuntimeError("execution reverted"),
        },
    )

    profile = await get_wallet_profile(services, ARC, ME, now=RECORDED_AT)

    assert profile.blocklisted_by == []
    assert not [f for f in profile.findings if f.id.endswith("_blocklisted")]
    assert {s.source: s.ok for s in profile.sources}["Blocklist"] is False
    assert any("USDC and EURC blocklists could not be read" in g for g in profile.data_gaps)
    result = score_findings(profile.findings, profile.sources)
    assert result.confidence == "medium"


@respx.mock
async def test_other_chains_skip_arc_checks(services):
    seen = []
    mock_etherscan(
        {
            "txlist": lambda p: seen.append(p) or [],
            "tokentx": lambda p: seen.append(p) or [],
            "txlistinternal": lambda p: seen.append(p) or [],
        }
    )
    mock_goplus_address({})
    mock_rpc(ETH, {"eth_getBalance": "0x0", "eth_getTransactionCount": "0x0", "eth_getCode": "0x"})

    profile = await get_wallet_profile(services, ETH, ME, now=RECORDED_AT)

    assert "Blocklist" not in {s.source for s in profile.sources}
    assert not any("contractaddress" in p for p in seen)
    assert profile.notes == []


# --- Scoring ------------------------------------------------------------------


def _finding(fid, severity="critical"):
    return Finding(id=fid, severity=severity, title=fid, detail=fid, source="test")


OK = [SourceStatus(source="RPC", ok=True)]


def test_usdc_and_eurc_blocks_count_once_and_are_decisive():
    result = score_findings(
        [_finding("address.usdc_blocklisted"), _finding("address.eurc_blocklisted")], OK
    )
    assert result.score == 80
    assert [c.counted for c in result.contributions] == [True, False]

    with_trust = score_findings(
        [_finding("address.usdc_blocklisted"), _finding("token.trusted", "info")], OK
    )
    assert with_trust.score == DECISIVE_FLOOR
    assert with_trust.decisive_floor_applied is True


def test_rules_version_changes_with_the_rule_table():
    """If this fails, you changed a rule. Raise RULES_VERSION in scoring.py by one
    and put the new fingerprint below, so saved scores say which rules made them."""
    table = {
        "rules": {fid: [r.points, r.group, r.decisive] for fid, r in RULES.items()},
        "owner_power": [OWNER_POWER_CAP, sorted(OWNER_POWER_GROUPS)],
        "floor": DECISIVE_FLOOR,
        "levels": [[low, level] for low, level, _ in LEVELS],
        "severity_points": SEVERITY_POINTS,
        "function_groups": FUNCTION_GROUPS,
    }
    fingerprint = hashlib.sha256(json.dumps(table, sort_keys=True).encode()).hexdigest()[:16]
    assert {RULES_VERSION: fingerprint} == {3: "6e3c69407a928f0e"}


def test_official_arc_contract_gets_a_trust_signal():
    cctp = labels.lookup("arc", "0x28b5a0e9c621a5badaa536219b3a228c8168cf5d")
    assert cctp.official is True
    findings = address_findings("0x28b5a0e9c621a5badaa536219b3a228c8168cf5d", None, cctp)
    assert [f.id for f in findings] == ["address.official_contract"]
    assert "Circle CCTP: TokenMessengerV2" in findings[0].title
    assert RULES["address.official_contract"].points < 0
    # Labels from other sources (like an exchange wallet) are not "official".
    assert labels.lookup("ethereum", "0x28c6c06298d514db089934071355e5743bf21d60").official is False


@respx.mock
async def test_payment_simulation_uses_a_made_up_funded_sender(services):
    seen = []

    def eth_call(params):
        seen.append(params)
        return "0x"

    mock_rpc(ARC, {"eth_call": eth_call})

    assert await services.rpc.simulate_transfer(ARC, FRIEND, 10**18) is None
    call, block, override = seen[0]
    assert call == {"from": SIMULATION_SENDER, "to": FRIEND, "value": hex(10**18)}
    assert block == "latest"
    assert int(override[SIMULATION_SENDER]["balance"], 16) >= 10**18


@respx.mock
async def test_payment_refusal_is_an_answer_but_a_node_outage_is_a_failure(services):
    answers = iter([RuntimeError("Zero address not allowed"), RuntimeError("upstream timeout")])
    mock_rpc(ARC, {"eth_call": lambda _params: next(answers)})

    assert await services.rpc.simulate_transfer(ARC, ZERO, 1) == "Zero address not allowed"
    with pytest.raises(SourceError, match="upstream timeout"):
        await services.rpc.simulate_transfer(ARC, FRIEND, 1)
