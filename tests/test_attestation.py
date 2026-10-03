"""Tests for the data the web app saves in the RiskAttestation contract.

The log in tests/fixtures/attested_log.json was emitted by the real contract
(contracts/src/RiskAttestation.sol) on a local Arc chain (arc-anvil --network
arc), so the parser is checked against real output, not a hand-made guess.
"""

import json
from pathlib import Path

import pytest
import respx

from tests.mocks import mock_etherscan
from web3_risk_mcp import attestation
from web3_risk_mcp.analysis.score import RiskScore
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.scoring import ScoreContribution
from web3_risk_mcp.web.settings import WebSettings

ARC = get_chain("arc")
SUBJECT = "0x7f367cc41522ce07553e823bf3be79a889debe1b"
LOG = json.loads((Path(__file__).parent / "fixtures" / "attested_log.json").read_text())

# The same value is pinned in contracts/test/RiskAttestation.t.sol.
EXPECTED_CALLDATA = (
    "0xde93cefc"
    "0000000000000000000000007f367cc41522ce07553e823bf3be79a889debe1b"
    "0000000000000000000000000000000000000000000000000000000000000064"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "1111111111111111111111111111111111111111111111111111111111111111"
)


def _result(**overrides) -> RiskScore:
    def c(fid, points):
        return ScoreContribution(
            finding_id=fid,
            title=fid,
            severity="high",
            points=points,
            counted=True,
            reason="",
            source="test",
            rule="rule",
        )

    base = {
        "score": 100,
        "level": "critical",
        "verdict": "Very likely dangerous.",
        "confidence": "high",
        "contributions": [c("wallet.no_history", 5), c("address.sanctioned", 90)],
        "points_added": 95,
        "points_removed": 0,
        "decisive_floor_applied": False,
        "chain": "arc",
        "address": SUBJECT,
        "address_type": "wallet",
        "checks_run": [],
        "rules_version": 3,
    }
    return RiskScore(**{**base, **overrides})


def test_function_and_event_ids_match_the_contract():
    assert attestation.ATTEST_SELECTOR == "0xde93cefc"
    assert LOG["topics"][0] == attestation.ATTESTED_TOPIC


def test_calldata_matches_the_solidity_test():
    assert attestation.attest_calldata(SUBJECT, 100, 3, "0x" + "11" * 32) == EXPECTED_CALLDATA


@pytest.mark.parametrize(
    ("score", "version", "digest"),
    [(101, 3, "0x" + "11" * 32), (50, 0, "0x" + "11" * 32), (50, 3, "0x1234")],
)
def test_calldata_rejects_values_the_contract_would_refuse(score, version, digest):
    with pytest.raises(ValueError):
        attestation.attest_calldata(SUBJECT, score, version, digest)


def test_findings_hash_is_keccak_of_a_fixed_text_anyone_can_rebuild():
    data = attestation.build(_result())
    assert data.canonical == (
        '{"address":"0x7f367cc41522ce07553e823bf3be79a889debe1b","chain":"arc",'
        '"findings":[["address.sanctioned",90],["wallet.no_history",5]],'
        '"rules_version":3,"score":100}'
    )
    assert data.findings_hash == "0x" + attestation.keccak256(data.canonical.encode()).hex()
    assert data.calldata == attestation.attest_calldata(SUBJECT, 100, 3, data.findings_hash)
    # Same findings in another order give the same hash.
    flipped = _result(contributions=list(reversed(_result().contributions)))
    assert attestation.build(flipped).findings_hash == data.findings_hash


def test_parses_an_event_emitted_by_the_real_contract():
    saved = attestation.parse_attested_log(LOG)
    assert saved.attester == "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
    assert (saved.score, saved.rules_version) == (100, 3)
    assert saved.findings_hash == "0x" + "11" * 32
    assert saved.timestamp == int("6ac0d44d", 16)
    assert saved.tx_hash == LOG["transactionHash"]


@respx.mock
async def test_saved_checks_asks_for_this_address_and_lists_newest_first(services):
    contract = "0x" + "aa" * 20
    older = {**LOG, "data": LOG["data"][:-8] + "00000001", "transactionHash": "0xold"}
    seen = []
    mock_etherscan({"getLogs": lambda params: seen.append(params) or [older, LOG]})

    checks = await attestation.saved_checks(services, ARC, contract, SUBJECT)

    assert [c.tx_hash for c in checks] == [LOG["transactionHash"], "0xold"]
    params = seen[0]
    assert params["address"] == contract
    assert params["topic0"] == attestation.ATTESTED_TOPIC
    assert params["topic2"] == "0x" + SUBJECT[2:].rjust(64, "0")
    assert params["topic0_2_opr"] == "and"


def test_attestation_contract_setting_must_be_an_address():
    assert WebSettings(_env_file=None, attestation_contract="").attestation_contract == ""
    upper = "0x" + "AB" * 20
    assert WebSettings(_env_file=None, attestation_contract=upper).attestation_contract == (
        upper.lower()
    )
    with pytest.raises(ValueError):
        WebSettings(_env_file=None, attestation_contract="not-an-address")
