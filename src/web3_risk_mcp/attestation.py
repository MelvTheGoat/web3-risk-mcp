"""Turn a risk result into data the RiskAttestation contract on Arc can store.

The contract (contracts/src/RiskAttestation.sol) keeps, for each saved check:
the address, the score, the rule table version, a hash of the findings, and
the time. This module builds those values, and the transaction data a user's
own wallet signs to save them. The server never signs anything.

The findings hash is keccak256 of a short, fixed JSON text (see
`canonical_findings`), so anyone can rebuild the text from a result and check
the hash themselves.
"""

from __future__ import annotations

import json

from Crypto.Hash import keccak
from pydantic import BaseModel, Field

from web3_risk_mcp.analysis.score import RiskScore
from web3_risk_mcp.chains import Chain

ATTEST_SIGNATURE = "attest(address,uint8,uint16,bytes32)"
ATTESTED_EVENT = "Attested(address,address,uint8,uint16,bytes32,uint64)"


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def selector(signature: str) -> str:
    """The 4-byte function ID that starts a contract call."""
    return "0x" + keccak256(signature.encode()).hex()[:8]


ATTEST_SELECTOR = selector(ATTEST_SIGNATURE)
ATTESTED_TOPIC = "0x" + keccak256(ATTESTED_EVENT.encode()).hex()


class AttestationData(BaseModel):
    canonical: str = Field(description="The exact text that was hashed.")
    findings_hash: str = Field(description="keccak256 of `canonical`, as 0x + 64 hex.")
    calldata: str = Field(description="Data for attest(...), to be signed by the user's wallet.")


def canonical_findings(result: RiskScore) -> str:
    """A fixed JSON text: sorted keys, no spaces, findings sorted by ID."""
    payload = {
        "address": result.address,
        "chain": result.chain,
        "findings": sorted([c.finding_id, c.points] for c in result.contributions),
        "rules_version": result.rules_version,
        "score": result.score,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _word(value: int) -> str:
    return f"{value:064x}"


def attest_calldata(subject: str, score: int, rules_version: int, findings_hash: str) -> str:
    """ABI-encode a call to attest(subject, score, rulesVersion, findingsHash)."""
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    if not 0 < rules_version < 2**16:
        raise ValueError("rules_version must fit in uint16 and not be 0")
    digest = findings_hash.lower().removeprefix("0x")
    if len(digest) != 64:
        raise ValueError("findings_hash must be 32 bytes")
    address = subject.lower().removeprefix("0x")
    return ATTEST_SELECTOR + address.rjust(64, "0") + _word(score) + _word(rules_version) + digest


def build(result: RiskScore) -> AttestationData:
    canonical = canonical_findings(result)
    digest = "0x" + keccak256(canonical.encode()).hex()
    return AttestationData(
        canonical=canonical,
        findings_hash=digest,
        calldata=attest_calldata(result.address, result.score, result.rules_version, digest),
    )


class SavedCheck(BaseModel):
    """A check someone saved in the RiskAttestation contract."""

    attester: str
    score: int
    rules_version: int
    findings_hash: str
    timestamp: int = Field(description="Unix time when it was saved.")
    tx_hash: str


def parse_attested_log(log: dict) -> SavedCheck:
    """Read one Attested event, as Etherscan's getLogs returns it."""
    topics = log["topics"]
    data = log["data"].removeprefix("0x")
    words = [data[i : i + 64] for i in range(0, len(data), 64)]
    return SavedCheck(
        attester="0x" + topics[1][-40:].lower(),
        score=int(words[0], 16),
        rules_version=int(words[1], 16),
        findings_hash="0x" + words[2].lower(),
        timestamp=int(words[3], 16),
        tx_hash=log["transactionHash"],
    )


async def saved_checks(
    services, chain: Chain, contract: str, subject: str, *, limit: int = 5
) -> list[SavedCheck]:
    """The latest checks saved about `subject` in the contract, newest first."""
    topic = "0x" + subject.lower().removeprefix("0x").rjust(64, "0")
    rows = await services.etherscan.logs(chain, contract, topic0=ATTESTED_TOPIC, topic2=topic)
    checks = [parse_attested_log(row) for row in rows]
    return sorted(checks, key=lambda c: c.timestamp, reverse=True)[:limit]
