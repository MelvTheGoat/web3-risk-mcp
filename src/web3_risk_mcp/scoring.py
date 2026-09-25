"""The risk scorer: turns findings into a 0-100 score, with a reason for every point.

How it works, in four steps:

1. Every finding has a stable ID, such as `token.honeypot`.
2. A rule table below gives each ID a number of points. Trust signals, such
   as "on a trusted token list", give negative points.
3. Some findings describe the same problem seen by two sources (for example
   "source not verified" from both GoPlus and Etherscan). These share a
   group, and only the biggest one in a group counts. Nothing is counted twice.
4. The total is kept between 0 and 100. If a "decisive" finding is present,
   such as a honeypot or a sanctioned address, the score cannot be below 75,
   no matter how many trust signals there are.

There is no machine learning and no hidden weighting. Anyone can read the
table and recompute the score by hand.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from web3_risk_mcp.models import Finding, Severity, SourceStatus

Level = Literal["low", "medium", "high", "critical"]
DECISIVE_FLOOR = 75

LEVELS: list[tuple[int, Level, str]] = [
    (75, "critical", "Very likely dangerous. Do not interact."),
    (50, "high", "Serious red flags. Avoid unless you fully understand the risks."),
    (20, "medium", "Some warning signs. Look closely before interacting."),
    (0, "low", "No major red flags in the data we could check."),
]

# Points used when a finding has no specific rule (for example risky
# functions, whose severity already depends on whether the owner renounced).
SEVERITY_POINTS: dict[Severity, int] = {
    "critical": 40,
    "high": 15,
    "medium": 8,
    "low": 2,
    "info": 0,
}


@dataclass(frozen=True)
class Rule:
    points: int
    group: str | None = None
    decisive: bool = False


RULES: dict[str, Rule] = {
    # Address labels (GoPlus and the local list)
    "address.sanctioned": Rule(90, "sanctioned", decisive=True),
    "address.known_sanctioned": Rule(90, "sanctioned", decisive=True),
    "address.known_exploit": Rule(80, "known_bad", decisive=True),
    "address.known_scam": Rule(80, "known_bad", decisive=True),
    "address.stealing_attack": Rule(70, "known_bad", decisive=True),
    "address.phishing_activities": Rule(70, "known_bad", decisive=True),
    "address.cybercrime": Rule(50, "crime"),
    "address.money_laundering": Rule(50, "crime"),
    "address.financial_crime": Rule(50, "crime"),
    "address.blackmail_activities": Rule(50, "crime"),
    "address.darkweb_transactions": Rule(50, "crime"),
    "address.malicious_contracts_created": Rule(50),
    "address.honeypot_related_address": Rule(40),
    "address.fake_token": Rule(40),
    "address.known_mixer": Rule(40, "mixer"),
    "address.mixer": Rule(30, "mixer"),
    "address.malicious_mining_activities": Rule(25),
    "address.fake_standard_interface": Rule(25),
    "address.fake_kyc": Rule(20),
    "address.blacklist_doubt": Rule(20),
    "address.gas_abuse": Rule(20),
    "address.reinit": Rule(15),
    # Wallet behaviour
    "wallet.funded_by_risky": Rule(30),
    "wallet.risky_counterparty": Rule(25, "direct_link"),
    "wallet.very_new": Rule(10, "wallet_age"),
    "wallet.new": Rule(5, "wallet_age"),
    "wallet.no_history": Rule(5, "wallet_age"),
    "wallet.many_failed_txs": Rule(5),
    "wallet.established": Rule(-10),
    # Token
    "token.honeypot": Rule(60, "honeypot", decisive=True),
    "token.airdrop_scam": Rule(60, decisive=True),
    "token.fake_token": Rule(60, decisive=True),
    "token.owner_can_change_balance": Rule(50, "balance_control", decisive=True),
    "token.extreme_sell_tax": Rule(45, "sell_tax", decisive=True),
    "token.cannot_sell_all": Rule(35, "honeypot"),
    "token.no_sells": Rule(35, "honeypot"),
    "token.creator_made_honeypots": Rule(30),
    "token.per_wallet_tax": Rule(30, "fees"),
    "token.not_open_source": Rule(25, "unverified"),
    "token.hidden_owner": Rule(25),
    "token.can_take_back_ownership": Rule(25),
    "token.selfdestruct": Rule(20, "selfdestruct"),
    "token.no_liquidity": Rule(20, "liquidity"),
    "token.mintable": Rule(15, "mint"),
    "token.mintable_renounced": Rule(3, "mint"),
    "token.tax_modifiable": Rule(15, "fees"),
    "token.high_sell_tax": Rule(15, "sell_tax"),
    "token.extreme_concentration": Rule(15, "concentration"),
    "token.high_concentration": Rule(8, "concentration"),
    "token.high_buy_tax": Rule(10),
    "token.cannot_buy": Rule(10),
    "token.insider_holds_large_share": Rule(10),
    "token.low_liquidity": Rule(10, "liquidity"),
    "token.liquidity_not_locked": Rule(10),
    "token.very_new_pool": Rule(10, "age"),
    "token.new_pool": Rule(4, "age"),
    "token.proxy": Rule(10, "upgradeable"),
    "token.transfer_pausable": Rule(10, "pause"),
    "token.blacklist": Rule(10, "blacklist"),
    "token.whitelist": Rule(3),
    "token.trading_cooldown": Rule(3),
    "token.anti_whale_modifiable": Rule(3),
    "token.external_call": Rule(3),
    "token.goplus_note": Rule(0),
    "token.trusted": Rule(-40),
    # Contract
    "contract.unverified": Rule(25, "unverified"),
    "contract.verified": Rule(0),
    "contract.upgradeable_by_wallet": Rule(20, "upgradeable"),
    "contract.upgradeable": Rule(8, "upgradeable"),
    "contract.implementation_unverified": Rule(15),
    "contract.selfdestruct": Rule(20, "selfdestruct"),
    "contract.owner_is_single_wallet": Rule(8),
    "contract.very_new": Rule(10, "age"),
    "contract.ownership_renounced": Rule(-5),
    "contract.owner_is_multisig": Rule(-5),
    # Fund tracing
    "trace.direct.sanctioned": Rule(60, "direct_link"),
    "trace.direct.exploit": Rule(45, "direct_link"),
    "trace.direct.scam": Rule(40, "direct_link"),
    "trace.direct.mixer": Rule(30, "direct_link"),
    "trace.direct.flagged": Rule(30, "direct_link"),
    "trace.indirect.sanctioned": Rule(15, "indirect_link"),
    "trace.indirect.exploit": Rule(10, "indirect_link"),
    "trace.indirect.scam": Rule(10, "indirect_link"),
    "trace.indirect.mixer": Rule(8, "indirect_link"),
    "trace.indirect.flagged": Rule(8, "indirect_link"),
}

# Risky-function findings ("contract.fn.<category>") use SEVERITY_POINTS, and
# share a group with the matching token flag so they are not counted twice.
FUNCTION_GROUPS: dict[str, str] = {
    "balance_control": "balance_control",
    "mint": "mint",
    "blacklist": "blacklist",
    "fees": "fees",
    "pause": "pause",
    "upgrade": "upgradeable",
    "limits": "limits",
    "withdraw": "withdraw",
}


class ScoreContribution(BaseModel):
    finding_id: str
    title: str
    severity: Severity
    points: int = Field(description="Points this finding adds to the score (negative lowers it).")
    counted: bool = Field(
        description="False if a bigger finding in the same group already counted."
    )
    reason: str
    source: str
    rule: str = Field(description="Which rule decided the points.")


class ScoreResult(BaseModel):
    score: int
    level: Level
    verdict: str
    confidence: Literal["high", "medium", "low"]
    contributions: list[ScoreContribution]
    points_added: int
    points_removed: int
    decisive_floor_applied: bool


def rule_for(finding_id: str, severity: Severity) -> tuple[Rule, str]:
    """Find the rule for a finding. Returns the rule and a short description of it."""
    rule = RULES.get(finding_id)
    if rule is not None:
        return rule, f"rule {finding_id}"
    if finding_id.startswith("contract.fn."):
        category = finding_id.removeprefix("contract.fn.")
        points = SEVERITY_POINTS[severity]
        return Rule(points, FUNCTION_GROUPS.get(category)), f"risky function, {severity} severity"
    return Rule(SEVERITY_POINTS[severity]), f"no specific rule, {severity} severity"


def score_findings(findings: list[Finding], sources: list[SourceStatus]) -> ScoreResult:
    """Score a list of findings. Pure function: same input, same output."""
    # Unique by ID: the same finding from two reports only counts once.
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.id, finding)

    rated = []
    for finding in unique.values():
        rule, rule_text = rule_for(finding.id, finding.severity)
        rated.append((finding, rule, rule_text))
    # Biggest first, so the biggest in each group is the one that counts.
    rated.sort(key=lambda item: item[1].points, reverse=True)

    used_groups: dict[str, str] = {}
    contributions = []
    decisive = False
    for finding, rule, rule_text in rated:
        counted = True
        text = rule_text
        if rule.group and rule.points > 0:
            if rule.group in used_groups:
                counted = False
                text += f"; same issue as {used_groups[rule.group]}, not counted twice"
            else:
                used_groups[rule.group] = finding.id
        if counted and rule.decisive:
            decisive = True
            text += "; decisive"
        contributions.append(
            ScoreContribution(
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity,
                points=rule.points if counted else 0,
                counted=counted,
                reason=finding.detail,
                source=finding.source,
                rule=text,
            )
        )

    added = sum(c.points for c in contributions if c.points > 0)
    removed = -sum(c.points for c in contributions if c.points < 0)
    score = max(0, min(100, added - removed))
    floor_applied = decisive and score < DECISIVE_FLOOR
    if floor_applied:
        score = DECISIVE_FLOOR

    level, verdict = _level(score)
    confidence = _confidence(sources)
    if confidence != "high":
        verdict += " Some data could not be checked, so the real risk may be higher."
    contributions.sort(key=lambda c: (not c.counted, -abs(c.points), c.finding_id))
    return ScoreResult(
        score=score,
        level=level,
        verdict=verdict,
        confidence=confidence,
        contributions=contributions,
        points_added=added,
        points_removed=removed,
        decisive_floor_applied=floor_applied,
    )


def _level(score: int) -> tuple[Level, str]:
    for threshold, level, verdict in LEVELS:
        if score >= threshold:
            return level, verdict
    return "low", LEVELS[-1][2]


def _confidence(sources: list[SourceStatus]) -> Literal["high", "medium", "low"]:
    """How much of the data we wanted did we actually get?"""
    if not sources:
        return "low"
    failed = sum(1 for s in sources if not s.ok)
    if failed == 0:
        return "high"
    if failed / len(sources) <= 0.5:
        return "medium"
    return "low"
