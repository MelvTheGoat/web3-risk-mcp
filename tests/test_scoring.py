import re
from pathlib import Path

import pytest

from web3_risk_mcp.analysis.address import GOPLUS_ADDRESS_FLAGS
from web3_risk_mcp.analysis.trace import _CATEGORY_SEVERITY
from web3_risk_mcp.method import scoring_method_markdown
from web3_risk_mcp.models import Finding, SourceStatus
from web3_risk_mcp.scoring import RULES, score_findings

OK = [SourceStatus(source="GoPlus", ok=True)]


def f(fid, severity="high"):
    return Finding(id=fid, severity=severity, title=fid, detail=f"detail {fid}", source="test")


def test_no_findings_is_zero_and_low():
    result = score_findings([], OK)
    assert result.score == 0
    assert result.level == "low"
    assert result.confidence == "high"


def test_every_point_has_a_reason():
    result = score_findings([f("token.mintable", "medium"), f("token.blacklist", "medium")], OK)
    assert result.score == 25
    assert {c.finding_id: c.points for c in result.contributions} == {
        "token.mintable": 15,
        "token.blacklist": 10,
    }
    assert all(c.reason and c.rule for c in result.contributions)


def test_same_issue_from_two_sources_counts_once():
    result = score_findings([f("token.not_open_source"), f("contract.unverified")], OK)
    assert result.score == 25
    skipped = [c for c in result.contributions if not c.counted]
    assert len(skipped) == 1
    assert "not counted twice" in skipped[0].rule


def test_risky_function_shares_group_with_token_flag():
    result = score_findings([f("token.mintable", "medium"), f("contract.fn.mint", "high")], OK)
    assert result.score == 15


def test_trust_signals_lower_the_score():
    result = score_findings([f("token.proxy", "medium"), f("token.trusted", "info")], OK)
    assert result.score == 0
    assert result.points_added == 10
    assert result.points_removed == 40


def test_decisive_finding_sets_a_floor():
    result = score_findings([f("token.honeypot", "critical"), f("token.trusted", "info")], OK)
    assert result.score == 75
    assert result.decisive_floor_applied
    assert result.level == "critical"


def test_score_is_capped_at_100():
    findings = [f("address.sanctioned", "critical"), f("token.honeypot", "critical")]
    assert score_findings(findings, OK).score == 100


def test_unknown_finding_uses_severity_points():
    result = score_findings([f("token.something_new", "medium")], OK)
    assert result.score == 8
    assert "no specific rule" in result.contributions[0].rule


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([True, True], "high"),
        ([True, False], "medium"),
        ([False, False, True], "low"),
        ([], "low"),
    ],
)
def test_confidence_depends_on_sources(statuses, expected):
    sources = [SourceStatus(source=str(i), ok=ok) for i, ok in enumerate(statuses)]
    result = score_findings([], sources)
    assert result.confidence == expected
    if expected != "high":
        assert "may be higher" in result.verdict


def test_every_finding_id_in_the_code_has_a_rule():
    source_dir = Path(__file__).parent.parent / "src" / "web3_risk_mcp" / "analysis"
    literal_ids = set()
    for path in source_dir.glob("*.py"):
        literal_ids |= set(
            re.findall(r'"((?:token|contract|wallet|address|trace)\.[a-z_]+)"', path.read_text())
        )
    dynamic_ids = {f"address.{name}" for name in GOPLUS_ADDRESS_FLAGS}
    dynamic_ids |= {"address.known_" + c for c in ("sanctioned", "exploit", "scam", "mixer")}
    for level in ("direct", "indirect"):
        dynamic_ids |= {f"trace.{level}.{c}" for c in [*_CATEGORY_SEVERITY, "flagged"]}
    missing = sorted((literal_ids | dynamic_ids) - set(RULES))
    assert missing == []
    assert len(literal_ids) > 30


def test_method_doc_is_up_to_date():
    doc = Path(__file__).parent.parent / "docs" / "risk-method.md"
    assert doc.read_text() == scoring_method_markdown(), (
        "Run: uv run python scripts/render_method_doc.py"
    )
