"""Builds the "risk scoring method" document from the live rule table.

The document is generated from the same code the scorer uses, so it can
never drift out of date.
"""

from __future__ import annotations

from web3_risk_mcp.scoring import DECISIVE_FLOOR, LEVELS, RULES, SEVERITY_POINTS

_INTRO = """\
# How the risk score works

The score runs from 0 (no red flags found) to 100 (almost certainly dangerous).
It is rule-based. There is no machine learning and no hidden weighting.
Every point in a score comes from one finding, and each finding has a plain
reason and a data source.

## Steps

1. **Collect findings.** The tools check the address with Etherscan, GoPlus,
   DexScreener, public RPC nodes, and a small local list of known bad addresses.
   Each thing they notice becomes a *finding* with a stable ID, such as
   `token.honeypot`.
2. **Give points.** The table below gives each finding ID a number of points.
   Trust signals give negative points.
3. **Do not count twice.** Findings that describe the same problem share a
   *group*. Only the biggest finding in a group counts. For example, "source
   not verified" from GoPlus and from Etherscan count once.
4. **Add up and clamp.** Points are added and kept between 0 and 100.
5. **Decisive floor.** Some findings are so serious that nothing should hide
   them, such as a honeypot token or a sanctioned address. If one is present,
   the score is at least {floor}, however many trust signals there are.

## Levels

| Score | Level | Meaning |
|---|---|---|
{levels}

## Confidence

The score also has a confidence: **high** if every data source answered,
**medium** if up to half failed, **low** if more than half failed. Missing
data never lowers the score. It lowers the confidence instead, and the
report says what could not be checked. **A low score with low confidence
does not mean "safe".**

## Rule table

| Finding ID | Points | Group | Decisive |
|---|---:|---|:---:|
{rules}

Findings without their own rule get points from their severity:
{severity}. Risky functions found in a contract (`contract.fn.*`) use these
severity points too. Their severity is lowered when the owner has renounced
control, because nobody can call owner-only functions any more.

## Limits of this method

- Points were chosen by hand from common scam patterns. They are a
  reasoned starting point, not a statistical model. The evaluation set in the
  repository measures how well they separate known scams from known safe
  addresses.
- The score only knows what its data sources know. A brand-new scam that no
  source has flagged yet can score low.
- Fund tracing looks at recent history only and follows the busiest paths.
"""


def scoring_method_markdown() -> str:
    levels = "\n".join(
        f"| {low} to {high} | {level} | {verdict} |"
        for (low, level, verdict), high in zip(
            LEVELS, [100] + [t - 1 for t, _, _ in LEVELS[:-1]], strict=True
        )
    )
    rules = "\n".join(
        f"| `{fid}` | {rule.points:+d} | {rule.group or ''} | {'yes' if rule.decisive else ''} |"
        for fid, rule in RULES.items()
    )
    severity = ", ".join(f"{sev} = {pts}" for sev, pts in SEVERITY_POINTS.items())
    return _INTRO.format(floor=DECISIVE_FLOOR, levels=levels, rules=rules, severity=severity)
