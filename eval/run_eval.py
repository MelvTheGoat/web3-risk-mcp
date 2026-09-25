"""Run the risk scorer on the labelled dataset and report how well it separates
risky addresses from safe ones.

Usage:
    uv run python eval/run_eval.py                 # live APIs (needs .env keys)
    uv run python eval/run_eval.py --record        # live, and save responses
    uv run python eval/run_eval.py --replay        # offline, from saved responses

Results are written to eval/results.md and eval/results.json.

The run is done twice: once as normal, and once with the local list of known
bad addresses switched off. Some risky items in the dataset are on that list,
so the second run shows what the other signals catch on their own.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import httpx

from web3_risk_mcp import __version__, labels
from web3_risk_mcp.analysis.score import score_risk
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.config import get_settings
from web3_risk_mcp.evaluation import (
    Cassette,
    RecordingTransport,
    ReplayTransport,
    compute_metrics,
)
from web3_risk_mcp.services import Services

HERE = Path(__file__).resolve().parent
DATASET = HERE / "dataset.json"
CASSETTE = HERE / "fixtures" / "cassette.json.gz"
THRESHOLD = 50


def _without_local_list():
    """Hide every local label except burn addresses (which are not a risk signal)."""
    original = labels.lookup

    def lookup(chain_key: str, address: str):
        label = original(chain_key, address)
        return label if label and label.category == "burn" else None

    return mock.patch.object(labels, "lookup", side_effect=lookup)


async def _score_all(services: Services, items: list[dict]) -> list[dict]:
    rows = []
    for i, item in enumerate(items, 1):
        chain = get_chain(item["chain"])
        started = time.monotonic()
        result = await score_risk(services, chain, item["address"].lower())
        rows.append(
            {
                **item,
                "score": result.score,
                "level": result.level,
                "confidence": result.confidence,
                "address_type": result.address_type,
                "top_reasons": [
                    f"{c.finding_id} ({c.points:+d})"
                    for c in result.contributions
                    if c.counted and c.points
                ][:4],
                "failed_sources": [s.source for s in result.sources if not s.ok],
                "seconds": round(time.monotonic() - started, 1),
            }
        )
        print(
            f"[{i}/{len(items)}] {item['label']:5} {result.score:3d} {result.level:8} "
            f"{item['name']}",
            file=sys.stderr,
        )
    return rows


def _metrics(rows: list[dict]) -> dict:
    risky = [r["score"] for r in rows if r["label"] == "risky"]
    safe = [r["score"] for r in rows if r["label"] == "safe"]
    return asdict(compute_metrics(risky, safe, THRESHOLD))


def _markdown(runs: dict[str, dict], mode: str) -> str:
    main, ablation = runs["with_local_list"], runs["without_local_list"]
    m, a = main["metrics"], ablation["metrics"]
    lines = [
        "# Evaluation results",
        "",
        f"Generated {datetime.now(UTC):%Y-%m-%d} with web3-risk-mcp {__version__} "
        f"({mode} data). An address is flagged as risky when its score is {THRESHOLD} or more.",
        "",
        "| Metric | Full scorer | Without local address list |",
        "|---|---:|---:|",
        f"| ROC AUC (1.0 = perfect separation) | {m['roc_auc']} | {a['roc_auc']} |",
        f"| Accuracy | {m['accuracy']} | {a['accuracy']} |",
        f"| Precision (flagged items that are risky) | {m['precision']} | {a['precision']} |",
        f"| Recall (risky items that got flagged) | {m['recall']} | {a['recall']} |",
        f"| False alarms on safe items | {m['false_positives']} of {m['safe_count']} "
        f"| {a['false_positives']} of {a['safe_count']} |",
        f"| Missed risky items | {m['false_negatives']} of {m['risky_count']} "
        f"| {a['false_negatives']} of {a['risky_count']} |",
        f"| Mean score, risky / safe | {m['risky_mean']} / {m['safe_mean']} "
        f"| {a['risky_mean']} / {a['safe_mean']} |",
        "",
        "## Every item (full scorer)",
        "",
        "| Label | Name | Chain | Score | Level | Confidence | Main reasons |",
        "|---|---|---|---:|---|---|---|",
    ]
    for r in sorted(main["rows"], key=lambda r: (r["label"], -r["score"])):
        reasons = ", ".join(r["top_reasons"]) or "none"
        lines.append(
            f"| {r['label']} | {r['name']} | {r['chain']} | {r['score']} | {r['level']} "
            f"| {r['confidence']} | {reasons} |"
        )
    return "\n".join(lines) + "\n"


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--record", action="store_true", help="Save API responses to a cassette.")
    group.add_argument("--replay", action="store_true", help="Use saved responses only.")
    parser.add_argument("--limit", type=int, default=0, help="Only run the first N items.")
    args = parser.parse_args()

    items = json.loads(DATASET.read_text())["items"]
    if args.limit:
        items = items[: args.limit]

    settings = get_settings()
    cassette = Cassette(CASSETTE) if (args.record or args.replay) else None
    transport = None
    if args.record:
        transport = RecordingTransport(cassette)
    elif args.replay:
        transport = ReplayTransport(cassette)
        settings = settings.model_copy(update={"http_max_retries": 0})
    mode = "replayed" if args.replay else "live"

    async with httpx.AsyncClient(
        transport=transport, timeout=settings.http_timeout_seconds
    ) as client:
        services = Services(settings, client=client)
        if args.replay and not services.etherscan.api_key:
            services.etherscan.api_key = "replay"  # Keys are not stored in the cassette.
        runs = {}
        print("Run 1: full scorer", file=sys.stderr)
        rows = await _score_all(services, items)
        runs["with_local_list"] = {"rows": rows, "metrics": _metrics(rows)}
        print("Run 2: without the local address list", file=sys.stderr)
        with _without_local_list():
            rows = await _score_all(services, items)
        runs["without_local_list"] = {"rows": rows, "metrics": _metrics(rows)}

    if cassette is not None and args.record:
        cassette.save()
        print(f"Saved {len(cassette.entries)} responses to {CASSETTE}", file=sys.stderr)
    if isinstance(transport, ReplayTransport) and transport.misses:
        print(
            f"Warning: {len(transport.misses)} requests were not in the cassette.", file=sys.stderr
        )

    (HERE / "results.json").write_text(json.dumps(runs, indent=2) + "\n")
    (HERE / "results.md").write_text(_markdown(runs, mode))
    print(_markdown(runs, mode))


if __name__ == "__main__":
    asyncio.run(main())
