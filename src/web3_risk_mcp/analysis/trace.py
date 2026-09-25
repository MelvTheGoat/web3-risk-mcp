"""Fund tracing: follow money in and out of an address for one or two "hops".

A hop is one step in the money trail. Hop 1 is everyone who sent money
directly to the address or received money directly from it. Hop 2 is the
next step out from those addresses.

We only follow the busiest paths and we only look at recent history, so the
trace is a sample, not a full audit. Every node is checked against our local
list of known bad addresses, and the closest ones are also checked with GoPlus.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal

from web3_risk_mcp import labels
from web3_risk_mcp.analysis.address import GOPLUS_ADDRESS_FLAGS, goplus_flags
from web3_risk_mcp.analysis.common import Collector, wei_to_coin
from web3_risk_mcp.chains import Chain
from web3_risk_mcp.models import Finding, FlowEdge, FundTrace, RiskyLink, Severity, TraceNode
from web3_risk_mcp.services import Services

Direction = Literal["in", "out", "both"]

ROOT_HISTORY_LIMIT = 100
HOP2_HISTORY_LIMIT = 50
HOP2_FANOUT = 3
GOPLUS_SCREEN_LIMIT = 6

# Following money through these tells us nothing: they touch everyone.
_DO_NOT_EXPAND = frozenset({"exchange", "protocol", "burn"})

_CATEGORY_SEVERITY: dict[str, tuple[Severity, Severity]] = {
    # category: (severity at hop 1, severity at hop 2)
    "sanctioned": ("critical", "high"),
    "exploit": ("critical", "medium"),
    "scam": ("high", "medium"),
    "mixer": ("high", "medium"),
}


@dataclass
class _Flow:
    """Totals for money moving between the address and one counterparty."""

    in_transfers: int = 0
    out_transfers: int = 0
    in_value: float = 0.0
    out_value: float = 0.0
    token_in: int = 0
    token_out: int = 0
    interactions: int = 0

    def weight(self, direction: Direction) -> tuple[int, float]:
        if direction == "in":
            return (self.in_transfers + self.token_in, self.in_value)
        if direction == "out":
            return (self.out_transfers + self.token_out, self.out_value)
        return (
            self.in_transfers + self.out_transfers + self.token_in + self.token_out,
            self.in_value + self.out_value,
        )


@dataclass
class _Graph:
    nodes: dict[str, TraceNode] = field(default_factory=dict)
    parents: dict[str, str] = field(default_factory=dict)
    edges: list[FlowEdge] = field(default_factory=list)


def flows(
    address: str, *tx_lists: list[dict[str, Any]], tokens: list[dict[str, Any]] = ()
) -> dict[str, _Flow]:
    """Add up value moving between `address` and each counterparty."""
    table: dict[str, _Flow] = defaultdict(_Flow)
    for txs in tx_lists:
        for tx in txs:
            if tx.get("isError") == "1":
                continue
            sender = (tx.get("from") or "").lower()
            receiver = (tx.get("to") or "").lower()
            value = wei_to_coin(tx.get("value"))
            if sender == address and receiver and receiver != address:
                flow = table[receiver]
                if value > 0:
                    flow.out_transfers += 1
                    flow.out_value += value
                else:
                    flow.interactions += 1
            elif receiver == address and sender and sender != address:
                flow = table[sender]
                if value > 0:
                    flow.in_transfers += 1
                    flow.in_value += value
                else:
                    flow.interactions += 1
    for tx in tokens:
        sender = (tx.get("from") or "").lower()
        receiver = (tx.get("to") or "").lower()
        if sender == address and receiver and receiver != address:
            table[receiver].token_out += 1
        elif receiver == address and sender and sender != address:
            table[sender].token_in += 1
    return table


def _pick(table: dict[str, _Flow], direction: Direction, limit: int) -> list[str]:
    """Choose the busiest counterparties in the chosen direction."""
    relevant = {a: f for a, f in table.items() if f.weight(direction)[0] > 0}
    ranked = sorted(relevant, key=lambda a: relevant[a].weight(direction), reverse=True)
    return ranked[:limit]


async def trace_funds(
    services: Services,
    chain: Chain,
    address: str,
    *,
    hops: int = 1,
    direction: Direction = "both",
    max_per_hop: int = 5,
) -> FundTrace:
    hops = max(1, min(2, hops))
    max_per_hop = max(1, min(10, max_per_hop))
    c = Collector()
    es = services.etherscan
    trace = FundTrace(
        chain=chain.key,
        address=address,
        native_symbol=chain.native_symbol,
        hops=hops,
        direction=direction,
    )
    graph = _Graph()
    graph.nodes[address] = TraceNode(address=address, hop=0, expanded=True)

    txs, internal, tokens = await asyncio.gather(
        c.run("Etherscan", es.transactions(chain, address, limit=ROOT_HISTORY_LIMIT)),
        c.run("Etherscan", es.internal_transactions(chain, address, limit=ROOT_HISTORY_LIMIT)),
        c.run("Etherscan", es.token_transfers(chain, address, limit=ROOT_HISTORY_LIMIT)),
    )
    if c.failed("Etherscan"):
        trace.data_gaps.append(
            f"Transaction history could not be loaded, so funds were not traced. "
            f"Reason: {c.error('Etherscan')}"
        )
        trace.sources = c.statuses
        return trace

    root_flows = flows(address, txs or [], internal or [], tokens=tokens or [])
    hop1 = _pick(root_flows, direction, max_per_hop)
    hop1 += [
        a for a in root_flows if a not in hop1 and labels.is_risky(labels.lookup(chain.key, a))
    ]
    for other in hop1:
        _add_node(graph, chain, other, hop=1, parent=address)
        _add_edges(graph, address, other, root_flows[other], hop=1)

    if hops == 2:
        expandable = [
            a for a in hop1 if (graph.nodes[a].label_category or "") not in _DO_NOT_EXPAND
        ][:max_per_hop]
        for a in hop1:
            if a not in expandable:
                graph.nodes[a].note = "Not followed further (exchange, protocol, burn, or limit)."
        histories = await asyncio.gather(
            *(
                c.run("Etherscan", es.transactions(chain, a, limit=HOP2_HISTORY_LIMIT))
                for a in expandable
            )
        )
        for parent, history in zip(expandable, histories, strict=True):
            if history is None:
                graph.nodes[parent].note = "History could not be loaded."
                continue
            graph.nodes[parent].expanded = True
            table = flows(parent, history)
            table.pop(address, None)
            picks = _pick(table, direction, HOP2_FANOUT)
            picks += [
                a for a in table if a not in picks and labels.is_risky(labels.lookup(chain.key, a))
            ]
            for other in picks:
                if other not in graph.nodes:
                    _add_node(graph, chain, other, hop=2, parent=parent)
                _add_edges(graph, parent, other, table[other], hop=2)

    # GoPlus screening for the closest nodes. We cap it to respect rate limits.
    to_screen = [n.address for n in graph.nodes.values() if n.hop == 1][:GOPLUS_SCREEN_LIMIT]
    results = await asyncio.gather(
        *(c.run("GoPlus", services.goplus.address_security(chain, a)) for a in to_screen)
    )
    for a, result in zip(to_screen, results, strict=True):
        graph.nodes[a].security_flags = goplus_flags(result)
    unscreened = [n for n in graph.nodes.values() if n.hop >= 1 and n.address not in to_screen]
    if unscreened:
        trace.data_gaps.append(
            f"{len(unscreened)} address(es) were only checked against the local list, "
            "not GoPlus, to stay within rate limits."
        )
    if c.failed("GoPlus"):
        trace.data_gaps.append(f"GoPlus screening failed. Reason: {c.error('GoPlus')}")

    trace.nodes = sorted(graph.nodes.values(), key=lambda n: (n.hop, n.address))
    trace.edges = graph.edges
    trace.risky_links = _risky_links(graph, address)
    trace.findings = _findings(trace.risky_links, graph)
    trace.data_gaps.append(
        f"Based on the latest {ROOT_HISTORY_LIMIT} transactions of each kind for the start "
        f"address and {HOP2_HISTORY_LIMIT} for hop-2 addresses. Older activity is not included."
    )
    trace.sources = c.statuses
    return trace


def _add_node(graph: _Graph, chain: Chain, address: str, *, hop: int, parent: str) -> None:
    label = labels.lookup(chain.key, address)
    graph.nodes[address] = TraceNode(
        address=address,
        hop=hop,
        label=label.name if label else None,
        label_category=label.category if label else None,
    )
    graph.parents[address] = parent


def _add_edges(graph: _Graph, a: str, b: str, flow: _Flow, *, hop: int) -> None:
    if flow.out_transfers or flow.token_out:
        graph.edges.append(
            FlowEdge(
                from_address=a,
                to_address=b,
                transfers=flow.out_transfers,
                native_value=round(flow.out_value, 6),
                token_transfers=flow.token_out,
                hop=hop,
            )
        )
    if flow.in_transfers or flow.token_in:
        graph.edges.append(
            FlowEdge(
                from_address=b,
                to_address=a,
                transfers=flow.in_transfers,
                native_value=round(flow.in_value, 6),
                token_transfers=flow.token_in,
                hop=hop,
            )
        )


def _path(graph: _Graph, address: str) -> list[str]:
    path = [address]
    while path[-1] in graph.parents:
        path.append(graph.parents[path[-1]])
    return list(reversed(path))


def _relation(graph: _Graph, node: TraceNode) -> str:
    parent = graph.parents.get(node.address)
    sent = any(e.from_address == node.address and e.to_address == parent for e in graph.edges)
    received = any(e.to_address == node.address and e.from_address == parent for e in graph.edges)
    who = "the address" if node.hop == 1 else "a hop-1 address"
    if sent and received:
        return f"sent funds to and received funds from {who}"
    if sent:
        return f"sent funds to {who}"
    return f"received funds from {who}"


def _risky_links(graph: _Graph, root: str) -> list[RiskyLink]:
    links = []
    for node in graph.nodes.values():
        if node.address == root:
            continue
        reasons = []
        if node.label_category in _CATEGORY_SEVERITY:
            reasons.append(f"{node.label} ({node.label_category})")
        reasons += [f"GoPlus: {GOPLUS_ADDRESS_FLAGS[f][1]}" for f in node.security_flags]
        if reasons:
            links.append(
                RiskyLink(
                    address=node.address,
                    hop=node.hop,
                    relation=_relation(graph, node),
                    reason="; ".join(reasons),
                    path=_path(graph, node.address),
                )
            )
    links.sort(key=lambda link: link.hop)
    return links


def _findings(links: list[RiskyLink], graph: _Graph) -> list[Finding]:
    """One finding per (hop, category), keeping the most serious example."""
    best: dict[str, Finding] = {}
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for link in links:
        node = graph.nodes[link.address]
        kinds: list[tuple[str, Severity]] = []
        if node.label_category in _CATEGORY_SEVERITY:
            sev1, sev2 = _CATEGORY_SEVERITY[node.label_category]
            kinds.append((node.label_category, sev1 if node.hop == 1 else sev2))
        for flag_name in node.security_flags:
            sev, _ = GOPLUS_ADDRESS_FLAGS[flag_name]
            if node.hop == 2:
                sev = {"critical": "high", "high": "medium"}.get(sev, "low")
            kinds.append(("flagged", sev))
        for kind, severity in kinds:
            level = "direct" if node.hop == 1 else "indirect"
            fid = f"trace.{level}.{kind}"
            where = "directly" if node.hop == 1 else "two steps away"
            finding = Finding(
                id=fid,
                severity=severity,
                title=f"{'Direct' if node.hop == 1 else 'Indirect'} link to a risky address",
                detail=f"Linked {where} to {link.address}: {link.reason}. "
                f"It {link.relation}. Path: {' -> '.join(link.path)}.",
                source="Etherscan + " + ("GoPlus" if kind == "flagged" else "local list"),
            )
            current = best.get(fid)
            if current is None or order[severity] > order[current.severity]:
                best[fid] = finding
    return sorted(best.values(), key=lambda f: -order[f.severity])
