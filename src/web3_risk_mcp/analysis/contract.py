"""Contract inspection: is the code public, can it be changed, who controls it,
and which functions could hurt users?"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from web3_risk_mcp.analysis.common import Collector, days_between, from_unix
from web3_risk_mcp.analysis.selectors import match_abi_name, scan_bytecode, selector
from web3_risk_mcp.chains import Chain
from web3_risk_mcp.clients.rpc import (
    EIP1967_ADMIN_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    slot_to_address,
)
from web3_risk_mcp.errors import SourceError
from web3_risk_mcp.models import (
    ContractReport,
    Controller,
    Finding,
    RiskyFunction,
    Severity,
)
from web3_risk_mcp.services import Services

DEAD_ZERO = "0x0000000000000000000000000000000000000000"
DEAD = {
    DEAD_ZERO,
    "0x000000000000000000000000000000000000dead",
}
OWNER_SELECTORS = (selector("owner()"), selector("getOwner()"))
THRESHOLD_SELECTOR = selector("getThreshold()")

_LOWER = {"critical": "medium", "high": "low", "medium": "low", "low": "info", "info": "info"}


async def inspect_contract(
    services: Services, chain: Chain, address: str, *, now: datetime | None = None
) -> ContractReport:
    now = now or datetime.now(UTC)
    c = Collector()
    rpc, es = services.rpc, services.etherscan
    report = ContractReport(chain=chain.key, address=address)

    code, source, creation, impl_slot, admin_slot = await asyncio.gather(
        c.run("RPC", rpc.code(chain, address)),
        c.run("Etherscan", es.source_code(chain, address)),
        c.run("Etherscan", es.contract_creation(chain, address)),
        c.run("RPC", rpc.storage(chain, address, EIP1967_IMPLEMENTATION_SLOT)),
        c.run("RPC", rpc.storage(chain, address, EIP1967_ADMIN_SLOT)),
    )

    if code is not None:
        report.is_contract = code != "0x"
        report.bytecode_size_bytes = max(0, (len(code) - 2) // 2)
        if not report.is_contract:
            report.summary = (
                "This address has no contract code. It is a normal wallet (or a contract that "
                "self-destructed). Use get_wallet_profile instead."
            )
            report.sources = c.statuses
            return report

    abi = _apply_source(report, source)
    if creation:
        report.creator = (creation.get("contractCreator") or "").lower() or None
        report.creation_tx = creation.get("txHash")
        report.created_at = from_unix(creation.get("timestamp"))

    # Proxy detection: Etherscan's flag, or the standard EIP-1967 storage slot.
    implementation = (
        slot_to_address(impl_slot) or ((source or {}).get("Implementation") or "").lower() or None
    )
    if implementation or (source or {}).get("Proxy") == "1":
        report.proxy.is_proxy = True
        report.proxy.implementation = implementation
        report.proxy.admin = slot_to_address(admin_slot)

    impl_source = None
    if report.proxy.implementation:
        impl_source = await c.run("Etherscan", es.source_code(chain, report.proxy.implementation))
        impl_abi = _parse_abi(impl_source)
        report.proxy.implementation_verified = impl_abi is not None
        if impl_abi:
            abi = (abi or []) + impl_abi

    report.owner = await _controller(c, services, chain, address)
    if report.proxy.admin:
        admin = await _controller(c, services, chain, report.proxy.admin, is_owner_of=True)
        report.proxy.admin_controlled_by = admin.address

    impl_code = None
    if report.proxy.implementation and not report.proxy.implementation_verified:
        impl_code = await c.run("RPC", rpc.code(chain, report.proxy.implementation))

    report.risky_functions = _risky_functions(abi, [code or "", impl_code or ""])
    sources_text = " ".join(
        str(s.get("SourceCode") or "") for s in (source, impl_source) if isinstance(s, dict)
    )
    report.findings = await _findings(report, sources_text, now, services, chain, c)
    report.summary = _summary(report)

    if c.failed("Etherscan"):
        report.data_gaps.append(
            f"Source code and creator could not be checked. Reason: {c.error('Etherscan')}"
        )
    if c.failed("RPC"):
        report.data_gaps.append(
            f"On-chain checks (code, proxy slots, owner) failed. Reason: {c.error('RPC')}"
        )
    report.sources = c.statuses
    return report


def _parse_abi(source: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if not source:
        return None
    try:
        abi = json.loads(source.get("ABI") or "")
    except (TypeError, ValueError):
        return None  # Etherscan puts "Contract source code not verified" here.
    return abi if isinstance(abi, list) else None


def _apply_source(report: ContractReport, source: dict[str, Any] | None) -> list | None:
    if source is None:
        return None
    abi = _parse_abi(source)
    report.verified = bool(source.get("SourceCode")) and abi is not None
    report.contract_name = source.get("ContractName") or None
    report.compiler_version = source.get("CompilerVersion") or None
    report.license = source.get("LicenseType") or None
    return abi


async def _safe_eth_call(services: Services, chain: Chain, to: str, data: str) -> str | None:
    """Call a view function. A "revert" just means the function does not exist."""
    try:
        return await services.rpc.eth_call(chain, to, data)
    except SourceError as exc:
        if "revert" in exc.message.lower() or "invalid opcode" in exc.message.lower():
            return None
        raise


async def _controller(
    c: Collector, services: Services, chain: Chain, address: str, *, is_owner_of: bool = False
) -> Controller:
    """Find who controls `address`.

    With is_owner_of=True, `address` is itself the controller (like a proxy
    admin), and we look one level deeper to see who owns *it*.
    """

    async def lookup_owner() -> str | None:
        for sel in OWNER_SELECTORS:
            result = await _safe_eth_call(services, chain, address, "0x" + sel)
            if result and len(result) >= 66:
                return slot_to_address(result[:66]) or DEAD_ZERO
        return None

    owner = await c.run("RPC", lookup_owner())
    if is_owner_of and owner in (None, DEAD_ZERO):
        # The admin has no owner() of its own, so the admin itself is the controller.
        owner = address
    if owner is None:
        return Controller(kind="none")
    if owner in DEAD:
        return Controller(address=DEAD_ZERO, kind="renounced")
    return await _classify(c, services, chain, owner)


async def _classify(c: Collector, services: Services, chain: Chain, address: str) -> Controller:
    code = await c.run("RPC", services.rpc.code(chain, address))
    if code is None:
        return Controller(address=address, kind="unknown")
    if code == "0x":
        return Controller(address=address, kind="wallet")
    threshold = await c.run(
        "RPC", _safe_eth_call(services, chain, address, "0x" + THRESHOLD_SELECTOR)
    )
    if threshold and threshold != "0x":
        return Controller(address=address, kind="multisig", multisig_threshold=int(threshold, 16))
    return Controller(address=address, kind="contract")


def _risky_functions(abi: list | None, bytecodes: list[str]) -> list[RiskyFunction]:
    found: dict[str, RiskyFunction] = {}
    if abi:
        for item in abi:
            if item.get("type") != "function":
                continue
            if item.get("stateMutability") in ("view", "pure"):
                continue
            name = item.get("name") or ""
            cat = match_abi_name(name)
            if cat is None:
                continue
            args = ",".join(i.get("type", "") for i in item.get("inputs") or [])
            sig = f"{name}({args})"
            found.setdefault(
                sig,
                RiskyFunction(
                    name=sig,
                    category=cat.key,
                    severity=cat.severity,
                    explanation=cat.explanation,
                    found_by="verified source",
                ),
            )
    else:
        for code in bytecodes:
            for cat, sig in scan_bytecode(code):
                found.setdefault(
                    sig,
                    RiskyFunction(
                        name=sig,
                        category=cat.key,
                        severity=cat.severity,
                        explanation=cat.explanation,
                        found_by="bytecode scan",
                    ),
                )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(found.values(), key=lambda f: (order[f.severity], f.name))


async def _findings(
    report: ContractReport,
    source_text: str,
    now: datetime,
    services: Services,
    chain: Chain,
    c: Collector,
) -> list[Finding]:
    out: list[Finding] = []

    def add(fid: str, severity: Severity, title: str, detail: str, source: str) -> None:
        out.append(Finding(id=fid, severity=severity, title=title, detail=detail, source=source))

    if report.verified is False:
        add(
            "contract.unverified",
            "high",
            "Source code is not verified",
            "The author has not published the source code, so nobody can easily check "
            "what the contract does. Most honest projects verify their contracts.",
            "Etherscan",
        )
    elif report.verified:
        add(
            "contract.verified",
            "info",
            "Source code is verified",
            "Anyone can read the published source code on the block explorer.",
            "Etherscan",
        )

    proxy = report.proxy
    if proxy.is_proxy:
        controller = proxy.admin_controlled_by or report.owner.address
        kind = None
        if controller:
            kind = (
                report.owner.kind
                if controller == report.owner.address
                else (await _classify(c, services, chain, controller)).kind
            )
        if kind == "wallet":
            add(
                "contract.upgradeable_by_wallet",
                "high",
                "One wallet can replace this contract's code",
                f"This is an upgradeable proxy controlled by a single wallet ({controller}). "
                "Whoever holds that wallet's key can change the rules at any time.",
                "RPC",
            )
        else:
            add(
                "contract.upgradeable",
                "medium",
                "Contract code can be replaced",
                "This is an upgradeable proxy. Its admin can swap in new code. "
                + (
                    f"The admin is a {kind} ({controller})."
                    if controller and kind
                    else "We could not tell who the admin is."
                ),
                "RPC",
            )
        if proxy.implementation_verified is False:
            add(
                "contract.implementation_unverified",
                "high",
                "The real logic is not verified",
                f"The implementation contract ({proxy.implementation}) that holds the "
                "real logic has no published source code.",
                "Etherscan",
            )

    owner = report.owner
    renounced = owner.kind in ("renounced", "none") and not proxy.is_proxy
    if owner.kind == "renounced":
        add(
            "contract.ownership_renounced",
            "info",
            "Ownership renounced",
            "The owner gave up control. Owner-only functions can no longer be used.",
            "RPC",
        )
    elif owner.kind == "wallet" and report.risky_functions:
        add(
            "contract.owner_is_single_wallet",
            "medium",
            "Controlled by a single wallet",
            f"The owner ({owner.address}) is a normal wallet. If its key is lost, stolen, or "
            "used in bad faith, the owner-only functions below can be abused.",
            "RPC",
        )
    elif owner.kind == "multisig":
        add(
            "contract.owner_is_multisig",
            "info",
            "Controlled by a multisig",
            f"The owner is a multisig wallet needing {owner.multisig_threshold} signature(s). "
            "This is safer than a single key.",
            "RPC",
        )

    for fn in report.risky_functions:
        severity: Severity = _LOWER[fn.severity] if renounced else fn.severity
        if fn.category == "ownership":
            continue
        add(
            f"contract.fn.{fn.category}",
            severity,
            f"Risky function: {fn.name}",
            fn.explanation
            + (" (Owner is renounced, so this is likely unusable.)" if renounced else ""),
            "Etherscan" if fn.found_by == "verified source" else "Bytecode scan",
        )
    lowered = source_text.lower()
    if "selfdestruct(" in lowered or "suicide(" in lowered:
        add(
            "contract.selfdestruct",
            "high",
            "Can self-destruct",
            "The source contains selfdestruct, which can remove the contract's code.",
            "Etherscan",
        )

    age = days_between(report.created_at, now)
    if age is not None and age < 7:
        add(
            "contract.very_new",
            "medium",
            "Contract is very new",
            f"Deployed {age} days ago. New contracts have no track record.",
            "Etherscan",
        )
    return _dedupe(out)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per ID. Risky functions are sorted most severe first,
    so the kept one is the most severe of its category."""
    seen: set[str] = set()
    unique = []
    for finding in findings:
        if finding.id not in seen:
            seen.add(finding.id)
            unique.append(finding)
    return unique


def _summary(report: ContractReport) -> str:
    parts: list[str] = []
    name = f" named {report.contract_name}" if report.contract_name else ""
    if report.verified:
        parts.append(f"This is a verified contract{name}.")
    elif report.verified is False:
        parts.append(
            "This contract's source code is not published, so its behaviour is hidden. "
            "The function list below comes from a bytecode scan and may be incomplete."
        )
    else:
        parts.append("We could not check whether the source code is published.")

    if report.proxy.is_proxy:
        parts.append(
            "It is an upgradeable proxy: the real logic lives at "
            f"{report.proxy.implementation or 'an unknown address'}, and its admin can swap "
            "that logic for new code."
        )

    owner = report.owner
    owner_text = {
        "renounced": "Ownership has been renounced, so owner-only powers are switched off.",
        "none": "It has no standard owner() function.",
        "wallet": f"It is owned by a single wallet ({owner.address}).",
        "multisig": f"It is owned by a multisig ({owner.address}) needing "
        f"{owner.multisig_threshold} signature(s).",
        "contract": f"It is owned by another contract ({owner.address}), "
        "such as a timelock or governance system.",
        "unknown": "We could not tell who owns it.",
    }[owner.kind]
    parts.append(owner_text)

    powers = [f for f in report.risky_functions if f.category != "ownership"]
    if powers:
        by_cat: dict[str, str] = {}
        for fn in powers:
            by_cat.setdefault(fn.category, fn.explanation.rstrip(".").lower())
        listed = "; ".join(by_cat.values())
        parts.append(f"Functions that could hurt users: it {listed}.")
    elif report.verified:
        parts.append("We found no common risky functions.")
    return " ".join(parts)
