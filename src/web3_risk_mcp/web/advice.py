"""Advice shown before a USDC payment on Arc: send, think twice, or do not send.

The advice comes from the risk result plus Arc's own transfer rules. Arc
refuses a USDC payment to a blocked address, to the zero address, or to a
contract that does not accept it, and the sender still pays the fee. The
check simulates a payment (see send_check in score_risk) to find out. If the
simulation could not run, the same rules are applied from what we know.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from web3_risk_mcp.analysis.score import RiskScore
from web3_risk_mcp.chains import Chain

ZERO_ADDRESS = "0x" + "0" * 40


class SendAdvice(BaseModel):
    can_send: bool = Field(description="False when a payment would surely fail or be lost.")
    needs_confirmation: bool = Field(
        description="True when the user must confirm that they understand the risk."
    )
    messages: list[str] = Field(default_factory=list)


def send_advice(result: RiskScore, chain: Chain) -> SendAdvice:
    can_send = True
    needs_confirmation = False
    messages: list[str] = []
    found = {c.finding_id for c in result.contributions}
    coin = chain.native_symbol

    if result.send_check is not None and not result.send_check.would_succeed:
        can_send = False
        messages.append(result.send_check.explanation)
    elif result.address == ZERO_ADDRESS:
        can_send = False
        messages.append(f"{chain.name} does not allow sending {coin} to the zero address.")
    if "address.usdc_blocklisted" in found and can_send:
        can_send = False
        messages.append(
            "Circle's USDC contract blocks this address. A USDC payment to it would fail, "
            "and you would still pay the fee."
        )
    if "address.eurc_blocklisted" in found:
        messages.append("Circle's EURC contract also blocks this address.")
    if result.level in ("high", "critical"):
        needs_confirmation = True
        messages.append(f"{result.level.capitalize()} risk ({result.score}/100). {result.verdict}")
    if can_send and result.address_type in ("token", "contract"):
        needs_confirmation = True
        messages.append(
            "This is a smart contract, not a personal wallet. Money sent to a contract "
            "that does not expect it can be lost for good."
        )
    if result.address_type == "unknown":
        needs_confirmation = True
        messages.append("We could not tell if this is a wallet or a contract.")
    if result.confidence != "high":
        messages.append(
            f"Confidence is {result.confidence}: some data could not be checked, "
            "so the real risk may be higher."
        )
    if can_send and result.send_check is not None and result.send_check.would_succeed:
        messages.append(result.send_check.explanation)
    if can_send and not needs_confirmation and len(messages) <= 1:
        messages.insert(0, "No red flags in the data we could check. Double-check the address.")
    return SendAdvice(can_send=can_send, needs_confirmation=needs_confirmation, messages=messages)
