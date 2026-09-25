"""Prompt templates. A prompt is a ready-made set of instructions a user can
pick in their MCP client, so the assistant follows a proven workflow."""

from __future__ import annotations


def investigation_prompt(address: str, chain: str = "ethereum", user_goal: str = "") -> str:
    goal = (
        f"The user's goal: {user_goal.strip()}\n"
        if user_goal.strip()
        else "The user did not say what they plan to do. Ask if it matters for your advice.\n"
    )
    return f"""\
Investigate this address for risk before the user interacts with it.

Address: {address}
Chain: {chain}
{goal}
Follow these steps. Use the tools; do not guess facts you have not checked.

1. Quick verdict. Call `score_risk` with the address and chain. Note the score,
   level, confidence, and the `address_type` (wallet, token, or contract).

2. Go deeper based on the type:
   - token: call `check_token_risk`. Focus on honeypot signs, sell tax, who can
     mint or blacklist, holder concentration, liquidity size, and whether
     liquidity is locked. Then call `inspect_contract` to see who controls it.
   - contract: call `inspect_contract`. Explain whether the code is verified,
     whether it can be upgraded, and who controls it (single wallet, multisig,
     or renounced).
   - wallet: call `get_wallet_profile`, then `trace_funds` with hops=2 to see
     where money came from and went. Pay attention to mixers, sanctioned
     addresses, and exploiters in the paths.

3. Check the gaps. Read `sources` and `data_gaps` in every result. If a source
   failed, say so clearly. Missing data is not evidence of safety.

4. Write the answer for someone new to crypto:
   - Start with one sentence: the verdict and the score (for example
     "High risk, 68/100, medium confidence").
   - List the top 3 to 5 reasons, each in plain words, with the source.
   - Mention any trust signals that lowered the score.
   - Say what could not be checked.
   - End with a clear, practical recommendation tied to the user's goal.
     If it looks dangerous, say plainly "do not interact".

Rules:
- Explain any crypto term the first time you use it (for example "honeypot:
  a token you can buy but cannot sell").
- Never ask for a private key or seed phrase, and never suggest signing
  anything. These tools are read-only.
- Do not overstate certainty. The score is rule-based and can miss new scams.
- If you need the details of how points are given, read the resource
  `risk://scoring-method`.
"""
