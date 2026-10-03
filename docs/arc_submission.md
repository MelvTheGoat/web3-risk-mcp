# Arc Microgrants submission pack: Arc Safe Send

Everything needed for the DoraHacks submission. Fill in the two links marked
**TODO** once the web app and the contract are live on Arc mainnet.

---

## 1. BUIDL text (DoraHacks)

**Name:** Arc Safe Send

**One-line pitch:** Arc is built for payments and agents. Safe Send is the
check that runs before money moves.

**Problem:** On Arc, USDC moves in under a second and cannot be pulled back.
People and AI agents pay addresses they know nothing about. A payment to a
blocked address fails and still costs the fee. Money sent to a scammer is gone.

**What it does:** Paste a wallet, token, or contract address on Arc and get a
0 to 100 risk score, a reason for every point, and a confidence level. Then
pay in USDC from your own wallet. Sending is blocked when Arc would refuse
the payment, and risky addresses need a confirmation first. The server never
sees a key and never signs anything. The same check is an MCP tool, so AI
agents can check the other side before they pay, and any check can be saved
on Arc in a small RiskAttestation contract.

**How it uses Arc:**
- Reads Circle's USDC and EURC blocklists on Arc for every address.
- Simulates a 1 USDC payment with a read-only call to see if Arc would accept it.
- Reads USDC flows from Arc's system Transfer logs (EIP-7708) at 18
  decimals, so each move is counted once and none is missed.
- Pays in native USDC on Arc (chain 5042) from the user's wallet.
- Saves checks in a contract deployed on Arc mainnet.

**Tech stack:** Python, FastAPI, the MCP Python SDK, httpx, plain
JavaScript, Solidity with Arc Foundry, Etherscan V2, GoPlus, DexScreener, and
Arc RPC. 178 tests (170 Python, 8 Solidity), many replaying recorded Arc mainnet data.

**What's next:** Hand-checked Arc addresses in the public evaluation set, a
hosted MCP endpoint for agents, and an API that wallets and payment apps call
before every send.

**Links:**
- Live app: **TODO** (your Render link)
- RiskAttestation on Arc mainnet: **TODO** (`https://explorer.arc.io/address/<ADDRESS>`)
- Code: https://github.com/MelvTheGoat/web3-risk-mcp
- Builder profile: https://github.com/MelvTheGoat

---

## 2. Demo video script (about 1 minute 50 seconds)

Record the screen of the live app at normal browser width. Speak slowly.
Times are a guide.

| Time | Show on screen | Say |
|---|---|---|
| 0:00 to 0:12 | The Arc Safe Send page | "On Arc, USDC moves in under a second, and there is no undo. Arc Safe Send is the check that runs before money moves." |
| 0:12 to 0:30 | Click **USDC on Arc**. The score shows 0, low risk. Scroll the reasons. | "Here is a safe address: USDC itself. Score 0, low risk. Every point has a reason and a source, and the trust signals are listed too." |
| 0:30 to 0:55 | Click **A wallet USDC blocks**. The score shows 100, critical. Point at the reasons, then the blocklist findings. | "Now a risky one. Score 100, critical. GoPlus flags it as sanctioned, and Circle's own USDC and EURC contracts on Arc block it. Same issue, so it is not counted twice." |
| 0:55 to 1:10 | Scroll to **Check, then pay**. Show the red messages and the **Sending is blocked** button. | "We simulated a USDC payment. Arc would refuse it, and you would still pay the fee, so the page will not let you send." |
| 1:10 to 1:25 | Open **Data sources and how the data was read**. | "On Arc, USDC is the native coin with 18 decimals. We read Arc's system Transfer logs, so every USDC move is counted once." |
| 1:25 to 1:42 | Claude Desktop with the MCP server. Type: "Check 0x7f367cc41522ce07553e823bf3be79a889debe1b on Arc before I pay it." Show the tool call and the answer. | "AI agents get the same check as an MCP tool. Before an agent pays in USDC, it calls score_risk on Arc and sees the payment would fail." |
| 1:42 to 1:50 | Back on the page, check another address, enter 1 USDC, press **Connect wallet and send**, approve in MetaMask, show the explorer link. Optionally press **Save to Arc**. | "For a safe address, you pay from your own wallet, and you can save the check on Arc. Arc Safe Send: check, then pay." |

Tips:
- For the payment shot, pay a wallet you own, such as your second account.
- Run each example once before recording, so the answers come from the
  cache and appear at once.
- The free Render plan sleeps when idle. Open the page a minute before you
  record.

---

## 3. Checklist (from the Arc Microgrants rules)

| The rules ask for | Status | What to do |
|---|---|---|
| Deployed and working on Arc mainnet at the time you submit | Not yet | Deploy the RiskAttestation contract (contracts/README.md) and the web app (README, "Deploy the web app on Render"). Make one real payment and one saved check on mainnet. |
| A live deployment with a link reviewers can open | Not yet | Use the Render link. Check that it loads, that `/healthz` answers, and that the three example buttons work. |
| A public repo | Done | https://github.com/MelvTheGoat/web3-risk-mcp (everything is on `main`). |
| A short description of what it does and what it uses Arc for | Done | Section 1 above. |
| A public builder profile (GitHub, X, or Farcaster) | Done | https://github.com/MelvTheGoat |
| Not a mockup, slide deck, or testnet-only build | Done once deployed | Everything runs on Arc mainnet data; the contract and payments must be on mainnet. |
| Has an Arc component | Done | Blocklist reads, payment test, EIP-7708 USDC flows, USDC payments, contract on Arc. |
| Not already funded by a Circle or Arc program | Your call | Confirm this is true before you submit. |
| The work is yours, or you have the right to submit it | Your call | The repo is MIT licensed and written for you. |
| A wallet that can receive USDC on Arc (for payout) | Your call | Use a wallet you control on Arc. Do not reuse the deployer key for anything else. |
| Sanctions and restricted-jurisdiction screening; verification only if selected | Later | Pseudonymous submission is allowed. Verification is private and only for payout. |
| Deadline: 14 October 2026, 23:59 ET | Open | Reviews are rolling, so submit as soon as both links work. |
| One submission per project | Note | Submit Arc Safe Send once. |
| Demo video | Optional | The rules do not ask for one, but a short video helps reviewers. Script in section 2. |
