# web3-risk-mcp

[![CI](https://github.com/MelvTheGoat/web3-risk-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/MelvTheGoat/web3-risk-mcp/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A fraud analyst for web3 that any AI assistant can use.

`web3-risk-mcp` is an **MCP server**: a small program that gives AI assistants
(Claude Desktop, Cursor, and other MCP clients) new tools. These tools check a
crypto wallet, token, or smart contract for risk **before** someone interacts
with it. It then gives a 0 to 100 risk score with a clear reason for every point.

> **MCP** (Model Context Protocol) is an open standard for connecting AI
> assistants to outside tools and data. Write a tool once, and every MCP
> client can use it.

**New: [Arc Safe Send](#arc-and-arc-safe-send).** A web page and MCP tool
that checks an address on Arc, Circle's chain, before you send USDC. It reads
Circle's USDC and EURC blocklists, simulates the payment, counts each USDC
move once, and lets you pay from your own wallet.

---

## Contents

- [Why it matters](#why-it-matters)
- [Read-only by design](#read-only-by-design)
- [What it can do](#what-it-can-do)
- [How it works](#how-it-works)
- [Arc and Arc Safe Send](#arc-and-arc-safe-send)
- [Setup](#setup)
- [Connect it to Claude Desktop or Cursor](#connect-it-to-claude-desktop-or-cursor)
- [Example questions and outputs](#example-questions-and-outputs)
- [The risk score](#the-risk-score)
- [Evaluation](#evaluation)
- [Limitations](#limitations)
- [Development](#development)
- [Glossary](#glossary)

---

## Why it matters

Crypto scams are common, fast, and final. There is no bank to call and no
"undo" button. Common traps include:

- **Honeypot tokens**: you can buy them, but the contract stops you from selling.
- **Rug pulls**: the creator removes the trading money (the "liquidity") and the price goes to zero.
- **Hidden owner powers**: the owner can mint new tokens, freeze your wallet, or raise the sell fee to 100%.
- **Dirty money**: a wallet that received funds from a hack or a mixer.

People now ask AI assistants "is this token safe?" Without real data the
assistant can only guess. This server gives it real, on-chain evidence from
several sources, and a score it can explain line by line.

## Read-only by design

This is a safety feature, not a missing feature.

| The server never... | Why |
|---|---|
| asks for a private key or seed phrase | A key gives full control of a wallet. A risk checker has no reason to see one, so any tool that asks for one should be treated as a scam. |
| signs or sends transactions | Every check uses public, read-only data. There is no code path that can move funds. The RPC client even refuses any method outside a short read-only allow-list. |
| holds funds or approves spending | Nothing to steal, nothing to drain. |

Because of this, it is safe to hand the tools to an AI assistant. The worst a
confused assistant can do is read public data. Every tool is also marked with
the MCP `readOnlyHint`, so clients know it does not change anything.

The Arc Safe Send web app follows the same rule. When a user pays or saves a
check on Arc, their own browser wallet builds, shows, and signs the
transaction. The server only reads public data.

## What it can do

| Tool | What it answers |
|---|---|
| `score_risk` | "How risky is this address?" Detects if it is a wallet, token, or contract, runs the right checks, and returns a 0 to 100 score with every point explained. |
| `get_wallet_profile` | Wallet age, balance, number of transactions sent, top counterparties, tokens used recently, activity patterns, who first funded it, and known bad-actor labels. |
| `check_token_risk` | Honeypot signs, mint, blacklist, and pause powers, buy and sell tax, owner and holder concentration, liquidity size, and whether liquidity is locked. |
| `inspect_contract` | Is the source verified? Is it an upgradeable proxy? Who controls it: a single wallet, a multisig, or nobody? Plus a plain-English summary of risky functions. Works on unverified contracts too, by scanning the bytecode. |
| `trace_funds` | Follows money in and out for 1 or 2 hops and flags links to mixers, sanctioned wallets, exploiters, and phishing addresses, with the full path. |
| `list_supported_chains` | The chains it supports. |

Also included:

- **Resource** `risk://scoring-method`: the full scoring rules, generated from the same rule table the scorer uses.
- **Prompt** `investigate_address`: a step-by-step investigation plan that tells the assistant which tools to call, what to look for, and how to explain the result to a beginner.

**Chains:** Ethereum, Base, Arbitrum One, Polygon PoS, BNB Chain, and Arc
(Circle's chain, where USDC is the native coin). Arc gets
[extra checks](#arc-and-arc-safe-send).

## How it works

```mermaid
flowchart LR
    client["MCP client<br/>(Claude Desktop, Cursor)"] -->|"stdio or streamable HTTP"| server["MCP server<br/>6 tools, 1 resource, 1 prompt"]

    subgraph analysis["Analysis"]
        score["score_risk"]
        wallet["wallet profile"]
        token["token risk"]
        contract["contract inspection"]
        trace["fund tracing"]
    end

    server --> score
    browser["Arc Safe Send page"] -->|"POST /api/check"| webapp["Web app<br/>cache, limits per visitor"]
    webapp --> score
    browser -.->|"user's own wallet signs"| arc["Arc mainnet<br/>USDC payment,<br/>RiskAttestation"]
    score --> wallet & token & contract & trace
    wallet & token & contract & trace --> findings["Findings<br/>(id, severity, reason, source)"]
    findings --> scorer["Rule-based scorer<br/>0-100 + reasons + confidence"]

    wallet & token & contract & trace --> http["Shared HTTP layer<br/>cache, rate limits, retries"]
    http --> etherscan["Etherscan V2<br/>history, source code"]
    http --> goplus["GoPlus<br/>token and address security"]
    http --> dex["DexScreener<br/>pools and liquidity"]
    http --> rpc["Public RPC nodes<br/>balance, code, proxy slots,<br/>Arc blocklists, payment test"]
    wallet & trace --> list["Local list<br/>known mixers and exploiters"]
```

A few design choices worth knowing:

- **One failing source never breaks an investigation.** Each call is wrapped.
  If GoPlus is down, you still get the Etherscan and DexScreener results, and
  the report lists what failed and why in `sources` and `data_gaps`.
- **Missing data lowers confidence, not the score.** A report never quietly
  treats "no data" as "safe".
- **Resilient HTTP.** Answers are cached (5 minutes by default). Each source
  has its own rate limit under the free-plan limits. Timeouts, HTTP 429, and
  server errors are retried with exponential backoff and jitter. API keys are
  removed from logs, cache keys, and error messages.
- **Findings, then scoring.** The analysis code only describes what it sees.
  A separate, pure scoring function turns findings into points. This keeps
  the score easy to test and easy to explain.

## Arc and Arc Safe Send

> **Arc Safe Send** is a risk check before you send USDC on Arc.
> Arc is built for payments and agents. Safe Send is the check that runs
> before money moves.

**Live demo:** not deployed yet. Deploy it on Render's free plan with the
steps in [Deploy the web app on Render](#deploy-the-web-app-on-render), then
put the link here.

![Arc Safe Send checking a wallet that Circle's USDC contract blocks](docs/images/arc-safe-send-blocked.png)

Paste a wallet, token, or contract address on [Arc](https://docs.arc.io)
(Circle's chain, chain ID 5042). You get the 0 to 100 risk score with a
reason for every point and a confidence level. If you want to pay, the same
page sends USDC from your own browser wallet. The same check is the MCP tool
`score_risk` with `chain: "arc"`, so AI agents that pay in USDC can check
the other side before they send.

### What is checked on Arc

| Check | How | Finding |
|---|---|---|
| Blocked by Circle | Reads `isBlacklisted(address)` on the USDC and EURC contracts for every address checked | `address.usdc_blocklisted`, `address.eurc_blocklisted` (80 points, decisive, same group as sanctions) |
| Would a payment go through? | Simulates a 1 USDC payment with a read-only `eth_call` from a made-up sender. Nothing is sent or signed. | `send_check` in the result (it does not change the score) |
| Links to blocked addresses | Fund tracing checks the addresses it finds against both blocklists | `trace.direct.blocklisted` (50), `trace.indirect.blocklisted` (12) |
| Official Circle and Arc contracts | 13 contracts from the [official Arc contract list](https://docs.arc.io/arc/references/contract-addresses) are labelled | `address.official_contract` (-30, a trust signal) |
| Everything else | Sanctions and scam labels (GoPlus), wallet age and history, token and contract checks, fund tracing | The same rules as on every other chain |

Every data source answered for Arc in live checks on 3 October 2026:
Etherscan V2 (chain 5042, including account history on the free plan),
GoPlus (chain 5042), DexScreener (chain `arc`), and the Arc RPC nodes.

### USDC decimals and the system emitter

On Arc, USDC is the native coin and pays for gas. It has two views of one
balance:

| View | Decimals | Where you see it |
|---|---|---|
| Native | 18 | `eth_getBalance`, `msg.value`, plain sends |
| ERC-20 | 6 | The contract at `0x3600000000000000000000000000000000000000` |

They are the same money, so the tools never add them up, and every amount
uses the native 18-decimal value.

Every USDC move is logged once as a `Transfer` event by the system emitter
`0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE` (EIP-7708), at 18 decimals.
That covers plain sends, ERC-20 transfers, payouts from contracts, and bridge
mints and burns. An ERC-20 transfer is also logged a second time by the USDC
contract at 6 decimals, and Etherscan lists both. So on Arc:

- Wallet profiles and fund traces read money flows only from the system
  emitter stream (Etherscan `tokentx` filtered to the emitter address).
- Plain transactions only add zero-value contract calls, so nothing is
  counted twice.
- Both duplicate USDC rows are removed from the token list, so USDC shows once.
- Hop 2 of a trace follows the same stream.
- A transfer from the zero address is a mint, for example USDC bridged in
  with Circle's CCTP.

Why it matters, from real data: one ordinary Arc wallet received 7,862.87
USDC and bridged 7,862.43 USDC out through CCTP. Its plain transaction list
shows these as zero-value calls to the USDC contract, so a tracer that read
only transactions would see no money move. The system stream shows both
flows, once each, in whole USDC. This is a test in `tests/test_arc.py` that
replays recorded Arc mainnet responses.

### Check, then pay

![The payment box refusing to send to a blocked address](docs/images/arc-safe-send-pay-blocked.png)

After a check on Arc, the page can send USDC from your own browser wallet
(MetaMask, or any wallet that lets you add a network):

- The server never sees a key and never signs anything. Your wallet shows the
  payment before you approve it.
- The page adds or switches your wallet to Arc (chain 5042) and pays the
  exact address that was checked. If you edit the address, the old result
  disappears.
- Amounts become 18-decimal units with exact whole-number math (BigInt),
  never floating point.
- Sending is blocked when Arc would refuse the payment (a blocked address,
  the zero address, or a contract that does not accept USDC), because a
  refused payment still costs the fee.
- High-risk addresses and contracts need a confirmation tick first.

### Save a check on Arc

[`contracts/`](contracts/) holds `RiskAttestation`, a tiny contract that
keeps a public record of checks: the address, score, rule table version, a
hash of the findings, the time, and who saved it. It has no owner and holds
no money. When `ATTESTATION_CONTRACT` is set, the page shows **Save to Arc**
and your own wallet signs the call. The findings hash is keccak256 of a short
fixed text that anyone can rebuild from the result. Deploy steps with Arc
Foundry are in [contracts/README.md](contracts/README.md).

### For AI agents

Agents use the same MCP server (see [Setup](#setup)). Call `score_risk` with
`chain: "arc"`. On Arc the answer also has `send_check`. This is the real
answer for the blocked wallet in the screenshot:

```json
"send_check": {
  "would_succeed": false,
  "reason": "Blocked address",
  "explanation": "Arc would refuse a USDC payment to this address: the address is on the USDC blocklist. If you sent one, it would fail and you would still pay the fee. (This was only simulated: nothing was sent.)"
}
```

### Run the web app yourself

```bash
uv sync --extra web
uv run web3-risk-web            # then open http://127.0.0.1:8080
```

Or with Docker:

```bash
docker build -f Dockerfile.web -t arc-safe-send .
docker run --rm -p 10000:10000 -e ETHERSCAN_API_KEY=your-key arc-safe-send
```

The API is one call. Interactive docs are at `/api/docs`.

```bash
curl -X POST http://127.0.0.1:8080/api/check \
  -H "content-type: application/json" \
  -d '{"address": "0x3600000000000000000000000000000000000000", "chain": "arc"}'
```

### Deploy the web app on Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/MelvTheGoat/web3-risk-mcp)

1. Sign in at [render.com](https://render.com) with GitHub (the free plan is enough).
2. Press the button above, or choose **New > Blueprint** and pick this repository.
   Render reads [`render.yaml`](render.yaml) and builds [`Dockerfile.web`](Dockerfile.web).
3. When asked, paste your free Etherscan API key. It is stored only in
   Render's settings, never in the repository.
4. Wait for the build (a few minutes), then open the `onrender.com` link
   Render shows. Check `/healthz`, then try the three example buttons.

The free API keys are protected: results are cached for 10 minutes (1 minute
when a source failed), each visitor can run 6 new checks a minute and 40 an
hour, everyone together can run 1,500 a day, and at most 3 run at once.
Answers from the cache do not count. All of these are settings in
[`.env.example`](.env.example).

### What was tested, and how

| What | How | Result |
|---|---|---|
| Arc logic | 19 tests that replay 70 recorded Arc mainnet responses, plus small tests with hand-made responses | Pass |
| Web API | 18 tests on recorded data: blocked wallet, payment advice, cache, limits per visitor, bad input, failing sources | Pass |
| Saved checks | 9 tests, including an event emitted by the real contract on a local Arc chain | Pass |
| Page | Browser test (Chromium) with a mock wallet: a blocked wallet, a 12.5 USDC payment, bad amounts, the confirmation tick, phone width, dark mode | Pass |
| Payment and Save to Arc, end to end | The page's wallet calls sent to a local Arc chain (`arc-anvil --network arc`, chain ID 5042) running the contract | 2.5 USDC arrived, and the saved record matched the page |
| Contract | 8 Arc Foundry tests (with fuzzing) under standard rules, Arc rules, and on an Arc mainnet fork | Pass |
| Web image | Built and run locally, with a live Arc check | Pass |
| Not tested from here | A payment with a real wallet on Arc mainnet, the Render deployment, and the contract on mainnet. These need your own wallet and accounts. | Not run |

### Limits on Arc

- **Arc mainnet is young** (its first blocks are from May 2026). No Arc wallet
  is old enough for the "long, active history" trust signal yet, and many
  wallets will show "new wallet".
- **No Arc addresses in the evaluation set yet.** The published evaluation
  numbers come from 34 addresses on other chains. Arc addresses will be added
  once they are checked by hand.
- **Etherscan has no verified source for some Circle contracts on Arc**, so
  they still get "source not verified" points. Circle's CCTP TokenMessengerV2
  scores 38 (medium) even with the official-contract trust signal. EURC scores
  15 (low) and USDC scores 0.
- **The payment test uses a made-up sender**, so it cannot tell if *your*
  address is blocked. If it is, Arc refuses the transaction before it is
  sent, and no fee is charged.
- **GoPlus may know less about a new chain** than about Ethereum.
- **explorer.arc.io is not a data source.** Its API sits behind a browser
  check, so the tools use Etherscan for Arc history.
- **The free Render plan sleeps** after 15 minutes without visits. The first
  check after that can take up to a minute.

## Setup

### Quick start (no download needed)

The server is on PyPI, so you only need [uv](https://docs.astral.sh/uv/),
a small tool that runs Python programs. Install it once:

```bash
# Mac or Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Then get a free Etherscan key (see [API keys](#api-keys-all-free)) and
[connect your client](#connect-it-to-claude-desktop-or-cursor). The client
starts the server for you with `uvx web3-risk-mcp`. uvx downloads the latest
version the first time and reuses it after that.

Try it in a terminal first if you like:

```bash
uvx web3-risk-mcp --version
```

### API keys (all free)

| Setting | Where to get it | Needed? |
|---|---|---|
| `ETHERSCAN_API_KEY` | [etherscan.io/myapikey](https://etherscan.io/myapikey). One key covers every chain through the V2 API. | Yes, for wallet history, source code, and tracing |
| `GOPLUS_APP_KEY`, `GOPLUS_APP_SECRET` | [gopluslabs.io](https://gopluslabs.io) developer dashboard | No. GoPlus works without a key, at lower limits. |
| `RPC_URL_<CHAIN>` | Any provider, for example Alchemy or Infura | No. Free public nodes are the default. |
| DexScreener | No key | Not needed |

Settings are read from environment variables. With the quick start, you put
them in the `env` block of your client's config (shown below). When you run
from a copy of the repo, you can use a `.env` file instead (see `.env.example`).

> **Note on Etherscan's free plan.** It no longer includes account history
> on Base and BNB Chain. On those chains the wallet and tracing tools still
> return balance and contract data from RPC, and they say that history is
> missing. Source-code lookups work on every chain.

Keep your keys private. Never commit a `.env` file or share your config file.

### Run from source (for development)

```bash
git clone https://github.com/MelvTheGoat/web3-risk-mcp.git
cd web3-risk-mcp
uv sync
cp .env.example .env                                   # then add your keys
uv run web3-risk-mcp                                   # stdio (for local clients)
uv run web3-risk-mcp --transport http --port 8000      # streamable HTTP at /mcp
```

### Docker

```bash
docker build -t web3-risk-mcp .
docker run --rm -p 8000:8000 --env-file .env web3-risk-mcp        # HTTP on :8000/mcp
docker run -i --rm --env-file .env web3-risk-mcp --transport stdio # stdio
```

The image runs as a non-root user.

## Connect it to Claude Desktop or Cursor

### Claude Desktop

Open **Settings → Developer → Edit Config** and add this to
`claude_desktop_config.json`. Put your own key in place of `your-key-here`.

```json
{
  "mcpServers": {
    "web3-risk": {
      "command": "uvx",
      "args": ["web3-risk-mcp"],
      "env": { "ETHERSCAN_API_KEY": "your-key-here" }
    }
  }
}
```

Restart Claude Desktop. The tools appear under the tools icon, and the
`investigate_address` prompt appears in the prompt menu.

If the tools do not appear, Claude Desktop may not find `uvx`. Replace
`"uvx"` with its full path, which `which uvx` (Mac) or `where uvx` (Windows)
prints.

### Cursor

Add the same block to `~/.cursor/mcp.json` (all projects) or
`.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "web3-risk": {
      "command": "uvx",
      "args": ["web3-risk-mcp"],
      "env": { "ETHERSCAN_API_KEY": "your-key-here" }
    }
  }
}
```

### Running from a copy of the repo instead

Point the client at your folder. `--directory` makes the server start there,
so it reads your `.env` file:

```json
{
  "mcpServers": {
    "web3-risk": {
      "command": "uv",
      "args": ["--directory", "/full/path/to/web3-risk-mcp", "run", "web3-risk-mcp"]
    }
  }
}
```

### Any client, over HTTP

Start the server with `--transport http` (or the Docker image) and point the
client at `http://localhost:8000/mcp`:

```json
{ "mcpServers": { "web3-risk": { "url": "http://localhost:8000/mcp" } } }
```

Only run the HTTP server on your own machine or a private network. It has no
login, so anyone who can reach it can use your API keys.

## Releasing a new version

1. Change `version` in `pyproject.toml` and commit.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

The release workflow runs the tests, builds the package, publishes it to PyPI,
and creates a GitHub release. It uses PyPI trusted publishing, so no PyPI
password or token is stored in GitHub.

## Example questions and outputs

Things you can ask your assistant once the server is connected:

- "Is it safe to buy the token `0x…` on Base?"
- "Who controls the contract `0x…`? Can they change it?"
- "Where did the money in wallet `0x…` come from? Any links to mixers?"
- "Give me a risk score for `0x…` and explain every point."
- Or pick the **investigate_address** prompt and paste an address.

The outputs below are real. They come from the live evaluation run, and you
can reproduce them offline from `eval/fixtures/`. Some fields are trimmed.

**A honeypot token** (`0x43571a39…69be` on Ethereum, from a GoPlus case study):

```json
{
  "score": 100,
  "level": "critical",
  "confidence": "high",
  "address_type": "token",
  "contributions": [
    { "finding_id": "token.hidden_owner", "points": 25,
      "reason": "The contract has an owner-like role that is hidden from normal checks." },
    { "finding_id": "token.extreme_concentration", "points": 15,
      "reason": "The top 10 wallets hold 100.0% of the supply. They could crash the price." },
    { "finding_id": "token.high_sell_tax", "points": 15, "reason": "Selling costs 14.45%." },
    { "finding_id": "token.tax_modifiable", "points": 15,
      "reason": "The owner can raise the buy or sell tax at any time." },
    { "finding_id": "token.blacklist", "points": 10,
      "reason": "The owner can block chosen wallets from selling or moving tokens." },
    { "finding_id": "token.high_buy_tax", "points": 10, "reason": "Buying costs 15.0%." },
    { "finding_id": "contract.owner_is_single_wallet", "points": 8,
      "reason": "The owner (0x92ee…7ed1) is a normal wallet. If its key is lost, stolen, or used in bad faith, the owner-only functions below can be abused." }
  ],
  "checks_run": ["check_token_risk", "inspect_contract", "address_labels"],
  "data_gaps": []
}
```

**Circle's USDC on Arbitrum** (`0xaf88d065…5831`) shows the owner-power cap
and the "not counted twice" rule at work. Its admin powers are real and
reported, but they add up to 30 points, not 70:

```json
{
  "score": 30,
  "level": "medium",
  "contributions": [
    { "finding_id": "contract.upgradeable_by_wallet", "points": 20, "counted": true,
      "reason": "This is an upgradeable proxy controlled by a single wallet (0xc7a5…ebc9). Whoever holds that wallet's key can change the rules at any time." },
    { "finding_id": "contract.fn.blacklist", "points": 10, "counted": true,
      "rule": "risky function, high severity; owner powers are capped at 30 points in total" },
    { "finding_id": "contract.fn.mint", "points": 0, "counted": false,
      "rule": "risky function, high severity; owner powers are capped at 30 points in total" },
    { "finding_id": "token.proxy", "points": 0, "counted": false,
      "rule": "rule token.proxy; same issue as contract.upgradeable_by_wallet, not counted twice" }
  ]
}
```

`inspect_contract` writes a plain-English summary. For the same USDC contract:

> This is a verified contract named FiatTokenProxy. It is an upgradeable
> proxy: the real logic lives at 0x86e7…57b3, and its admin can swap that
> logic for new code. It is owned by a single wallet (0xc7a5…ebc9).
> Functions that could hurt users: it can block chosen wallets from selling
> or moving tokens; can create new tokens out of thin air, which dilutes
> every holder; can freeze transfers or trading; can move funds held by the
> contract out to an address the owner chooses; can replace the contract's
> code with new code.

## The risk score

The score is **rule-based and fully explainable**. There is no machine
learning and no hidden weighting.

1. Each tool turns what it sees into **findings** with a stable ID, such as
   `token.honeypot` or `trace.direct.mixer`.
2. A public **rule table** gives each finding ID its points. Trust signals give
   negative points: for example `token.trusted` is −40 and `wallet.established` is −10.
3. Findings that describe the **same problem** share a group, and only the
   biggest in a group counts. For example, "source not verified" from GoPlus and
   from Etherscan count once.
4. **Owner powers are capped.** Mint, blacklist, pause, upgrade, withdraw,
   trade limits, and single-wallet ownership all mean "a central party
   controls this". Together they add at most 30 points. Regulated stablecoins
   have all of these powers and are not scams. Scam-specific signals, such as
   honeypots, tax tricks, and hidden owners, are not capped.
5. The total is clamped to 0 to 100.
6. **Decisive findings** set a **floor of 75**, so trust signals can never
   hide them. Decisive means evidence of fraud or harm, not just the ability
   to cause it: a honeypot, a sanctioned or exploiter address, phishing, a
   fake token, and a few others.

| Score | Level | Meaning |
|---|---|---|
| 75 to 100 | critical | Very likely dangerous. Do not interact. |
| 50 to 74 | high | Serious red flags. Avoid unless you fully understand the risks. |
| 20 to 49 | medium | Some warning signs. Look closely before interacting. |
| 0 to 19 | low | No major red flags in the data we could check. |

Each score also has a **confidence** (high, medium, or low) based on how many
data sources answered. Every contribution lists its points, its reason, its
source, and the rule that applied. The full rule table is in
[docs/risk-method.md](https://github.com/MelvTheGoat/web3-risk-mcp/blob/main/docs/risk-method.md), and clients can read it through the
`risk://scoring-method` resource. Both are generated from the code, and a test
fails if the document drifts.

## Evaluation

[`eval/dataset.json`](https://github.com/MelvTheGoat/web3-risk-mcp/blob/main/eval/dataset.json) has 34 hand-checked addresses, each
with a source for its label:

- **12 risky**: a honeypot token from a GoPlus case study, the SQUID rug pull,
  4 phishing wallets labelled by Etherscan and ScamSniffer, 4 exploiter
  wallets (Ronin, Bybit, Euler, Wormhole), and 2 Tornado Cash pools.
- **22 safe**: major tokens on all five chains (USDC, USDT, DAI, WETH, UNI,
  LINK, AAVE, WBTC, stETH, ARB, CAKE, and others), Uniswap and Aave contracts,
  vitalik.eth, and an exchange hot wallet.

[`eval/run_eval.py`](https://github.com/MelvTheGoat/web3-risk-mcp/blob/main/eval/run_eval.py) scores every item and reports ROC AUC,
precision, recall, false alarms, and missed items at a threshold of 50. It
runs **twice**. The second run switches off the local list of known bad
addresses. Six risky items are on that list, so the second run shows what the
other signals (GoPlus, contract analysis, behaviour) catch on their own. This
keeps the evaluation honest.

```bash
uv run python eval/run_eval.py --record   # live run, saves every API response
uv run python eval/run_eval.py --replay   # re-run offline from the saved responses
```

With `--record`, every response is saved to `eval/fixtures/cassette.json.gz`
(API keys are never stored). Anyone can then reproduce the exact numbers with
`--replay`, without keys or network access.

### Results

From a live run on 2026-09-30. An address counts as flagged when it scores
50 or more. The full per-item table is in [`eval/results.md`](https://github.com/MelvTheGoat/web3-risk-mcp/blob/main/eval/results.md).

| Metric | Full scorer | Without local list |
|---|---:|---:|
| ROC AUC (1.0 = perfect separation, 0.5 = coin flip) | **0.981** | **0.958** |
| Accuracy | 0.941 | 0.882 |
| Precision (flagged items that really are risky) | 0.917 | 0.900 |
| Recall (risky items that got flagged) | 0.917 | 0.750 |
| False alarms | 1 of 22 safe | 1 of 22 safe |
| Missed | 1 of 12 risky | 3 of 12 risky |
| Mean score, risky / safe | 82.2 / 9.5 | 71.3 / 9.5 |

**What it gets wrong, and why:**

- **USDT scores 68 (false alarm).** USDT's owner really can wipe the balance
  of a blacklisted wallet (`destroyBlackFunds`), and GoPlus reports it. The
  finding is true. Whether it should make a major stablecoin "high risk" is
  a judgment call, so it stays visible rather than being tuned away.
- **SQUID scores 30 (missed).** The 2021 rug pull already happened. Today
  the contract looks ordinary to GoPlus. Account history on BNB Chain needs a
  paid Etherscan plan, so the tools could not see the old activity either.
- **Tornado Cash pools score 23 without the local list (missed).** GoPlus
  does not label the pool contracts themselves as mixers. The local list
  catches them.

**Honest note on tuning.** The first live run found real bugs and some rules
that were too harsh. I fixed three bugs: wallets using EIP-7702 delegation
were treated as contracts, empty GoPlus records made plain contracts look like
tokens, and rate-limit retries gave up too early. I also changed three rules:
the owner-power cap, "can change balances" no longer being decisive, and
ignoring GoPlus's "linked to honeypots" label for tokens. Each change is its
own commit with the reason. Because the rules were changed after seeing
this dataset, the numbers above are optimistic. The first run, before any
changes, scored:

| Metric | First run, full | First run, without local list |
|---|---:|---:|
| ROC AUC | 0.951 | 0.894 |
| Precision / recall | 0.786 / 0.917 | 0.750 / 0.750 |
| False alarms | 3 of 22 | 3 of 22 |

A fair next step is a larger, held-out set of addresses that was never used
to tune the rules.

## Limitations

- **Only as good as its sources.** A brand-new scam that GoPlus has not scanned
  and that is not on any list can score low. A low score is "no red flags
  found", not "safe".
- **Rule weights are hand-picked.** They follow common scam patterns and are
  checked by the evaluation set, but they are not a trained statistical model.
  Some rules were adjusted after the first evaluation run (see above), so the
  published numbers are optimistic.
- **Small evaluation set.** 34 addresses is enough to catch big mistakes, not
  to prove accuracy. Past scams that have gone quiet, like SQUID, are hard to
  catch after the fact.
- **Sampled history.** Wallet profiles and fund tracing look at the latest
  100 transactions of each kind (50 for hop-2 addresses), and tracing follows
  the busiest paths only. Old or low-volume activity can be missed.
- **Bytecode scanning is a heuristic.** It finds known function signatures in
  unverified contracts. Renamed or custom functions can slip through.
- **Etherscan free plan.** No account history on Base or BNB Chain without a
  paid plan. Arc is included in the free plan.
- **Arc.** See [Limits on Arc](#limits-on-arc).
- **Small local list.** The built-in list of known bad addresses is short and
  hand-checked on purpose. GoPlus provides the broad coverage.
- **EVM only.** No Solana, Bitcoin, or other non-EVM chains.
- **Not financial advice.** This is a research tool. Always do your own checks.

## Development

```bash
uv sync --all-extras         # install everything, including dev tools and the web app
uv run pytest                # 170 tests; all HTTP is mocked or replayed, no keys needed
uv run ruff check .          # lint
uv run ruff format .         # format
uv run python scripts/render_method_doc.py   # rebuild docs/risk-method.md after changing rules
uv run python -m tests.arc_fixtures --add-missing   # record new Arc responses (needs a key)

cd contracts && arc-forge test && FOUNDRY_PROFILE=arc arc-forge test   # contract tests
```

CI runs lint, format checks, and tests on Python 3.11, 3.12, and 3.13, builds
and starts both Docker images (MCP server and web app), and runs the contract
tests with Arc Foundry on every push.

```
src/web3_risk_mcp/
├── server.py          MCP tools, resource, and prompt
├── __main__.py        command line (stdio or HTTP)
├── config.py          settings from .env
├── chains.py          supported chains and address checks
├── services.py        builds all API clients
├── clients/           Etherscan, GoPlus, DexScreener, RPC, and the shared HTTP layer
├── analysis/          wallet, token, contract, trace, and score logic
├── scoring.py         rule table and scoring function
├── method.py          builds the scoring-method document
├── prompts.py         investigate_address prompt text
├── labels.py          lookup for the local address list
├── evaluation.py      metrics and record/replay for the evaluation
├── attestation.py     findings hash and call data for the RiskAttestation contract
├── web/               Arc Safe Send: FastAPI app, page, limits, payment advice
└── data/known_addresses.json

contracts/             RiskAttestation contract, tests, and deploy script (Arc Foundry)
render.yaml            one-click deploy of the web app on Render
Dockerfile.web         image for the web app (Dockerfile is the MCP server)
```

## Glossary

- **Address**: an account on the blockchain, written as `0x` plus 40 hex characters. It can be a wallet or a contract.
- **Wallet (EOA)**: an address controlled by a private key held by a person.
- **Smart contract**: a program that lives on the blockchain at its own address.
- **Token (ERC-20)**: a coin created by a smart contract.
- **EVM**: the Ethereum Virtual Machine. EVM chains share the same address and contract format.
- **DEX / pool / liquidity**: a decentralized exchange is a contract where people trade tokens. A pool holds two tokens, and the money in it is its liquidity.
- **LP tokens / locked liquidity**: whoever holds a pool's LP tokens can withdraw its liquidity. Locking or burning them stops a rug pull.
- **Honeypot**: a token you can buy but cannot sell.
- **Proxy / upgradeable contract**: a contract whose logic can be swapped for new code by its admin.
- **Renounced**: the owner gave up control, so owner-only functions can no longer be used.
- **Multisig**: a wallet that needs several people to sign, which is safer than a single key.
- **Mixer**: a service that pools and mixes funds to hide where they came from.
- **Verified source**: the author published the source code and the block explorer confirmed it matches the code on chain.
- **Function selector**: a 4-byte fingerprint of a function's name and inputs, stored in the contract's bytecode.
- **Arc**: Circle's own EVM chain (chain ID 5042). Fees are paid in USDC, and transactions are final in under a second.
- **Native USDC on Arc**: USDC is Arc's built-in coin, with 18 decimals. The same balance also appears through an ERC-20 contract with 6 decimals.
- **System emitter (EIP-7708)**: a special address on Arc that logs a `Transfer` event for every USDC move, so plain sends can be tracked like token transfers.
- **Blocklist**: a list kept by a stablecoin's issuer (here Circle). A blocked address cannot send or receive that coin.
- **CCTP**: Circle's Cross-Chain Transfer Protocol. It moves USDC between chains by burning it on one chain and minting it on another.
- **Attestation**: a signed, public record of a claim. Here, "this address scored N under rule table version V", saved on Arc.

## License

[MIT](https://github.com/MelvTheGoat/web3-risk-mcp/blob/main/LICENSE)
