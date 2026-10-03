# RiskAttestation: saving risk checks on Arc

`RiskAttestation` is a tiny contract on Arc mainnet. It lets anyone save a risk
check about an address: the address, the 0 to 100 score, the version of the
public rule table, a hash of the findings, and the time. Each record keeps who
saved it, so readers decide whose checks they trust.

- No owner, no admin, no upgrades. Nobody can change or delete a record.
- It holds no money. Its functions refuse USDC, so USDC sent to it by mistake
  is refused instead of lost.
- The Arc Safe Send page builds the data for `attest(...)`. Your own wallet
  signs it. The server never signs anything.

The findings hash is `keccak256` of a short fixed text (sorted finding IDs and
their points, the score, the chain, the address and the rule version). Anyone
can rebuild the text from a result and check the hash. See
`src/web3_risk_mcp/attestation.py`.

## What was tested here

| Check | Result |
|---|---|
| `arc-forge test` (standard EVM rules), 8 tests including a 256-run fuzz test | passed |
| `FOUNDRY_PROFILE=arc arc-forge test` (Arc rules) | passed |
| The same tests on a fork of live Arc mainnet (`--fork-url https://rpc.mainnet.arc.io`) | passed |
| Deploy script dry run against Arc mainnet (no key, nothing sent) | about 378,000 gas, estimated 0.015 USDC at 40 gwei |
| Deploy and one `attest` call on a local Arc chain (`arc-anvil --network arc`) | worked; `attest` used 92,966 gas |
| A plain USDC send to the contract on the local Arc chain | refused, as intended |

It has **not** been deployed to Arc mainnet yet. That step needs your wallet,
so you do it yourself, below.

## Deploy it to Arc mainnet (about 10 minutes)

You need a wallet you control with a little USDC on Arc for gas. About
0.05 USDC is plenty: the dry run estimated 0.015 USDC.

1. **Install Arc Foundry** (Arc's own version of Foundry). On Linux x86_64:

   ```bash
   v=v0.8.0-2
   f=arc-foundry-$v-x86_64-unknown-linux-gnu.tar.gz
   curl -LO https://github.com/circlefin/arc-foundry/releases/download/$v/$f
   curl -LO https://github.com/circlefin/arc-foundry/releases/download/$v/$f.sha256
   sha256sum -c $f.sha256
   tar -xzf $f
   mkdir -p ~/.local/bin
   mv forge ~/.local/bin/arc-forge; mv cast ~/.local/bin/arc-cast; mv anvil ~/.local/bin/arc-anvil
   export PATH="$HOME/.local/bin:$PATH"
   arc-forge --version
   ```

   On a Mac, pick the `aarch64-apple-darwin` archive from the
   [releases page](https://github.com/circlefin/arc-foundry/releases) and use
   `shasum -a 256 -c` instead of `sha256sum -c`.

2. **Get the code and run the tests.**

   ```bash
   git clone --recurse-submodules https://github.com/MelvTheGoat/web3-risk-mcp
   cd web3-risk-mcp/contracts
   arc-forge test
   FOUNDRY_PROFILE=arc arc-forge test
   ```

3. **Put your key in an encrypted keystore.** Run this in your own terminal.
   It asks for the private key and a password, and stores the key encrypted in
   `~/.foundry/keystores`. Never paste a private key into a chat, an issue, or
   a file in this repository.

   ```bash
   arc-cast wallet import arc-deployer --interactive
   arc-cast wallet address --account arc-deployer   # shows the address to fund
   arc-cast balance $(arc-cast wallet address --account arc-deployer) --rpc-url arc --ether
   ```

   The last line shows your USDC balance on Arc (native USDC uses 18
   decimals, so `--ether` prints whole USDC).

4. **Dry run.** This simulates the deployment and prints the cost. Nothing is sent.

   ```bash
   FOUNDRY_PROFILE=arc arc-forge script script/DeployRiskAttestation.s.sol \
     --rpc-url arc --account arc-deployer
   ```

5. **Deploy.** The same command with `--broadcast`. It asks for the keystore
   password, sends one transaction, and prints the contract address.

   ```bash
   FOUNDRY_PROFILE=arc arc-forge script script/DeployRiskAttestation.s.sol \
     --rpc-url arc --account arc-deployer --broadcast
   ```

   Arc is final in under a second, so the contract is live as soon as the
   command finishes. Open `https://explorer.arc.io/address/<ADDRESS>` to see it.

6. **Publish the source on Etherscan** (optional, but it lets anyone read
   the code). This uses your free Etherscan key. It was not tested from here,
   because it needs a deployed contract.

   ```bash
   arc-forge verify-contract <ADDRESS> src/RiskAttestation.sol:RiskAttestation \
     --chain 5042 --etherscan-api-key $ETHERSCAN_API_KEY --watch
   ```

7. **Turn on "Save this check on Arc" in the web app.** In Render, open the
   service, go to **Environment**, add `ATTESTATION_CONTRACT` with the address
   from step 5, and save. Render redeploys by itself.

8. **Make the first record.** Open the live page, check an address, and press
   **Save to Arc**. Your wallet shows the call before you approve it. The
   transaction link appears on the page.

Prefer an environment variable to a keystore? `export DEPLOYER_PRIVATE_KEY=0x...`
in your own terminal, then run step 5 without `--account`. The keystore is
safer, because the key is never stored in plain text.

## Read records without the web app

```bash
# The latest check one attester saved about one address:
arc-cast call <CONTRACT> "latest(address,address)((uint8,uint16,uint64,bytes32))" \
  <ATTESTER> <SUBJECT> --rpc-url arc

# How many checks were saved in total:
arc-cast call <CONTRACT> "totalAttestations()(uint256)" --rpc-url arc
```
