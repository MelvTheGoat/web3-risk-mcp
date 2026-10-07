#!/usr/bin/env bash
# Deploy RiskAttestation to Arc mainnet, signed with your own encrypted keystore.
#
# Before you run it:
#   1. Install Arc Foundry (see README.md in this folder).
#   2. Put your key in a keystore (once):  arc-cast wallet import arc-deployer --interactive
#   3. Have a little USDC on Arc in that wallet (about 0.05 USDC is plenty).
#
# Run it from anywhere:
#   ./contracts/deploy.sh                 # uses the keystore named "arc-deployer"
#   ./contracts/deploy.sh my-other-name   # or another keystore name
#
# Your key never leaves your machine. The script asks for the keystore
# password once, keeps it in a private temporary file while it runs, and
# deletes that file when it ends.
set -euo pipefail
# A password in the environment would change how arc-cast reads calls, so drop it.
unset ETH_PASSWORD

ACCOUNT="${1:-arc-deployer}"
RPC="${ARC_RPC_URL:-https://rpc.mainnet.arc.io}"
ARC_CHAIN_ID=5042
SCRIPT=script/DeployRiskAttestation.s.sol

cd "$(dirname "$0")"

fail() { echo "Stopped: $*" >&2; exit 1; }

command -v arc-forge >/dev/null || fail "arc-forge not found. Install Arc Foundry first (see contracts/README.md)."
command -v arc-cast >/dev/null || fail "arc-cast not found. Install Arc Foundry first (see contracts/README.md)."
if [ ! -f lib/forge-std/src/Test.sol ]; then
  echo "Fetching forge-std..."
  git submodule update --init --recursive
fi

echo "1/6 Checking the network..."
chain_id=$(arc-cast chain-id --rpc-url "$RPC")
[ "$chain_id" = "$ARC_CHAIN_ID" ] || fail "$RPC is chain $chain_id, not Arc mainnet ($ARC_CHAIN_ID)."
echo "    Arc mainnet (chain $chain_id)"

echo "2/6 Running the contract tests (standard rules, then Arc rules)..."
arc-forge test > /dev/null || fail "tests failed. Run 'arc-forge test' in contracts/ to see why."
FOUNDRY_PROFILE=arc arc-forge test > /dev/null || fail "tests failed under Arc rules."
echo "    all tests passed"

PASSWORD_FILE=$(mktemp)
chmod 600 "$PASSWORD_FILE"
trap 'rm -f "$PASSWORD_FILE"' EXIT
read -r -s -p "Keystore password for '$ACCOUNT': " password; echo
printf '%s' "$password" > "$PASSWORD_FILE"
unset password

echo "3/6 Checking the deployer wallet..."
deployer=$(arc-cast wallet address --account "$ACCOUNT" --password-file "$PASSWORD_FILE") \
  || fail "could not open keystore '$ACCOUNT'. Create it with: arc-cast wallet import $ACCOUNT --interactive"
balance=$(arc-cast balance "$deployer" --rpc-url "$RPC" --ether)
echo "    $deployer has $balance USDC"
awk "BEGIN { exit !($balance >= 0.03) }" || fail "this wallet needs at least 0.03 USDC on Arc for gas."

echo "4/6 Dry run (nothing is sent)..."
FOUNDRY_PROFILE=arc arc-forge script "$SCRIPT" --rpc-url "$RPC" \
  --account "$ACCOUNT" --password-file "$PASSWORD_FILE" 2>&1 | grep -E "Estimated|Chain" || true

read -r -p "5/6 Deploy RiskAttestation to Arc mainnet from $deployer? Type yes: " answer
[ "$answer" = "yes" ] || fail "nothing was deployed."

FOUNDRY_PROFILE=arc arc-forge script "$SCRIPT" --rpc-url "$RPC" \
  --account "$ACCOUNT" --password-file "$PASSWORD_FILE" --broadcast > deploy.log 2>&1 \
  || { tail -20 deploy.log; fail "the deployment failed (full output in contracts/deploy.log)."; }

address=$(grep -oE "RiskAttestation deployed at: 0x[0-9a-fA-F]{40}" deploy.log | grep -oE "0x[0-9a-fA-F]{40}" | tail -1)
[ -n "$address" ] || fail "could not find the new address (see contracts/deploy.log)."

echo "6/6 Checking the contract is live..."
code=$(arc-cast code "$address" --rpc-url "$RPC")
[ "${#code}" -gt 2 ] || fail "no code at $address yet. Check contracts/deploy.log."
total=$(arc-cast call "$address" "totalAttestations()(uint256)" --rpc-url "$RPC")
echo "    live, totalAttestations() = $total"

cat <<EOF

Done. RiskAttestation is on Arc mainnet:
    $address
    https://explorer.arc.io/address/$address

Next:
  1. In Render, open the arc-safe-send service > Environment, add
         ATTESTATION_CONTRACT = $address
     and save. Render redeploys by itself.
  2. Open https://arc-safe-send.onrender.com, check an address, and press "Save to Arc".
  3. Put the explorer link above into docs/arc_submission.md (the TODO line).
EOF
