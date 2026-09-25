import json
from datetime import UTC, datetime

import respx

from tests.mocks import etherscan_error, mock_etherscan, mock_rpc
from web3_risk_mcp.analysis.contract import inspect_contract
from web3_risk_mcp.analysis.selectors import scan_bytecode, selector
from web3_risk_mcp.chains import get_chain
from web3_risk_mcp.clients.rpc import EIP1967_ADMIN_SLOT, EIP1967_IMPLEMENTATION_SLOT

ETH = get_chain("ethereum")
CONTRACT = "0x" + "c0" * 20
IMPL = "0x" + "1a" * 20
PROXY_ADMIN = "0x" + "ad" * 20
SAFE = "0x" + "5a" * 20
DEV = "0x" + "de" * 20
NOW = datetime(2026, 9, 1, tzinfo=UTC)
ZERO_WORD = "0x" + "0" * 64


def word(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def abi(*functions):
    items = [
        {
            "type": "function",
            "name": n,
            "inputs": [{"type": t} for t in ins],
            "stateMutability": "nonpayable",
        }
        for n, ins in functions
    ]
    items.append(
        {
            "type": "function",
            "name": "balanceOf",
            "inputs": [{"type": "address"}],
            "stateMutability": "view",
        }
    )
    return json.dumps(items)


def source(abi_json, name="Token", code="contract Token {}"):
    return [
        {
            "SourceCode": code,
            "ABI": abi_json,
            "ContractName": name,
            "CompilerVersion": "v0.8.20",
            "Proxy": "0",
            "Implementation": "",
            "LicenseType": "MIT",
        }
    ]


def rpc(code_by_addr, *, owner_by_addr=None, storage=None, threshold_by_addr=None):
    owner_by_addr = owner_by_addr or {}
    storage = storage or {}
    threshold_by_addr = threshold_by_addr or {}

    def get_code(params):
        return code_by_addr.get(params[0], "0x")

    def get_storage(params):
        return storage.get((params[0], params[1]), ZERO_WORD)

    def call(params):
        to, data = params[0]["to"], params[0]["data"]
        if data == "0x" + selector("owner()") and to in owner_by_addr:
            return owner_by_addr[to]
        if data == "0x" + selector("getThreshold()") and to in threshold_by_addr:
            return threshold_by_addr[to]
        return Exception("execution reverted")

    return {"eth_getCode": get_code, "eth_getStorageAt": get_storage, "eth_call": call}


def test_selector_matches_known_values():
    assert selector("transferOwnership(address)") == "f2fde38b"
    assert selector("mint(address,uint256)") == "40c10f19"


def test_bytecode_scan_finds_push4_selectors():
    code = "0x6080" + "63" + selector("mint(address,uint256)") + "00" + "63" + selector("pause()")
    found = {sig for _, sig in scan_bytecode(code)}
    assert found == {"mint(address,uint256)", "pause()"}


@respx.mock
async def test_verified_token_with_renounced_owner(services):
    mock_etherscan(
        {
            "getsourcecode": source(
                abi(("mint", ["address", "uint256"]), ("transferOwnership", ["address"]))
            ),
            "getcontractcreation": [
                {"contractCreator": DEV, "txHash": "0xabc", "timestamp": "1600000000"}
            ],
        }
    )
    mock_rpc(ETH, rpc({CONTRACT: "0x6080"}, owner_by_addr={CONTRACT: ZERO_WORD}))

    report = await inspect_contract(services, ETH, CONTRACT, now=NOW)
    by_id = {f.id: f for f in report.findings}

    assert report.verified is True
    assert report.contract_name == "Token"
    assert report.creator == DEV
    assert report.owner.kind == "renounced"
    assert report.proxy.is_proxy is False
    assert [f.name for f in report.risky_functions] == [
        "mint(address,uint256)",
        "transferOwnership(address)",
    ]
    assert by_id["contract.fn.mint"].severity == "low"  # lowered because owner is renounced
    assert "contract.ownership_renounced" in by_id
    assert "Ownership has been renounced" in report.summary


@respx.mock
async def test_unverified_contract_owned_by_wallet(services):
    bytecode = (
        "0x6080"
        + "63"
        + selector("mint(address,uint256)")
        + "63"
        + selector("setBots(address[],bool)")
    )
    mock_etherscan(
        {
            "getsourcecode": [
                {"SourceCode": "", "ABI": "Contract source code not verified", "ContractName": ""}
            ],
            "getcontractcreation": [
                {
                    "contractCreator": DEV,
                    "txHash": "0x1",
                    "timestamp": str(int(NOW.timestamp()) - 3600),
                }
            ],
        }
    )
    mock_rpc(ETH, rpc({CONTRACT: bytecode}, owner_by_addr={CONTRACT: word(DEV)}))

    report = await inspect_contract(services, ETH, CONTRACT, now=NOW)
    ids = {f.id for f in report.findings}

    assert report.verified is False
    assert report.owner.kind == "wallet"
    assert report.owner.address == DEV
    assert {f.found_by for f in report.risky_functions} == {"bytecode scan"}
    assert {
        "contract.unverified",
        "contract.fn.mint",
        "contract.fn.blacklist",
        "contract.owner_is_single_wallet",
        "contract.very_new",
    } <= ids
    assert "not published" in report.summary


@respx.mock
async def test_proxy_controlled_by_multisig(services):
    def sources(params):
        if params["address"] == IMPL:
            return source(abi(("pause", []), ("upgradeTo", ["address"])), name="LogicV2")
        return source(abi(), name="TransparentUpgradeableProxy")

    mock_etherscan({"getsourcecode": sources})
    mock_rpc(
        ETH,
        rpc(
            {CONTRACT: "0x6080", PROXY_ADMIN: "0x6080", SAFE: "0x6080", IMPL: "0x6080"},
            owner_by_addr={PROXY_ADMIN: word(SAFE)},
            storage={
                (CONTRACT, EIP1967_IMPLEMENTATION_SLOT): word(IMPL),
                (CONTRACT, EIP1967_ADMIN_SLOT): word(PROXY_ADMIN),
            },
            threshold_by_addr={SAFE: "0x" + "0" * 63 + "3"},
        ),
    )

    report = await inspect_contract(services, ETH, CONTRACT, now=NOW)
    by_id = {f.id: f for f in report.findings}

    assert report.proxy.is_proxy is True
    assert report.proxy.implementation == IMPL
    assert report.proxy.admin == PROXY_ADMIN
    assert report.proxy.admin_controlled_by == SAFE
    assert report.proxy.implementation_verified is True
    assert "contract.upgradeable" in by_id
    assert "multisig" in by_id["contract.upgradeable"].detail
    assert "contract.fn.pause" in by_id
    assert "upgradeable proxy" in report.summary


@respx.mock
async def test_wallet_address_is_not_a_contract(services):
    mock_etherscan({})
    mock_rpc(ETH, rpc({}))

    report = await inspect_contract(services, ETH, CONTRACT, now=NOW)

    assert report.is_contract is False
    assert "get_wallet_profile" in report.summary


@respx.mock
async def test_etherscan_down_still_scans_bytecode(services):
    mock_etherscan(
        {
            "getsourcecode": etherscan_error("Invalid API Key"),
            "getcontractcreation": etherscan_error("Invalid API Key"),
        }
    )
    bytecode = "0x6080" + "63" + selector("pause()")
    mock_rpc(ETH, rpc({CONTRACT: bytecode}))

    report = await inspect_contract(services, ETH, CONTRACT, now=NOW)

    assert report.verified is None
    assert [f.name for f in report.risky_functions] == ["pause()"]
    assert any("Source code and creator could not be checked" in g for g in report.data_gaps)
