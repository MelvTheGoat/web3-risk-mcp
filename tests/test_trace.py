import respx

from tests.mocks import etherscan_error, mock_etherscan, mock_goplus_address_by
from web3_risk_mcp.analysis.trace import flows, trace_funds
from web3_risk_mcp.chains import get_chain

ETH = get_chain("ethereum")
ME = "0x" + "11" * 20
FRIEND = "0x" + "22" * 20
SHOP = "0x" + "33" * 20
TORNADO = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"
RONIN = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
BINANCE = "0x28c6c06298d514db089934071355e5743bf21d60"
ETH_1 = str(10**18)


def tx(frm, to, value=ETH_1, error="0"):
    return {"from": frm, "to": to, "value": value, "isError": error, "input": "0x"}


def history(table):
    """Etherscan txlist answered per address."""
    return lambda params: table.get(params["address"], [])


def test_flows_counts_value_and_ignores_failed_and_zero_value():
    table = flows(
        ME,
        [tx(FRIEND, ME), tx(ME, SHOP), tx(ME, SHOP, value="0"), tx(ME, FRIEND, error="1")],
        tokens=[{"from": ME, "to": SHOP}],
    )
    assert table[FRIEND].in_transfers == 1
    assert table[FRIEND].out_transfers == 0
    assert table[SHOP].out_transfers == 1
    assert table[SHOP].interactions == 1
    assert table[SHOP].token_out == 1


@respx.mock
async def test_direct_link_to_mixer(services):
    mock_etherscan({"txlist": history({ME: [tx(TORNADO, ME), tx(ME, SHOP)]})})
    mock_goplus_address_by({})

    trace = await trace_funds(services, ETH, ME, hops=1)

    assert {n.address for n in trace.nodes} == {ME, TORNADO, SHOP}
    assert [link.address for link in trace.risky_links] == [TORNADO]
    link = trace.risky_links[0]
    assert link.relation == "sent funds to the address"
    assert link.path == [ME, TORNADO]
    finding = trace.findings[0]
    assert finding.id == "trace.direct.mixer"
    assert finding.severity == "high"


@respx.mock
async def test_two_hops_finds_indirect_sanctioned_link(services):
    mock_etherscan(
        {
            "txlist": history(
                {
                    ME: [tx(ME, FRIEND), tx(BINANCE, ME)],
                    FRIEND: [tx(RONIN, FRIEND), tx(FRIEND, SHOP)],
                }
            )
        }
    )
    mock_goplus_address_by({})

    trace = await trace_funds(services, ETH, ME, hops=2)
    nodes = {n.address: n for n in trace.nodes}

    assert nodes[FRIEND].expanded is True
    assert nodes[BINANCE].expanded is False
    assert "Not followed" in nodes[BINANCE].note
    assert nodes[RONIN].hop == 2
    link = next(link for link in trace.risky_links if link.address == RONIN)
    assert link.path == [ME, FRIEND, RONIN]
    assert link.relation == "sent funds to a hop-1 address"
    assert [f.id for f in trace.findings] == ["trace.indirect.sanctioned"]


@respx.mock
async def test_direction_out_only_follows_outgoing(services):
    mock_etherscan({"txlist": history({ME: [tx(TORNADO, ME), tx(ME, SHOP)]})})
    mock_goplus_address_by({})

    trace = await trace_funds(services, ETH, ME, direction="out")
    addresses = {n.address for n in trace.nodes}

    assert SHOP in addresses
    # Known risky addresses are always kept, even outside the chosen direction.
    assert TORNADO in addresses


@respx.mock
async def test_goplus_flag_on_counterparty(services):
    mock_etherscan({"txlist": history({ME: [tx(SHOP, ME)]})})
    mock_goplus_address_by({SHOP: {"phishing_activities": "1"}})

    trace = await trace_funds(services, ETH, ME)

    assert trace.findings[0].id == "trace.direct.flagged"
    assert trace.findings[0].severity == "critical"
    assert "phishing" in trace.risky_links[0].reason


@respx.mock
async def test_etherscan_failure_returns_empty_trace_with_reason(services):
    mock_etherscan({"txlist": etherscan_error("Invalid API Key")})

    trace = await trace_funds(services, ETH, ME)

    assert trace.edges == []
    assert "could not be loaded" in trace.data_gaps[0]
