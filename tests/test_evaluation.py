import httpx
import pytest
import respx

from web3_risk_mcp.evaluation import (
    Cassette,
    RecordingTransport,
    ReplayTransport,
    compute_metrics,
    request_key,
    roc_auc,
)


def test_roc_auc_perfect_random_and_ties():
    assert roc_auc([90, 80], [10, 20]) == 1.0
    assert roc_auc([10], [90]) == 0.0
    assert roc_auc([50], [50]) == 0.5


def test_compute_metrics_confusion_matrix():
    m = compute_metrics(risky=[90, 60, 30], safe=[0, 10, 55], threshold=50)
    assert (m.true_positives, m.false_negatives) == (2, 1)
    assert (m.false_positives, m.true_negatives) == (1, 2)
    assert m.precision == pytest.approx(0.667, abs=0.001)
    assert m.recall == pytest.approx(0.667, abs=0.001)
    assert m.accuracy == pytest.approx(0.667, abs=0.001)


def test_request_key_drops_api_key():
    request = httpx.Request("GET", "https://x.io/api?b=2&apikey=SECRET&a=1")
    assert request_key(request) == "GET https://x.io/api?a=1&b=2 "


@respx.mock
async def test_record_then_replay_offline(tmp_path):
    path = tmp_path / "cassette.json.gz"
    respx.get("https://x.io/data").mock(return_value=httpx.Response(200, json={"v": 1}))

    cassette = Cassette(path)
    async with httpx.AsyncClient(transport=RecordingTransport(cassette)) as client:
        assert (await client.get("https://x.io/data", params={"apikey": "K"})).json() == {"v": 1}
    cassette.save()

    respx.reset()
    replay = ReplayTransport(Cassette(path))
    async with httpx.AsyncClient(transport=replay) as client:
        assert (await client.get("https://x.io/data", params={"apikey": "OTHER"})).json() == {
            "v": 1
        }
        assert (await client.get("https://x.io/missing")).status_code == 404
    assert len(replay.misses) == 1
