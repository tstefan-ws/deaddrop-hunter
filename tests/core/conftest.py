import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Tests must never touch the network."""
    import urllib.request

    def boom(*a, **k):
        raise AssertionError("network access attempted in tests")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    monkeypatch.delenv("DUNE_API_KEY", raising=False)
