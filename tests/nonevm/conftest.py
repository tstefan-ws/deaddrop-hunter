import pytest
from nonevm_fakes import FakeSleep


@pytest.fixture
def fake_sleep():
    return FakeSleep()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("TRONGRID_API_KEY", "DDH_RPC_SOLANA", "DDH_RPC_APTOS"):
        monkeypatch.delenv(k, raising=False)
