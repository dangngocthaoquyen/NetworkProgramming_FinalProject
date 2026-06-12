import pytest


@pytest.fixture(autouse=True)
def clear_nvd_api_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
