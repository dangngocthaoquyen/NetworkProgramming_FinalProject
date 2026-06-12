import json
from pathlib import Path

import requests

from app.tools.nvd_client import NvdClient, extract_cvss, normalize_cpe23


class FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        payload: dict | None = None,
        headers: dict[str, str] | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.text = text

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> dict:
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(
            {
                "url": url,
                "params": params,
                "headers": headers,
                "timeout": timeout,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_normalize_cpe22_to_cpe23():
    assert (
        normalize_cpe23("cpe:/a:proftpd:proftpd:1.3.5")
        == "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"
    )


def test_extract_cvss_prefers_v31_then_v30_then_v2():
    v31_payload = {
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}
            ],
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}
            ],
        }
    }
    v2_payload = {
        "metrics": {
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 10.0}, "baseSeverity": "HIGH"}
            ]
        }
    }

    assert extract_cvss(v31_payload) == (8.8, "HIGH")
    assert extract_cvss(v2_payload) == (10.0, "HIGH")


def test_client_sends_api_key_and_writes_cache(tmp_path: Path):
    session = FakeSession([FakeResponse(payload={"vulnerabilities": []})])
    client = NvdClient(
        api_key="secret-key",
        cache_dir=tmp_path,
        timeout_seconds=9.0,
        min_request_interval_seconds=0.0,
        session=session,
        sleep_func=lambda _: None,
    )

    payload = client.search_cves(
        cpe_name="cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"
    )

    assert payload == {"vulnerabilities": []}
    assert session.calls[0]["headers"] == {"apiKey": "secret-key"}
    assert session.calls[0]["timeout"] == 9.0
    assert list(tmp_path.glob("*.json"))


def test_client_falls_back_to_cached_response_when_live_fails(tmp_path: Path):
    session = FakeSession([requests.RequestException("temporary failure")])
    client = NvdClient(
        cache_dir=tmp_path,
        min_request_interval_seconds=0.0,
        max_retries=0,
        session=session,
        sleep_func=lambda _: None,
    )
    cache_path = client._cache_path(  # noqa: SLF001 - unit-testing cache key stability
        {"noRejected": "", "keywordSearch": "ProFTPD 1.3.5"}
    )
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2015-3306"}}]}),
        encoding="utf-8",
    )

    payload = client.search_cves(keyword_search="ProFTPD 1.3.5")

    assert payload["vulnerabilities"][0]["cve"]["id"] == "CVE-2015-3306"
