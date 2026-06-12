"""Thin NVD CVE API 2.0 client with cache and conservative rate limiting."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import requests


DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = Path("data/cache/nvd")
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MIN_REQUEST_INTERVAL_SECONDS = 6.0
DEFAULT_MAX_RETRIES = 2
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class NvdClientError(RuntimeError):
    """Raised when the NVD client cannot return a usable response."""


class NvdClient:
    """Call the NVD CVE API with optional cache, retry, and backoff."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        cache_dir: str | Path = DEFAULT_CACHE_DIR,
        use_cache: bool = True,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        min_request_interval_seconds: float = DEFAULT_MIN_REQUEST_INTERVAL_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        session: requests.Session | None = None,
        sleep_func: Any = time.sleep,
        time_func: Any = time.monotonic,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.base_url = base_url
        self.cache_dir = Path(cache_dir)
        self.use_cache = use_cache
        self.timeout_seconds = timeout_seconds
        self.min_request_interval_seconds = min_request_interval_seconds
        self.max_retries = max_retries
        self.session = session or requests.Session()
        self.sleep_func = sleep_func
        self.time_func = time_func
        self._last_request_started_at = 0.0

    def search_cves(self, *, cpe_name: str | None = None, keyword_search: str | None = None) -> dict[str, Any]:
        """Query the NVD CVE API using one supported filter at a time."""

        params: dict[str, str] = {"noRejected": ""}
        if cpe_name:
            params["cpeName"] = cpe_name
            params["isVulnerable"] = ""
        elif keyword_search:
            params["keywordSearch"] = keyword_search
        else:
            raise ValueError("Either cpe_name or keyword_search must be provided")

        cache_path = self._cache_path(params)
        try:
            payload = self._request_json(params)
        except NvdClientError:
            if self.use_cache and cache_path.exists():
                return json.loads(cache_path.read_text(encoding="utf-8"))
            raise

        if self.use_cache:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    def load_cached(self, *, cpe_name: str | None = None, keyword_search: str | None = None) -> dict[str, Any] | None:
        """Return a cached response for the query when present."""

        params: dict[str, str] = {"noRejected": ""}
        if cpe_name:
            params["cpeName"] = cpe_name
            params["isVulnerable"] = ""
        elif keyword_search:
            params["keywordSearch"] = keyword_search
        else:
            raise ValueError("Either cpe_name or keyword_search must be provided")

        cache_path = self._cache_path(params)
        if not cache_path.exists():
            return None
        return json.loads(cache_path.read_text(encoding="utf-8"))

    def _request_json(self, params: dict[str, str]) -> dict[str, Any]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        attempt = 0

        while True:
            self._respect_rate_limit()
            try:
                response = self.session.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
            except requests.RequestException as exc:
                if attempt >= self.max_retries:
                    raise NvdClientError(f"NVD request failed: {exc}") from exc
                self._sleep_for_retry(attempt, None)
                attempt += 1
                continue

            if response.status_code in RETRYABLE_STATUS_CODES:
                if attempt >= self.max_retries:
                    raise NvdClientError(
                        f"NVD returned retryable status {response.status_code}"
                    )
                self._sleep_for_retry(attempt, response)
                attempt += 1
                continue

            if not response.ok:
                message = response.headers.get("message") or response.text.strip()
                raise NvdClientError(
                    f"NVD returned {response.status_code}: {message or 'unknown error'}"
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise NvdClientError("NVD response was not valid JSON") from exc

            if not isinstance(payload, dict):
                raise NvdClientError("NVD response payload must be a JSON object")
            return payload

    def _respect_rate_limit(self) -> None:
        now = self.time_func()
        elapsed = now - self._last_request_started_at
        if self._last_request_started_at > 0 and elapsed < self.min_request_interval_seconds:
            self.sleep_func(self.min_request_interval_seconds - elapsed)
        self._last_request_started_at = self.time_func()

    def _sleep_for_retry(self, attempt: int, response: requests.Response | None) -> None:
        retry_after = None
        if response is not None:
            value = response.headers.get("Retry-After")
            if value is not None:
                try:
                    retry_after = float(value)
                except ValueError:
                    retry_after = None
        delay = retry_after if retry_after is not None else min(2 ** attempt, 8)
        self.sleep_func(delay)

    def _cache_path(self, params: dict[str, str]) -> Path:
        canonical = "&".join(f"{key}={params[key]}" for key in sorted(params))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"


def normalize_cpe23(cpe: str) -> str | None:
    """Normalize a legacy CPE 2.2 URI to CPE 2.3 when possible."""

    if not cpe:
        return None
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return None

    body = cpe.removeprefix("cpe:/")
    parts = body.split(":")
    if not parts or parts[0] not in {"a", "o", "h"}:
        return None

    normalized = [_normalize_cpe_component(value) for value in parts]
    while len(normalized) < 7:
        normalized.append("*")
    normalized = normalized[:7]
    normalized.extend(["*"] * 4)
    return "cpe:2.3:" + ":".join(normalized)


def extract_cvss(payload: dict[str, Any]) -> tuple[float | None, str | None]:
    """Return the preferred CVSS base score and severity from one NVD CVE record."""

    metrics = payload.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        metric = entries[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        if isinstance(score, (int, float)):
            return float(score), str(severity).upper() if severity else None
    return None, None


def english_description(payload: dict[str, Any]) -> str:
    """Pick the English description when present."""

    descriptions = payload.get("descriptions", [])
    if not isinstance(descriptions, list):
        return "NVD record matched the enumerated target."
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    for item in descriptions:
        if item.get("value"):
            return str(item["value"])
    return "NVD record matched the enumerated target."


def references_from_nvd(payload: dict[str, Any]) -> list[str]:
    """Extract reference URLs from an NVD CVE record."""

    references = payload.get("references", [])
    if not isinstance(references, list):
        return []
    urls: list[str] = []
    for item in references:
        url = item.get("url")
        if isinstance(url, str) and url:
            urls.append(url)
    return list(dict.fromkeys(urls))


def _normalize_cpe_component(value: str) -> str:
    if value == "":
        return "*"
    return value
