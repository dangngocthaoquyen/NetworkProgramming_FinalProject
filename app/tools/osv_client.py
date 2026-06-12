"""Thin OSV API client with cache, retry, and conservative parsing helpers."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests


DEFAULT_BASE_URL = "https://api.osv.dev/v1"
DEFAULT_CACHE_DIR = Path("data/cache/osv")
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_RETRIES = 2
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class OsvClientError(RuntimeError):
    """Raised when the OSV client cannot return a usable response."""


class OsvClient:
    """Call the OSV API with optional cache, retry, and backoff."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        cache_dir: str | Path = DEFAULT_CACHE_DIR,
        use_cache: bool = True,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        session: requests.Session | None = None,
        sleep_func: Any = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.cache_dir = Path(cache_dir)
        self.use_cache = use_cache
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.session = session or requests.Session()
        self.sleep_func = sleep_func

    def query(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST one OSV package/version query."""

        return self._request_json("POST", "/query", payload)

    def query_batch(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """POST batched OSV queries and return aligned per-query results."""

        if not queries:
            return []

        payload = {"queries": queries}
        response = self._request_json("POST", "/querybatch", payload)
        results = response.get("results")
        if not isinstance(results, list):
            raise OsvClientError("OSV querybatch response must contain a results list")
        return results

    def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        """GET a detailed vulnerability document by OSV identifier."""

        if not vuln_id:
            raise ValueError("vuln_id must be provided")
        return self._request_json("GET", f"/vulns/{quote(vuln_id, safe='')}", None)

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        cache_path = self._cache_path(method, path, payload)
        attempt = 0

        while True:
            try:
                response = self.session.request(
                    method,
                    f"{self.base_url}{path}",
                    json=payload,
                    timeout=self.timeout_seconds,
                )
            except requests.RequestException as exc:
                if attempt >= self.max_retries:
                    return self._load_cached_or_raise(cache_path, f"OSV request failed: {exc}", exc)
                self._sleep_for_retry(attempt, None)
                attempt += 1
                continue

            if response.status_code in RETRYABLE_STATUS_CODES:
                if attempt >= self.max_retries:
                    return self._load_cached_or_raise(
                        cache_path,
                        f"OSV returned retryable status {response.status_code}",
                    )
                self._sleep_for_retry(attempt, response)
                attempt += 1
                continue

            if not response.ok:
                message = response.text.strip() or "unknown error"
                raise OsvClientError(f"OSV returned {response.status_code}: {message}")

            try:
                data = response.json()
            except ValueError as exc:
                raise OsvClientError("OSV response was not valid JSON") from exc

            if not isinstance(data, dict):
                raise OsvClientError("OSV response payload must be a JSON object")

            if self.use_cache:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return data

    def _load_cached_or_raise(
        self,
        cache_path: Path,
        message: str,
        exc: Exception | None = None,
    ) -> dict[str, Any]:
        if self.use_cache and cache_path.exists():
            return json.loads(cache_path.read_text(encoding="utf-8"))
        if exc is not None:
            raise OsvClientError(message) from exc
        raise OsvClientError(message)

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

    def _cache_path(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> Path:
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")) if payload else ""
        digest = hashlib.sha256(
            f"{method.upper()} {path} {canonical_payload}".encode("utf-8")
        ).hexdigest()
        return self.cache_dir / f"{digest}.json"


def aliases_from_osv(payload: dict[str, Any]) -> list[str]:
    """Return unique aliases from an OSV vulnerability record."""

    aliases = payload.get("aliases", [])
    if not isinstance(aliases, list):
        return []
    return list(dict.fromkeys(str(item) for item in aliases if str(item)))


def preferred_cve_from_osv(payload: dict[str, Any]) -> str | None:
    """Return the first CVE alias when OSV links the record to one."""

    for alias in aliases_from_osv(payload):
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    return None


def references_from_osv(payload: dict[str, Any]) -> list[str]:
    """Extract reference URLs from an OSV vulnerability record."""

    references = payload.get("references", [])
    if not isinstance(references, list):
        return []

    urls: list[str] = []
    for item in references:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if isinstance(url, str) and url:
            urls.append(url)
    return list(dict.fromkeys(urls))


def summary_from_osv(payload: dict[str, Any]) -> str:
    """Return a concise summary from an OSV vulnerability record."""

    summary = payload.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()

    details = payload.get("details")
    if isinstance(details, str) and details.strip():
        return details.strip().splitlines()[0]

    vuln_id = payload.get("id")
    if isinstance(vuln_id, str) and vuln_id:
        return f"OSV record {vuln_id} matched the authorized target."
    return "OSV record matched the authorized target."


def extract_cvss_from_osv(payload: dict[str, Any]) -> float | None:
    """Return the strongest numeric CVSS score exposed by an OSV record."""

    scores: list[float] = []

    severity = payload.get("severity", [])
    if isinstance(severity, list):
        for item in severity:
            if isinstance(item, dict):
                parsed = _coerce_score(item.get("score"))
                if parsed is not None:
                    scores.append(parsed)

    scores.extend(_scores_from_mapping(payload.get("database_specific")))

    affected = payload.get("affected", [])
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            scores.extend(_scores_from_mapping(item.get("database_specific")))
            scores.extend(_scores_from_mapping(item.get("ecosystem_specific")))

    return max(scores) if scores else None


def _scores_from_mapping(value: Any) -> list[float]:
    if not isinstance(value, dict):
        return []

    scores: list[float] = []
    for key in ("score", "baseScore", "cvss_score"):
        parsed = _coerce_score(value.get(key))
        if parsed is not None:
            scores.append(parsed)

    for key in ("cvss", "cvss_v3", "severity"):
        nested = value.get(key)
        if isinstance(nested, dict):
            for nested_key in ("score", "baseScore"):
                parsed = _coerce_score(nested.get(nested_key))
                if parsed is not None:
                    scores.append(parsed)
        else:
            parsed = _coerce_score(nested)
            if parsed is not None:
                scores.append(parsed)
    return scores


def _coerce_score(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        score = float(value)
        return score if 0 <= score <= 10 else None
    if isinstance(value, str):
        stripped = value.strip()
        try:
            score = float(stripped)
        except ValueError:
            return None
        return score if 0 <= score <= 10 else None
    return None
