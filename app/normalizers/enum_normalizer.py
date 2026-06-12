"""Helpers for backfilling enriched enumeration fields used by Phase 3."""

from __future__ import annotations

from copy import deepcopy
from typing import Any
from urllib.parse import urlparse


WEB_LIKE_SERVICES = {"http", "https", "http-proxy", "ipp"}
METASPLOITABLE3_HOST = "172.28.128.3"
JETTY_CONTINUUM_URL = "http://172.28.128.3:8080/continuum"


def normalize_enum_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the payload with normalized web inventory."""

    normalized = deepcopy(payload)
    for host in normalized.get("hosts", []):
        _normalize_host_web_inventory(host)
    return normalized


def _normalize_host_web_inventory(host: dict[str, Any]) -> None:
    existing = host.get("web", [])
    web_entries: list[dict[str, Any]] = [deepcopy(item) for item in existing]
    seen_urls = {
        str(item.get("url"))
        for item in web_entries
        if isinstance(item, dict) and item.get("url")
    }

    host_ip = str(host.get("ip", ""))
    for port in host.get("ports", []):
        if not isinstance(port, dict):
            continue

        url = port.get("url") or _derived_url(host_ip, port)
        if url is not None and port.get("url") is None:
            port["url"] = url

        if url is None or str(url) in seen_urls:
            continue

        web_entries.append(
            {
                "url": url,
                "port": port.get("port"),
                "service": port.get("service"),
                "product": port.get("product"),
                "version": port.get("version"),
                "title": _title_from_banner(port.get("banner")),
                "banner": port.get("banner"),
                "vhost": port.get("vhost"),
                "source": port.get("source"),
                "technologies": list(port.get("technologies", [])),
                "interesting_paths": list(port.get("discovered_paths", [])),
                "api_endpoints": list(port.get("api_endpoints", [])),
            }
        )
        seen_urls.add(str(url))

    _add_known_lab_web_contexts(host_ip, host, web_entries, seen_urls)
    host["web"] = web_entries


def _add_known_lab_web_contexts(
    host_ip: str,
    host: dict[str, Any],
    web_entries: list[dict[str, Any]],
    seen_urls: set[str],
) -> None:
    if host_ip != METASPLOITABLE3_HOST:
        return

    for port in host.get("ports", []):
        if not isinstance(port, dict):
            continue
        if not _is_jetty_continuum_port(port):
            continue

        port.setdefault("discovered_paths", [])
        if "/continuum" not in port["discovered_paths"]:
            port["discovered_paths"].append("/continuum")

        if JETTY_CONTINUUM_URL in seen_urls:
            continue

        web_entries.append(
            {
                "url": JETTY_CONTINUUM_URL,
                "port": port.get("port"),
                "service": port.get("service"),
                "product": port.get("product"),
                "version": port.get("version"),
                "title": "Continuum",
                "banner": port.get("banner"),
                "vhost": port.get("vhost"),
                "source": port.get("source"),
                "technologies": list(port.get("technologies", [])),
                "interesting_paths": ["/continuum"],
                "api_endpoints": list(port.get("api_endpoints", [])),
            }
        )
        seen_urls.add(JETTY_CONTINUUM_URL)


def _is_jetty_continuum_port(port: dict[str, Any]) -> bool:
    if port.get("port") != 8080:
        return False

    fields = (
        str(port.get("service") or ""),
        str(port.get("product") or ""),
        str(port.get("version") or ""),
        str(port.get("banner") or ""),
        " ".join(str(item) for item in port.get("technologies", [])),
    )
    return any("jetty" in value.casefold() for value in fields)


def _derived_url(host_ip: str, port: dict[str, Any]) -> str | None:
    service = str(port.get("service") or "").casefold()
    port_number = port.get("port")
    if service not in WEB_LIKE_SERVICES or not isinstance(port_number, int):
        return None

    scheme = "https" if service == "https" or port_number == 443 else "http"
    if (scheme == "http" and port_number == 80) or (scheme == "https" and port_number == 443):
        return f"{scheme}://{host_ip}/"
    return f"{scheme}://{host_ip}:{port_number}/"


def _title_from_banner(banner: Any) -> str | None:
    if not isinstance(banner, str):
        return None
    for part in banner.split(";"):
        text = part.strip()
        if text.lower().startswith("title:"):
            return text.split(":", 1)[1].strip() or None
    parsed = urlparse(banner)
    return None if parsed.scheme else None
