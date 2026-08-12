"""Optional integrations: arpwatch, LibreNMS and Greenbone."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)


def normalize_mac(value: str) -> str:
    return value.strip().lower().replace("-", ":")


def read_arpwatch(path: str) -> dict[str, dict[str, str]]:
    """Read arpwatch's whitespace-separated arp.dat format."""
    result: dict[str, dict[str, str]] = {}
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return result
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        ip, mac, timestamp = parts[:3]
        if ":" not in mac and "-" not in mac:
            continue
        result[normalize_mac(mac)] = {
            "ip": ip,
            "last_seen": timestamp,
            "hostname": " ".join(parts[3:]) if len(parts) > 3 else "",
        }
    return result


def fetch_librenms(url: str, token: str, verify_tls: bool = True,
                   timeout: float = 10) -> list[dict[str, Any]]:
    endpoint = url.rstrip("/") + "/api/v0/devices"
    try:
        response = requests.get(
            endpoint, headers={"X-Auth-Token": token, "Accept": "application/json"},
            verify=verify_tls, timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("devices", data.get("rows", []))
    except (requests.RequestException, ValueError, TypeError) as exc:
        logger.warning("LibreNMS API failed: %s", exc)
        return []


def fetch_greenbone_report(url: str, username: str, password: str,
                           verify_tls: bool = True, timeout: float = 30) -> dict[str, Any]:
    """Fetch a configured Greenbone report URL.

    Greenbone installations expose reports through GMP or a generated HTTP
    export URL. Keeping the URL configurable supports both variants without
    requiring a Greenbone daemon on the Netwatcher host.
    """
    if not url:
        return {}
    try:
        response = requests.get(
            url, auth=(username, password) if username or password else None,
            verify=verify_tls, timeout=timeout,
        )
        response.raise_for_status()
        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            data = response.json()
            return data if isinstance(data, dict) else {"report": data}
        return {"report": response.text[:200000]}
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Greenbone report failed: %s", exc)
        return {}


def encode(data: dict[str, Any]) -> str | None:
    return json.dumps(data, ensure_ascii=False) if data else None
