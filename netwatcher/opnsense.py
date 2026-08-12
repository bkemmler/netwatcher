"""OPNsense API client for Dnsmasq static host entries."""
from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger(__name__)


@dataclass
class OpnHost:
    hostname: str | None = None
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    mac: str | None = None
    description: str | None = None


def fetch_static_hosts(
    url: str,
    api_key: str,
    api_secret: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
) -> list[OpnHost]:
    """Fetch all static DHCP host entries from OPNsense Dnsmasq API."""
    base = url.rstrip("/") + "/api/dnsmasq/settings/search_host"
    auth = (api_key, api_secret)
    all_rows: list[dict[str, Any]] = []

    current = 1
    row_count = 100
    while True:
        try:
            resp = requests.post(
                base,
                json={"current": current, "rowCount": row_count},
                auth=auth,
                verify=verify_tls,
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("rows", [])
            all_rows.extend(rows)
            total = data.get("total", 0)
            if len(rows) < row_count or len(all_rows) >= total:
                break
            current += 1
        except requests.exceptions.RequestException as exc:
            logger.warning("OPNsense API request failed: %s", exc)
            break
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("OPNsense API parse error: %s", exc)
            break

    hosts: list[OpnHost] = []
    for row in all_rows:
        hostname = row.get("host") or None
        descr = row.get("descr") or None
        ip_list = _split_ips(row.get("ip", ""))
        mac = _normalize_mac(row.get("hwaddr", ""))

        ipv4 = [ip for ip in ip_list if _is_v4(ip)]
        ipv6 = [ip for ip in ip_list if _is_v6(ip)]

        hosts.append(OpnHost(
            hostname=hostname,
            ipv4=ipv4,
            ipv6=ipv6,
            mac=mac,
            description=descr,
        ))

    return hosts


def _split_ips(raw: str | list[str]) -> list[str]:
    if isinstance(raw, list):
        return [s.strip() for s in raw if s.strip()]
    return [s.strip() for s in raw.split(",") if s.strip()]


def _is_v4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def _is_v6(ip: str) -> bool:
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def _normalize_mac(raw: str) -> str | None:
    s = raw.strip().lower().replace("-", ":")
    if not s or len(s) < 11:
        return None
    return s
