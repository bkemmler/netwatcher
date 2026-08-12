"""Tests for OPNsense API client."""
from __future__ import annotations

import json
from unittest.mock import patch

from netwatcher.opnsense import fetch_static_hosts, _normalize_mac, _split_ips, _is_v4, _is_v6


def test_normalize_mac():
    assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert _normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert _normalize_mac("  AA:BB:CC:DD:EE:FF  ") == "aa:bb:cc:dd:ee:ff"
    assert _normalize_mac("short") is None
    assert _normalize_mac("") is None


def test_split_ips():
    assert _split_ips("10.0.0.1,10.0.0.2") == ["10.0.0.1", "10.0.0.2"]
    assert _split_ips("10.0.0.1") == ["10.0.0.1"]
    assert _split_ips("") == []
    assert _split_ips(["10.0.0.1", "fe80::1"]) == ["10.0.0.1", "fe80::1"]


def test_is_v4():
    assert _is_v4("10.0.0.1") is True
    assert _is_v4("fe80::1") is False
    assert _is_v4("not-an-ip") is False


def test_is_v6():
    assert _is_v6("fe80::1") is True
    assert _is_v6("10.0.0.1") is False
    assert _is_v6("not-an-ip") is False


def test_fetch_static_hosts_success():
    mock_response = {
        "total": 2,
        "rowCount": 2,
        "current": 1,
        "rows": [
            {"host": "printer", "ip": "10.0.0.50", "hwaddr": "aa:bb:cc:dd:ee:01",
             "descr": "Office Printer"},
            {"host": "server", "ip": "10.0.0.10,fe80::1",
             "hwaddr": "AA-BB-CC-DD-EE-02", "descr": ""},
        ],
    }

    with patch("netwatcher.opnsense.requests.post") as mock_post:
        mock_post.return_value.json.return_value = mock_response
        mock_post.return_value.raise_for_status.return_value = None

        hosts = fetch_static_hosts(
            "https://192.168.1.1",
            "key", "secret",
            verify_tls=True, timeout=10,
        )

        assert len(hosts) == 2
        assert hosts[0].hostname == "printer"
        assert hosts[0].ipv4 == ["10.0.0.50"]
        assert hosts[0].ipv6 == []
        assert hosts[0].mac == "aa:bb:cc:dd:ee:01"
        assert hosts[0].description == "Office Printer"

        assert hosts[1].hostname == "server"
        assert hosts[1].ipv4 == ["10.0.0.10"]
        assert hosts[1].ipv6 == ["fe80::1"]
        assert hosts[1].mac == "aa:bb:cc:dd:ee:02"


def test_fetch_static_hosts_request_error():
    import requests as req
    with patch("netwatcher.opnsense.requests.post") as mock_post:
        mock_post.side_effect = req.exceptions.ConnectionError("connection refused")
        hosts = fetch_static_hosts("https://192.168.1.1", "k", "s")
        assert hosts == []
