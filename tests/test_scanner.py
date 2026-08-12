"""Tests for scanner parsers using fixtures (no real scans required)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from netwatcher.scanner import (
    ArpHost, DetailResult, parse_arp_scan, parse_nmap_xml,
    _reverse_dns, _ssdp_discover, _match_ssdp_to_ip,
)

FIX = Path(__file__).parent / "fixtures"


def test_arp_scan_parser():
    raw = (FIX / "arp_scan_output.txt").read_text()
    hosts = parse_arp_scan(raw)
    assert len(hosts) == 3
    assert hosts[0] == ArpHost(
        ip="192.168.1.1", mac="00:11:22:33:44:55", vendor="RouterVendor Inc"
    )
    assert hosts[1].mac == "aa:bb:cc:dd:ee:ff"
    assert hosts[1].vendor == "Apple, Inc."
    assert hosts[2].vendor is None


def test_nmap_xml_parser():
    xml = (FIX / "nmap_detail.xml").read_text()
    res = parse_nmap_xml(xml)
    assert res.hostname == "iphone.local"
    os_list = json.loads(res.os_info)
    assert len(os_list) == 2
    assert os_list[0]["name"] == "Apple iOS 17"
    services = json.loads(res.services)
    assert len(services) == 2
    ports = {s["port"] for s in services}
    assert ports == {22, 443}
    assert services[1]["product"] == "nginx"


def test_nmap_xml_http_title():
    xml = (FIX / "nmap_detail.xml").read_text()
    res = parse_nmap_xml(xml)
    assert res.http_info is not None
    hi = json.loads(res.http_info)
    assert hi["title"] == "Mein Gerät"


def test_nmap_xml_tls_info():
    xml = (FIX / "nmap_detail.xml").read_text()
    res = parse_nmap_xml(xml)
    assert res.tls_info is not None
    ti = json.loads(res.tls_info)
    assert ti["subject"] == "CN=example.com"
    assert ti["issuer"] == "CN=Let's Encrypt"


def test_nmap_xml_upnp_info():
    xml = (FIX / "nmap_detail.xml").read_text()
    res = parse_nmap_xml(xml)
    assert res.network_info is not None
    ni = json.loads(res.network_info)
    assert "upnp" in ni
    assert ni["upnp"]["server"] == "Linux/2.6 UPnP/1.0 MiniUPnPd/2.0"


def test_reverse_dns_mocked():
    with patch("netwatcher.scanner.socket.gethostbyaddr",
               return_value=("host.example.com", [], ["10.0.0.1"])):
        assert _reverse_dns("10.0.0.1") == "host.example.com"


def test_reverse_dns_fails():
    with patch("netwatcher.scanner.socket.gethostbyaddr",
               side_effect=OSError("no data")):
        assert _reverse_dns("10.0.0.1") is None


def test_match_ssdp_to_ip():
    entries = [
        {"LOCATION": "http://192.168.1.5:80/desc.xml", "SERVER": "MiniUPnP/2.0"},
        {"LOCATION": "http://192.168.1.10:8080/wps_device.xml", "SERVER": "Printer"},
    ]
    result = _match_ssdp_to_ip(entries, "192.168.1.10")
    assert result is not None
    assert result["server"] == "Printer"

    result2 = _match_ssdp_to_ip(entries, "192.168.1.50")
    assert result2 is None
