"""Network scanning: arp-scan (fast discovery) and nmap (detail)."""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from . import db, macvendor


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- arp-scan ---


@dataclass
class ArpHost:
    ip: str
    mac: str
    vendor: str | None = None


_ARP_LINE = re.compile(
    r"^\s*([0-9.]+)\s+([0-9A-Fa-f:]{17})\s+(.*)$"
)


def parse_arp_scan(output: str) -> list[ArpHost]:
    hosts: list[ArpHost] = []
    for line in output.splitlines():
        m = _ARP_LINE.match(line)
        if not m:
            continue
        ip, mac, vendor = m.group(1), m.group(2), m.group(3).strip()
        if not vendor or vendor.lower() == "(unknown)":
            vendor = None
        hosts.append(ArpHost(ip=ip, mac=mac.lower(), vendor=vendor))
    return hosts


def run_arp_scan(scan_range: str, interface: str | None = None) -> str:
    arp_bin = _which("arp-scan")
    if arp_bin is None:
        raise RuntimeError("arp-scan binary not found")
    cmd = [arp_bin, "--ignoredups", "--retry=3"]
    if not _is_root():
        cmd.insert(0, "sudo")
    if interface:
        cmd += ["--interface", interface]
    cmd.append(scan_range)
    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"arp-scan failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


# --- nmap ---


@dataclass
class DetailResult:
    os_info: str | None
    services: str | None
    hostname: str | None
    http_info: str | None = None
    tls_info: str | None = None
    network_info: str | None = None


def parse_nmap_xml(xml: str) -> DetailResult:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml)
    host = root.find("host")
    hostname = None
    if host is not None:
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

    os_list: list[dict[str, Any]] = []
    os_elem = host.find("os") if host is not None else None
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            os_list.append(
                {"name": match.get("name"), "accuracy": match.get("accuracy")}
            )

    services_list: list[dict[str, Any]] = []
    ports_elem = host.find("ports") if host is not None else None
    if ports_elem is not None:
        for port in ports_elem.findall("port"):
            s = port.find("state")
            if s is not None and s.get("state") != "open":
                continue
            sv = port.find("service")
            services_list.append(
                {
                    "port": int(port.get("portid", 0)),
                    "proto": port.get("protocol"),
                    "service": sv.get("name") if sv is not None else None,
                    "product": sv.get("product") if sv is not None else None,
                    "version": sv.get("version") if sv is not None else None,
                }
            )

    http_info: dict[str, Any] = {}
    tls_info: dict[str, Any] = {}
    network_info: dict[str, Any] = {}

    if host is not None:
        for script in host.findall(".//script"):
            sid = script.get("id", "")
            out = script.get("output", "")

            if sid == "http-title":
                http_info["title"] = _extract_script_val(out, "Site title:")
                http_info["raw"] = out.strip()

            elif sid == "ssl-cert":
                tls_info["subject"] = _extract_script_val(out, "Subject:")
                tls_info["issuer"] = _extract_script_val(out, "Issuer:")
                tls_info["not_before"] = _extract_script_val(out, "Not valid before:")
                tls_info["not_after"] = _extract_script_val(out, "Not valid after:")
                tls_info["raw"] = out.strip()

            elif sid == "upnp-info":
                network_info.setdefault("upnp", {})
                network_info["upnp"]["server"] = _extract_script_val(out, "Server:")
                network_info["upnp"]["raw"] = out.strip()

            elif sid in ("nbstat", "smb-os-discovery"):
                network_info.setdefault("smb", {})
                network_info["smb"]["computer_name"] = _extract_script_val(out, "Computer name:")
                network_info["smb"]["workgroup"] = _extract_script_val(out, "Workgroup:")
                network_info["smb"]["os"] = _extract_script_val(out, "OS:")
                network_info["smb"]["raw"] = out.strip()

    return DetailResult(
        os_info=json.dumps(os_list) if os_list else None,
        services=json.dumps(services_list) if services_list else None,
        hostname=hostname,
        http_info=json.dumps(http_info) if http_info else None,
        tls_info=json.dumps(tls_info) if tls_info else None,
        network_info=json.dumps(network_info) if network_info else None,
    )


def _extract_script_val(output: str, prefix: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            val = stripped[len(prefix):].strip()
            return val if val else None
    return None


def run_nmap_detail(ip: str) -> DetailResult | None:
    nmap_bin = _which("nmap")
    if nmap_bin is None:
        return None

    scripts = "http-title,ssl-cert,upnp-info,nbstat,smb-os-discovery"
    base = [nmap_bin, "-O", "-sV", "-T4", "--version-light",
            "--script", scripts, "-oX", "-", "-Pn", ip]
    if not _is_root():
        base = ["sudo"] + base

    proc = subprocess.run(base, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        cmd_fb = [nmap_bin, "-sV", "-T4", "-oX", "-", "-Pn", ip]
        if not _is_root():
            cmd_fb = ["sudo"] + cmd_fb
        proc = subprocess.run(cmd_fb, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return None
    try:
        return parse_nmap_xml(proc.stdout)
    except Exception:
        return None


SCAN_PROFILES = {
    "quick": "Schnellscan",
    "detail": "Detailscan",
    "full": "Vollscan",
}


def run_nmap_profile(ip: str, profile: str) -> DetailResult | None:
    """Run one of the supported nmap profiles against a single IP."""
    nmap_bin = _which("nmap")
    if nmap_bin is None or profile not in SCAN_PROFILES:
        return None

    if profile == "quick":
        args = ["-sV", "--top-ports", "20"]
    elif profile == "full":
        args = ["-O", "-sV", "-p-", "--version-light",
                "--script", "http-title,ssl-cert,upnp-info,nbstat,smb-os-discovery"]
    else:
        args = ["-O", "-sV", "-T4", "--version-light",
                "--script", "http-title,ssl-cert,upnp-info,nbstat,smb-os-discovery"]

    cmd = [nmap_bin, *args, "-oX", "-", "-Pn", ip]
    if not _is_root():
        cmd.insert(0, "sudo")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              check=False, timeout=900 if profile == "full" else 180)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    try:
        return parse_nmap_xml(proc.stdout)
    except Exception:
        return None


def run_profile_scan(profile: str, ip: str | None = None,
                     db_path: str | None = None) -> dict[str, Any]:
    """Run a profile for one IP or all known devices and record its history."""
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unbekanntes Scan-Profil: {profile}")
    devices = db.all_devices(db_path)
    if ip:
        devices = [d for d in devices if d.get("ip_last") == ip]

    scanned = 0
    updated = 0
    now = now_iso()
    for device in devices:
        target = device.get("ip_last")
        if not target:
            continue
        scanned += 1
        result = run_nmap_profile(target, profile)
        if result is None:
            continue
        db.update_device_detail(
            device_id=device["id"], os_info=result.os_info,
            services=result.services, hostname=result.hostname, now_iso=now,
            http_info=result.http_info, tls_info=result.tls_info,
            network_info=result.network_info, db_path=db_path,
        )
        with db.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO scan_history(device_id, ts, scan_type, ip, raw) "
                "VALUES(?,?,?,?,?)",
                (device["id"], now, f"profile:{profile}", target, None),
            )
        updated += 1
    return {"profile": profile, "scanned": scanned, "updated": updated,
            "timestamp": now}


# --- DNS / mDNS / IPv6 ---


def _reverse_dns(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name if name != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def _mdns_lookup(ip: str, timeout: float = 2.0) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        query = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x04_ip\x00\x00\x0c\x00\x01"
        )
        sock.sendto(query, ("224.0.0.251", 5353))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 12:
            name_parts = []
            pos = 12
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                if length >= 192:
                    break
                pos += 1
                name_parts.append(data[pos:pos + length].decode("ascii", errors="replace"))
                pos += length
            return ".".join(name_parts) if name_parts else None
    except Exception:
        return None
    return None


def _discover_ipv6_neighbors() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    try:
        proc = subprocess.run(
            ["ip", "-6", "neigh"], capture_output=True, text=True, check=False
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "lladdr":
                ipv6 = parts[0]
                mac = parts[4].lower()
                result.setdefault(mac, []).append(ipv6)
    except Exception:
        pass
    return result


# --- HTTP / TLS ---


def _http_check(ip: str, port: int = 80, timeout: float = 3.0) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        req = urllib.request.Request(f"http://{ip}:{port}/", headers={"User-Agent": "Netwatcher/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result["status"] = resp.status
            result["server"] = resp.headers.get("Server", "")
            body = resp.read(65536).decode("utf-8", errors="replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if m:
                result["title"] = m.group(1).strip()
    except Exception:
        pass
    return result


def _tls_check(ip: str, port: int = 443, timeout: float = 3.0) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                result["subject"] = _cert_name(cert, "subject")
                result["issuer"] = _cert_name(cert, "issuer")
                result["not_before"] = cert.get("notBefore", "")
                result["not_after"] = cert.get("notAfter", "")
    except Exception:
        pass
    return result


def _cert_name(cert: dict[str, Any], field: str) -> str:
    for tup in cert.get(field, ()):
        for k, v in tup:
            if k == "commonName":
                return v
    return ""


# --- SSDP / UPnP ---


def _ssdp_discover(timeout: float = 3.0) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    msg = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 2\r\n"
        b"ST: ssdp:all\r\n"
        b"\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 1900))
        while True:
            try:
                data, _ = sock.recvfrom(4096)
                entry: dict[str, str] = {}
                for line in data.decode("utf-8", errors="replace").splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        entry[k.strip().upper()] = v.strip()
                if entry:
                    results.append(entry)
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return results


# --- SMB / NetBIOS ---


def _smb_check(ip: str, timeout: float = 3.0) -> dict[str, Any]:
    result: dict[str, Any] = {}
    nb = _which("nmblookup")
    if nb is None:
        return result
    try:
        proc = subprocess.run(
            [nb, "-A", ip], capture_output=True, text=True, check=False, timeout=timeout
        )
        for line in proc.stdout.splitlines():
            if "looking up status of" in line.lower():
                continue
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split("<")
            if len(parts) >= 2:
                name = parts[0].strip().lstrip("\t ")
                flags = "<" + "<".join(parts[1:])
                result.setdefault("names", []).append({"name": name, "flags": flags})
    except Exception:
        pass
    return result


# --- orchestration ---


def run_scan(db_path: str | None = None) -> dict[str, Any]:
    cfg = db.get_config(db_path)
    scan_range = cfg.get("scan_range", "").strip()
    if not scan_range:
        raise RuntimeError("config 'scan_range' is empty")
    interface = cfg.get("scan_interface", "").strip() or None

    raw = run_arp_scan(scan_range, interface)
    hosts = parse_arp_scan(raw)

    now = now_iso()
    new_devices: list[tuple[int, ArpHost]] = []
    for h in hosts:
        vendor = h.vendor or macvendor.vendor_for(h.mac)
        oui = macvendor.oui_prefix(h.mac)
        device_id, is_new = db.upsert_device(
            mac=h.mac,
            ip=h.ip,
            vendor=vendor,
            oui=oui,
            now_iso=now,
            db_path=db_path,
            scan_type="arp",
        )
        if is_new:
            new_devices.append((device_id, h))

    if new_devices and cfg.get("notify_on_new", "1") == "1":
        from . import notifications

        for device_id, h in new_devices:
            notifications.notify_new_device(
                device_id=device_id,
                ip=h.ip,
                mac=h.mac,
                vendor=h.vendor,
                db_path=db_path,
            )

    return {
        "total": len(hosts),
        "new": len(new_devices),
        "new_macs": [h.mac for _, h in new_devices],
        "timestamp": now,
    }


def run_detail_scan_for_all(db_path: str | None = None) -> dict[str, Any]:
    cfg = db.get_config(db_path)
    enabled = cfg.get("detail_interval_enabled", "1") == "1"
    if not enabled:
        return {"scanned": 0, "updated": 0, "timestamp": now_iso(), "skipped": "disabled"}

    hours = int(cfg.get("detail_scan_interval_hours", "6") or "6")
    dns_enabled = cfg.get("detail_dns_enabled", "1") == "1"
    mdns_enabled = cfg.get("detail_mdns_enabled", "1") == "1"
    ipv6_enabled = cfg.get("detail_ipv6_enabled", "1") == "1"
    http_tls_enabled = cfg.get("detail_http_tls_enabled", "1") == "1"
    upnp_enabled = cfg.get("detail_upnp_enabled", "1") == "1"
    smb_enabled = cfg.get("detail_smb_enabled", "1") == "1"

    now = now_iso()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=abs(hours))).isoformat(timespec="seconds")

    devices = db.all_devices(db_path)

    ipv6_map: dict[str, list[str]] = {}
    if ipv6_enabled:
        ipv6_map = _discover_ipv6_neighbors()

    ssdp_devices: list[dict[str, str]] = []
    if upnp_enabled:
        ssdp_devices = _ssdp_discover()

    updated = 0
    scanned = 0
    for d in devices:
        ip = d.get("ip_last")
        if not ip:
            continue

        last_scan = d.get("last_detail_scan")
        if last_scan and last_scan >= cutoff:
            continue
        scanned += 1

        nmap_result = run_nmap_detail(ip)

        dns_name: str | None = None
        mdns_name: str | None = None
        ipv6_json: str | None = None
        http_json: str | None = None
        tls_json: str | None = None
        network_info: dict[str, Any] = {}

        if dns_enabled:
            dns_name = _reverse_dns(ip)

        if mdns_enabled:
            mdns_name = _mdns_lookup(ip)

        if ipv6_enabled and d["mac"] in ipv6_map:
            ipv6_json = json.dumps(ipv6_map[d["mac"]])

        if http_tls_enabled:
            http_result = _http_check(ip)
            if http_result:
                http_json = json.dumps(http_result)
            tls_result = _tls_check(ip)
            if tls_result:
                tls_json = json.dumps(tls_result)

        if nmap_result:
            if nmap_result.http_info and not http_json:
                http_json = nmap_result.http_info
            if nmap_result.tls_info and not tls_json:
                tls_json = nmap_result.tls_info
            if nmap_result.network_info:
                network_info.update(json.loads(nmap_result.network_info))

        if smb_enabled:
            smb_result = _smb_check(ip)
            if smb_result:
                network_info["smb"] = network_info.get("smb", {})
                network_info["smb"].update(smb_result)

        if upnp_enabled:
            upnp_match = _match_ssdp_to_ip(ssdp_devices, ip)
            if upnp_match:
                network_info["upnp"] = network_info.get("upnp", {})
                network_info["upnp"].update(upnp_match)

        net_json = json.dumps(network_info) if network_info else None

        db.update_device_detail(
            device_id=d["id"],
            os_info=nmap_result.os_info if nmap_result else None,
            services=nmap_result.services if nmap_result else None,
            hostname=nmap_result.hostname if nmap_result else None,
            now_iso=now,
            dns_name=dns_name,
            mdns_name=mdns_name,
            ipv6_addresses=ipv6_json,
            http_info=http_json,
            tls_info=tls_json,
            network_info=net_json,
            db_path=db_path,
        )
        with db.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO scan_history(device_id, ts, scan_type, ip, raw) "
                "VALUES(?,?,?,?,?)",
                (d["id"], now, "detail", ip, None),
            )
        updated += 1

    # --- OPNsense sync ---
    opnsense_enabled = cfg.get("opnsense_enabled", "0") == "1"
    if opnsense_enabled:
        try:
            from . import opnsense as opn
            url = cfg.get("opnsense_url", "").strip()
            key = cfg.get("opnsense_api_key", "").strip()
            secret = cfg.get("opnsense_api_secret", "").strip()
            if url and key and secret:
                verify = cfg.get("opnsense_verify_tls", "1") == "1"
                tout = float(cfg.get("opnsense_timeout", "10") or "10")
                _sync_opnsense_data(url, key, secret, verify, tout, now, db_path)
                scanned += 1
        except Exception:
            pass

    external = sync_external_integrations(db_path)
    return {"scanned": scanned, "updated": updated, "external": external,
            "timestamp": now}


def sync_opnsense(db_path: str | None = None) -> int:
    """Fetch OPNsense hosts and fill missing device data. Returns count of synced devices."""
    cfg = db.get_config(db_path)
    enabled = cfg.get("opnsense_enabled", "0") == "1"
    if not enabled:
        return 0
    url = cfg.get("opnsense_url", "").strip()
    key = cfg.get("opnsense_api_key", "").strip()
    secret = cfg.get("opnsense_api_secret", "").strip()
    if not url or not key or not secret:
        return 0
    verify = cfg.get("opnsense_verify_tls", "1") == "1"
    tout = float(cfg.get("opnsense_timeout", "10") or "10")
    now = now_iso()
    return _sync_opnsense_data(url, key, secret, verify, tout, now, db_path)


def sync_external_integrations(db_path: str | None = None) -> dict[str, int]:
    """Synchronize enabled arpwatch, LibreNMS and Greenbone sources."""
    from . import integrations

    cfg = db.get_config(db_path)
    devices = db.all_devices(db_path)
    by_mac = {d["mac"]: d for d in devices if d.get("mac")}
    by_ip = {d["ip_last"]: d for d in devices if d.get("ip_last")}
    merged: dict[int, dict[str, Any]] = {}
    now = now_iso()
    counts = {"arpwatch": 0, "librenms": 0, "greenbone": 0}

    if cfg.get("arpwatch_enabled") == "1":
        for mac, data in integrations.read_arpwatch(cfg.get("arpwatch_path", "")).items():
            device = by_mac.get(mac)
            if device:
                merged.setdefault(device["id"], {})["arpwatch"] = data
                counts["arpwatch"] += 1

    if cfg.get("librenms_enabled") == "1":
        rows = integrations.fetch_librenms(
            cfg.get("librenms_url", ""), cfg.get("librenms_token", ""),
            cfg.get("librenms_verify_tls", "1") == "1",
            float(cfg.get("librenms_timeout", "10") or "10"),
        )
        for row in rows:
            ip = str(row.get("ip", row.get("ip_address", "")))
            device = by_ip.get(ip)
            if device:
                merged.setdefault(device["id"], {})["librenms"] = row
                counts["librenms"] += 1

    if cfg.get("greenbone_enabled") == "1":
        report = integrations.fetch_greenbone_report(
            cfg.get("greenbone_report_url", ""),
            cfg.get("greenbone_username", ""), cfg.get("greenbone_password", ""),
            cfg.get("greenbone_verify_tls", "1") == "1",
            float(cfg.get("greenbone_timeout", "30") or "30"),
        )
        # Generated reports often contain a host list; map those by IP.
        hosts = report.get("hosts", report.get("results", []))
        if isinstance(hosts, list):
            for row in hosts:
                if not isinstance(row, dict):
                    continue
                ip = str(row.get("ip", row.get("host", "")))
                device = by_ip.get(ip)
                if device:
                    merged.setdefault(device["id"], {})["greenbone"] = row
                    counts["greenbone"] += 1

    for device_id, info in merged.items():
        db.update_device_external(device_id, integrations.encode(info), now, db_path)
    return counts


def _sync_opnsense_data(
    url: str, key: str, secret: str, verify: bool, timeout: float,
    now: str, db_path: str | None,
) -> int:
    from . import opnsense as opn

    hosts = opn.fetch_static_hosts(url, key, secret, verify, timeout)
    devices = db.all_devices(db_path)
    mac_map: dict[str, int] = {d["mac"]: d["id"] for d in devices if d["mac"]}

    synced = 0
    for h in hosts:
        if not h.mac or h.mac not in mac_map:
            continue
        device_id = mac_map[h.mac]
        ipv4_json = json.dumps(h.ipv4) if h.ipv4 else None
        ipv6_json = json.dumps(h.ipv6) if h.ipv6 else None
        db.update_device_opnsense(
            device_id=device_id,
            hostname=h.hostname,
            ipv4=ipv4_json,
            ipv6=ipv6_json,
            description=h.description,
            now_iso=now,
            db_path=db_path,
        )
        synced += 1
    return synced


def _match_ssdp_to_ip(ssdp_list: list[dict[str, str]], ip: str) -> dict[str, Any] | None:
    for entry in ssdp_list:
        loc = entry.get("LOCATION", "")
        if ip in loc:
            return {
                "server": entry.get("SERVER", ""),
                "usn": entry.get("USN", ""),
                "st": entry.get("ST", ""),
                "location": loc,
            }
    return None


def _is_root() -> bool:
    return os.geteuid() == 0


def _which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for p in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
        cand = f"{p}/{name}"
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None
