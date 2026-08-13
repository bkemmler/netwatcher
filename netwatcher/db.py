"""SQLite layer: schema initialization, migrations, access helpers."""
from __future__ import annotations

import sqlite3
import json
import ipaddress
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 4

DEFAULT_CONFIG = {
    "scan_range": "192.168.1.0/24",
    "scan_interface": "",
    "scan_interval_seconds": "300",
    "detail_interval_enabled": "1",
    "detail_scan_interval_hours": "6",
    "detail_dns_enabled": "1",
    "detail_mdns_enabled": "1",
    "detail_ipv6_enabled": "1",
    "detail_http_tls_enabled": "1",
    "detail_upnp_enabled": "1",
    "detail_smb_enabled": "1",
    "notify_on_new": "1",
    "gotify_url": "",
    "gotify_token": "",
    "web_bind_host": "0.0.0.0",
    "web_bind_port": "5000",
    "oui_refresh_days": "30",
    "date_format": "de",
    "timezone": "Europe/Berlin",
    "opnsense_enabled": "0",
    "opnsense_url": "",
    "opnsense_api_key": "",
    "opnsense_api_secret": "",
    "opnsense_verify_tls": "1",
    "opnsense_timeout": "10",
    "arpwatch_enabled": "0",
    "arpwatch_path": "/var/lib/arpwatch/arp.dat",
    "librenms_enabled": "0",
    "librenms_url": "",
    "librenms_token": "",
    "librenms_verify_tls": "1",
    "librenms_timeout": "10",
    "greenbone_enabled": "0",
    "greenbone_report_url": "",
    "greenbone_username": "",
    "greenbone_password": "",
    "greenbone_verify_tls": "1",
    "greenbone_timeout": "30",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    mac TEXT UNIQUE NOT NULL,
    ip_last TEXT,
    hostname TEXT,
    vendor TEXT,
    oui TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    name TEXT,
    notes TEXT,
    known INTEGER DEFAULT 0,
    os_info TEXT,
    services TEXT,
    dns_name TEXT,
    mdns_name TEXT,
    ipv6_addresses TEXT,
    http_info TEXT,
    tls_info TEXT,
    network_info TEXT,
    opnsense_hostname TEXT,
    opnsense_ipv4 TEXT,
    opnsense_ipv6 TEXT,
    opnsense_description TEXT,
    opnsense_last_sync TEXT,
    external_info TEXT,
    external_last_sync TEXT,
    last_detail_scan TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    scan_type TEXT,
    ip TEXT,
    raw TEXT
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_known ON devices(known);
CREATE INDEX IF NOT EXISTS idx_history_device ON scan_history(device_id);
CREATE INDEX IF NOT EXISTS idx_history_ts ON scan_history(ts);
"""

_V2_MIGRATIONS = [
    "ALTER TABLE devices ADD COLUMN dns_name TEXT",
    "ALTER TABLE devices ADD COLUMN mdns_name TEXT",
    "ALTER TABLE devices ADD COLUMN ipv6_addresses TEXT",
    "ALTER TABLE devices ADD COLUMN http_info TEXT",
    "ALTER TABLE devices ADD COLUMN tls_info TEXT",
    "ALTER TABLE devices ADD COLUMN network_info TEXT",
]

_V3_MIGRATIONS = [
    "ALTER TABLE devices ADD COLUMN opnsense_hostname TEXT",
    "ALTER TABLE devices ADD COLUMN opnsense_ipv4 TEXT",
    "ALTER TABLE devices ADD COLUMN opnsense_ipv6 TEXT",
    "ALTER TABLE devices ADD COLUMN opnsense_description TEXT",
    "ALTER TABLE devices ADD COLUMN opnsense_last_sync TEXT",
]

_V4_MIGRATIONS = [
    "ALTER TABLE devices ADD COLUMN external_info TEXT",
    "ALTER TABLE devices ADD COLUMN external_last_sync TEXT",
]


def get_db_path(override: str | None = None) -> Path:
    if override:
        return Path(override)
    import os

    env = os.environ.get("NETWATCHER_DB")
    if env:
        return Path(env)
    return Path.home() / ".netwatcher" / "netwatcher.db"


def _migrate(conn: sqlite3.Connection, target: int) -> None:
    cur_ver = conn.execute("PRAGMA user_version").fetchone()[0]
    if cur_ver < 2 and target >= 2:
        for sql in _V2_MIGRATIONS:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass
        conn.execute("PRAGMA user_version = 2")
        cur_ver = 2
    if cur_ver < 3 and target >= 3:
        for sql in _V3_MIGRATIONS:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass
        conn.execute("PRAGMA user_version = 3")
        cur_ver = 3
    if cur_ver < 4 and target >= 4:
        for sql in _V4_MIGRATIONS:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass
        conn.execute("PRAGMA user_version = 4")


def init_db(db_path: str | None = None) -> Path:
    path = get_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(_SCHEMA)
        for k, v in DEFAULT_CONFIG.items():
            conn.execute(
                "INSERT INTO config(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO NOTHING",
                (k, v),
            )
        _migrate(conn, SCHEMA_VERSION)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return path


@contextmanager
def connect(db_path: str | None = None) -> Iterable[sqlite3.Connection]:
    path = get_db_path(db_path)
    if not path.exists():
        init_db(str(path))
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# --- config helpers ---


def get_config(db_path: str | None = None) -> dict[str, str]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM config").fetchall()
    return {r["key"]: r["value"] for r in rows}


def set_config(key: str, value: str, db_path: str | None = None) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO config(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


# --- users ---


def add_user(username: str, pw_hash: str, db_path: str | None = None) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users(username, pw_hash) VALUES(?, ?)",
            (username, pw_hash),
        )


def get_user(username: str, db_path: str | None = None) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


# --- devices ---


def upsert_device(
    mac: str,
    ip: str,
    vendor: str | None,
    oui: str | None,
    now_iso: str,
    hostname: str | None = None,
    db_path: str | None = None,
    insert_history: bool = True,
    scan_type: str = "arp",
) -> tuple[int, bool]:
    """Insert or update a device. Returns (device_id, is_new)."""
    with connect(db_path) as conn:
        cur = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,))
        existing = cur.fetchone()
        if existing:
            device_id = existing["id"]
            conn.execute(
                "UPDATE devices SET ip_last=?, hostname=COALESCE(?, hostname), "
                "vendor=COALESCE(?, vendor), oui=COALESCE(?, oui), last_seen=? "
                "WHERE id=?",
                (ip, hostname, vendor, oui, now_iso, device_id),
            )
            is_new = False
        else:
            cur = conn.execute(
                "INSERT INTO devices(mac, ip_last, hostname, vendor, oui, "
                "first_seen, last_seen) VALUES(?,?,?,?,?,?,?)",
                (mac, ip, hostname, vendor, oui, now_iso, now_iso),
            )
            device_id = cur.lastrowid
            is_new = True
        if insert_history:
            conn.execute(
                "INSERT INTO scan_history(device_id, ts, scan_type, ip, raw) "
                "VALUES(?,?,?,?,?)",
                (device_id, now_iso, scan_type, ip, None),
            )
        return device_id, is_new


def _col_coalesce(row: sqlite3.Row, *names: str) -> str | None:
    for name in names:
        try:
            v = row[name]
            if v:
                return v
        except (KeyError, IndexError):
            continue
    return None


def update_device_detail(
    device_id: int,
    os_info: str | None,
    services: str | None,
    hostname: str | None,
    now_iso: str,
    dns_name: str | None = None,
    mdns_name: str | None = None,
    ipv6_addresses: str | None = None,
    http_info: str | None = None,
    tls_info: str | None = None,
    network_info: str | None = None,
    db_path: str | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE devices SET os_info=?, services=?, hostname=COALESCE(?, hostname), "
            "dns_name=COALESCE(?, dns_name), mdns_name=COALESCE(?, mdns_name), "
            "ipv6_addresses=COALESCE(?, ipv6_addresses), "
            "http_info=COALESCE(?, http_info), tls_info=COALESCE(?, tls_info), "
            "network_info=COALESCE(?, network_info), last_detail_scan=? "
            "WHERE id=?",
            (
                os_info, services, hostname,
                dns_name, mdns_name, ipv6_addresses,
                http_info, tls_info, network_info,
                now_iso, device_id,
            ),
        )


def update_device_opnsense(
    device_id: int,
    hostname: str | None,
    ipv4: str | None,
    ipv6: str | None,
    description: str | None,
    now_iso: str,
    db_path: str | None = None,
) -> None:
    """Fill missing device fields from OPNsense data (never overwrite existing)."""
    with connect(db_path) as conn:
        existing = conn.execute(
            "SELECT opnsense_ipv4, opnsense_ipv6 FROM devices WHERE id=?",
            (device_id,),
        ).fetchone()

        def merge_addresses(old: str | None, new: str | None) -> str | None:
            values: list[str] = []
            for raw in (old, new):
                if not raw:
                    continue
                try:
                    parsed = json.loads(raw)
                    values.extend(parsed if isinstance(parsed, list) else [str(parsed)])
                except (json.JSONDecodeError, TypeError):
                    values.append(raw)
            return json.dumps(list(dict.fromkeys(values))) if values else None

        merged_ipv4 = merge_addresses(existing["opnsense_ipv4"] if existing else None, ipv4)
        merged_ipv6 = merge_addresses(existing["opnsense_ipv6"] if existing else None, ipv6)
        conn.execute(
            "UPDATE devices SET "
            "opnsense_hostname=?, opnsense_ipv4=?, opnsense_ipv6=?, "
            "opnsense_description=?, opnsense_last_sync=? "
            "WHERE id=?",
            (hostname, merged_ipv4, merged_ipv6, description, now_iso, device_id),
        )
        # Only fill hostname and name if not already set
        conn.execute(
            "UPDATE devices SET hostname=? WHERE id=? AND (hostname IS NULL OR hostname='')",
            (hostname, device_id),
        )
        conn.execute(
            "UPDATE devices SET name=? WHERE id=? AND (name IS NULL OR name='')",
            (hostname, device_id),
        )


def update_device_external(device_id: int, info: str | None,
                           now_iso: str, db_path: str | None = None) -> None:
    with connect(db_path) as conn:
        existing = conn.execute(
            "SELECT external_info FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        merged: dict[str, Any] = {}
        if existing and existing["external_info"]:
            try:
                old = json.loads(existing["external_info"])
                if isinstance(old, dict):
                    merged.update(old)
            except (json.JSONDecodeError, TypeError):
                pass
        if info:
            try:
                new = json.loads(info)
                if isinstance(new, dict):
                    merged.update(new)
            except (json.JSONDecodeError, TypeError):
                pass
        conn.execute(
            "UPDATE devices SET external_info=?, external_last_sync=? WHERE id=?",
            (json.dumps(merged, ensure_ascii=False) if merged else None, now_iso, device_id),
        )


def list_devices(
    search: str | None = None,
    known_only: bool | None = None,
    vendor_filter: str | None = None,
    sort: str = "last_seen",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
    db_path: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    allowed_sorts = {
        "last_seen",
        "first_seen",
        "mac",
        "ip_last",
        "hostname",
        "vendor",
        "name",
    }
    if sort not in allowed_sorts:
        sort = "last_seen"
    sort_dir = "desc" if sort_dir.lower() != "asc" else "asc"

    where = []
    params: list[Any] = []
    if search:
        where.append(
            "(mac LIKE ? OR ip_last LIKE ? OR hostname LIKE ? OR vendor LIKE ? "
            "OR name LIKE ?)"
        )
        like = f"%{search}%"
        params += [like] * 5
    if known_only is True:
        where.append("known = 1")
    elif known_only is False:
        where.append("known = 0")
    if vendor_filter:
        if vendor_filter == "Unbekannt":
            where.append("(vendor IS NULL OR vendor='')")
        else:
            where.append("vendor = ?")
            params.append(vendor_filter)
    clause = (" WHERE " + " AND ".join(where)) if where else ""

    with connect(db_path) as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM devices{clause}", params
        ).fetchone()["c"]
        if sort == "ip_last":
            all_rows = [dict(r) for r in conn.execute(
                f"SELECT * FROM devices{clause}", params
            ).fetchall()]

            def ip_key(row: dict[str, Any]) -> int | None:
                try:
                    return int(ipaddress.IPv4Address(row.get("ip_last", "")))
                except (ipaddress.AddressValueError, TypeError, ValueError):
                    return None

            valid = [row for row in all_rows if ip_key(row) is not None]
            invalid = [row for row in all_rows if ip_key(row) is None]
            valid.sort(key=lambda row: ip_key(row), reverse=sort_dir == "desc")
            ordered = valid + invalid
            offset = (page - 1) * page_size
            return ordered[offset:offset + page_size], total

        offset = (page - 1) * page_size
        rows = conn.execute(
            f"SELECT * FROM devices{clause} ORDER BY {sort} {sort_dir} "
            f"LIMIT ? OFFSET ?",
            params + [page_size, offset],
        ).fetchall()
    return [dict(r) for r in rows], total


def list_manufacturers(
    search: str | None = None,
    sort: str = "vendor",
    sort_dir: str = "asc",
    db_path: str | None = None,
) -> list[dict[str, Any]]:
    """Return manufacturer names and device counts."""
    if sort not in {"vendor", "count"}:
        sort = "vendor"
    direction = "DESC" if sort_dir.lower() == "desc" else "ASC"
    vendor_expr = "CASE WHEN vendor IS NULL OR vendor='' THEN 'Unbekannt' ELSE vendor END"
    params: list[Any] = []
    where = ""
    if search:
        where = f"WHERE {vendor_expr} LIKE ?"
        params.append(f"%{search}%")
    order = "vendor" if sort == "vendor" else "device_count"
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT {vendor_expr} AS vendor, COUNT(*) AS device_count "
            f"FROM devices {where} GROUP BY {vendor_expr} "
            f"ORDER BY {order} {direction}, vendor ASC",
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_device(
    device_id: int, db_path: str | None = None
) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    return dict(row) if row else None


def device_history(
    device_id: int, limit: int = 5, db_path: str | None = None
) -> list[dict[str, Any]]:
    """Return first scan + last N entries for a device (merged, no dups)."""
    with connect(db_path) as conn:
        first = conn.execute(
            "SELECT * FROM scan_history WHERE device_id=? ORDER BY ts ASC LIMIT 1",
            (device_id,),
        ).fetchone()
        recent = conn.execute(
            "SELECT * FROM scan_history WHERE device_id=? ORDER BY ts DESC LIMIT ?",
            (device_id, limit),
        ).fetchall()
    result: list[dict[str, Any]] = []
    if first:
        result.append(dict(first))
    for r in recent:
        rd = dict(r)
        if rd["id"] != result[0]["id"] if result else True:
            result.append(rd)
    result.sort(key=lambda x: x["ts"], reverse=True)
    return result


def cleanup_old_history(db_path: str | None = None) -> int:
    """Delete yesterday's history entries except the very first scan per device.

    Returns number of deleted rows.
    """
    from datetime import datetime, timedelta, timezone

    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    deleted = 0
    with connect(db_path) as conn:
        devices = conn.execute("SELECT id FROM devices").fetchall()
        for d in devices:
            first = conn.execute(
                "SELECT id FROM scan_history WHERE device_id=? ORDER BY ts ASC LIMIT 1",
                (d["id"],),
            ).fetchone()
            first_id = first["id"] if first else None
            if first_id is None:
                continue
            cur = conn.execute(
                "DELETE FROM scan_history WHERE device_id=? AND ts LIKE ? AND id != ?",
                (d["id"], f"{yesterday}%", first_id),
            )
            deleted += cur.rowcount
    return deleted


def update_device_meta(
    device_id: int,
    name: str | None,
    notes: str | None,
    known: int | None,
    db_path: str | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE devices SET name=?, notes=?, known=? WHERE id=?",
            (name, notes, known, device_id),
        )


def all_devices(db_path: str | None = None) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM devices").fetchall()
    return [dict(r) for r in rows]


def devices_by_macs(macs: list[str], db_path: str | None = None) -> dict[str, dict]:
    if not macs:
        return {}
    placeholders = ",".join("?" * len(macs))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM devices WHERE mac IN ({placeholders})", macs
        ).fetchall()
    return {r["mac"]: dict(r) for r in rows}
