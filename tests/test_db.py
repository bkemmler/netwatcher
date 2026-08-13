"""Tests for db helpers using a temp sqlite database."""
from __future__ import annotations

import sqlite3

import bcrypt
import pytest

from netwatcher import db


def test_init_creates_tables(tmp_db):
    with db.connect(tmp_db) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
    assert {"devices", "scan_history", "config", "users"} <= tables


def test_default_config_loaded(tmp_db):
    cfg = db.get_config(tmp_db)
    assert cfg["scan_range"] == "192.168.1.0/24"
    assert cfg["notify_on_new"] == "1"


def test_new_config_keys_present(tmp_db):
    cfg = db.get_config(tmp_db)
    assert cfg.get("detail_scan_interval_hours") == "6"
    assert cfg.get("detail_dns_enabled") == "1"
    assert cfg.get("detail_http_tls_enabled") == "1"
    assert cfg.get("detail_smb_enabled") == "1"


def test_schema_v2_columns(tmp_db):
    with db.connect(tmp_db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
    for col in ("dns_name", "mdns_name", "ipv6_addresses",
                "http_info", "tls_info", "network_info"):
        assert col in cols, f"missing column: {col}"


def test_migration_v1_to_v2(tmp_db):
    with sqlite3.connect(tmp_db) as conn:
        conn.execute("PRAGMA user_version = 1")
        # remove v2 columns to simulate v1 schema
        for col in ("dns_name", "mdns_name", "ipv6_addresses",
                     "http_info", "tls_info", "network_info"):
            try:
                conn.execute(f"ALTER TABLE devices DROP COLUMN {col}")
            except sqlite3.OperationalError:
                pass
        conn.execute("DELETE FROM config WHERE key LIKE 'detail_%'")

    db.init_db(tmp_db)  # triggers migration
    cfg = db.get_config(tmp_db)
    assert cfg.get("detail_scan_interval_hours") == "6"
    with db.connect(tmp_db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
        assert "dns_name" in cols
        assert "opnsense_hostname" in cols
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == 4


def test_migration_v2_to_v3(tmp_db):
    with sqlite3.connect(tmp_db) as conn:
        conn.execute("PRAGMA user_version = 2")
        for col in ("opnsense_hostname", "opnsense_ipv4", "opnsense_ipv6",
                     "opnsense_description", "opnsense_last_sync"):
            try:
                conn.execute(f"ALTER TABLE devices DROP COLUMN {col}")
            except sqlite3.OperationalError:
                pass
        conn.execute("DELETE FROM config WHERE key LIKE 'opnsense_%'")

    db.init_db(tmp_db)
    cfg = db.get_config(tmp_db)
    assert cfg.get("opnsense_enabled") == "0"
    assert cfg.get("opnsense_url") == ""
    with db.connect(tmp_db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
        assert "opnsense_hostname" in cols
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        assert ver == 4


def test_schema_v4_external_columns(tmp_db):
    with db.connect(tmp_db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
        assert {"external_info", "external_last_sync"} <= cols


def test_upsert_device_new_and_existing(tmp_db):
    is_new_pair = db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5",
        vendor="X", oui="AABBCC", now_iso="2024-01-01T00:00:00",
        db_path=tmp_db, insert_history=False,
    )
    assert is_new_pair[1] is True
    res2 = db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9",
        vendor=None, oui=None, now_iso="2024-01-02T00:00:00",
        db_path=tmp_db, insert_history=False,
    )
    assert res2[1] is False
    dev = db.list_devices(db_path=tmp_db)[0][0]
    assert dev["ip_last"] == "10.0.0.9"
    assert dev["vendor"] == "X"


def test_update_device_detail_new_fields(tmp_db):
    db.upsert_device(
        "aa:bb:cc:dd:ee:ff", "10.0.0.5", "V", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False,
    )
    dev = db.list_devices(db_path=tmp_db)[0][0]
    db.update_device_detail(
        dev["id"], os_info='[{"name":"Linux"}]', services='[{"port":22}]',
        hostname="test", now_iso="2024-01-02T00:00:00",
        dns_name="host.local", mdns_name="host.local",
        ipv6_addresses='["fe80::1"]',
        http_info='{"title":"Hi"}', tls_info='{"subject":"CN=hi"}',
        network_info='{"smb":{"names":[]}}',
        db_path=tmp_db,
    )
    dev2 = db.get_device(dev["id"], tmp_db)
    assert dev2["dns_name"] == "host.local"
    assert dev2["mdns_name"] == "host.local"
    assert dev2["ipv6_addresses"] == '["fe80::1"]'
    assert dev2["http_info"] == '{"title":"Hi"}'
    assert dev2["tls_info"] == '{"subject":"CN=hi"}'
    assert "smb" in dev2["network_info"]


def test_add_and_get_user(tmp_db):
    pw = bcrypt.hashpw(b"secret", bcrypt.gensalt()).decode()
    db.add_user("admin", pw, tmp_db)
    user = db.get_user("admin", tmp_db)
    assert user is not None
    assert bcrypt.checkpw(b"secret", user["pw_hash"].encode())
    assert db.get_user("nope", tmp_db) is None


def test_list_devices_filter_known(tmp_db):
    db.upsert_device("aa:bb:cc:dd:ee:01", "10.0.0.1", "v", "o",
                     "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False)
    db.upsert_device("aa:bb:cc:dd:ee:02", "10.0.0.2", "v", "o",
                     "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False)
    devices, _ = db.list_devices(db_path=tmp_db)
    db.update_device_meta(devices[0]["id"], "n", None, 1, db_path=tmp_db)
    known, total_known = db.list_devices(known_only=True, db_path=tmp_db)
    unknown, total_unknown = db.list_devices(known_only=False, db_path=tmp_db)
    assert total_known == 1
    assert total_unknown == 1


def test_device_history_returns_first_and_recent(tmp_db):
    dev_id, _ = db.upsert_device(
        "aa:bb:cc:dd:ee:ff", "10.0.0.1", "V", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=True, scan_type="arp",
    )
    for i in range(2, 12):
        with db.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO scan_history(device_id, ts, scan_type, ip) VALUES(?,?,?,?)",
                (dev_id, f"2024-01-{i:02d}T00:00:00", "arp", f"10.0.0.{i}"),
            )
    history = db.device_history(dev_id, limit=5, db_path=tmp_db)
    # first entry + up to 5 recent, sorted desc
    ids = [h["id"] for h in history]
    assert len(ids) == 6  # 1 first + 5 recent
    assert ids[0] > ids[1]  # first entry (most recent by ts desc)
    # first entry should be the oldest ID
    first_entry_id = db.device_history(dev_id, limit=1, db_path=tmp_db)
    # the very first scan (ID 1 from upsert) should be somewhere in the result
    first_ids = [h["id"] for h in history]
    assert any(h["ip"] == "10.0.0.1" for h in history)


def test_device_history_dedup_first(tmp_db):
    dev_id, _ = db.upsert_device(
        "aa:bb:cc:dd:ee:ff", "10.0.0.1", "V", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=True, scan_type="arp",
    )
    # only one entry — first==last
    history = db.device_history(dev_id, limit=5, db_path=tmp_db)
    assert len(history) == 1


def test_cleanup_old_history(tmp_db, monkeypatch):
    from datetime import datetime, timedelta, timezone

    # Use yesterday as the "target" date
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")

    dev_id, _ = db.upsert_device(
        "aa:bb:cc:dd:ee:ff", "10.0.0.1", "V", "O",
        f"{yesterday}T08:00:00", db_path=tmp_db, insert_history=True, scan_type="arp",
    )
    with db.connect(tmp_db) as conn:
        conn.execute(
            "INSERT INTO scan_history(device_id, ts, scan_type, ip) VALUES(?,?,?,?)",
            (dev_id, f"{yesterday}T09:00:00", "arp", "10.0.0.2"),
        )
        conn.execute(
            "INSERT INTO scan_history(device_id, ts, scan_type, ip) VALUES(?,?,?,?)",
            (dev_id, f"{yesterday}T10:00:00", "arp", "10.0.0.3"),
        )

    deleted = db.cleanup_old_history(tmp_db)
    assert deleted == 2  # the two later entries deleted, first kept

    history = db.device_history(dev_id, db_path=tmp_db)
    assert len(history) == 1  # only first remains
    assert history[0]["ip"] == "10.0.0.1"


def test_update_device_opnsense(tmp_db):
    dev_id, _ = db.upsert_device(
        "aa:bb:cc:dd:ee:ff", "10.0.0.5", "V", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False,
    )
    db.update_device_opnsense(
        dev_id, hostname="opnsense-host", ipv4='["10.0.0.10"]',
        ipv6='["fe80::1"]', description="Testgerät",
        now_iso="2024-01-02T00:00:00", db_path=tmp_db,
    )
    dev = db.get_device(dev_id, tmp_db)
    assert dev["opnsense_hostname"] == "opnsense-host"
    assert dev["opnsense_ipv4"] == '["10.0.0.10"]'
    assert dev["opnsense_ipv6"] == '["fe80::1"]'
    assert dev["opnsense_description"] == "Testgerät"
    assert dev["opnsense_last_sync"] == "2024-01-02T00:00:00"
    # hostname is empty in device initially, should be filled
    assert dev["hostname"] == "opnsense-host"
    # name should also be filled from OPNsense hostname
    assert dev["name"] == "opnsense-host"


def test_list_devices_sorts_ipv4_numerically(tmp_db):
    for last_octet in (1, 10, 2):
        db.upsert_device(
            f"aa:bb:cc:dd:ee:{last_octet:02x}",
            f"10.10.10.{last_octet}", "V", "O", "2024-01-01T00:00:00",
            db_path=tmp_db, insert_history=False,
        )

    ascending, _ = db.list_devices(sort="ip_last", sort_dir="asc", page_size=20, db_path=tmp_db)
    descending, _ = db.list_devices(sort="ip_last", sort_dir="desc", page_size=20, db_path=tmp_db)
    assert [d["ip_last"] for d in ascending] == [
        "10.10.10.1", "10.10.10.2", "10.10.10.10"
    ]
    assert [d["ip_last"] for d in descending] == [
        "10.10.10.10", "10.10.10.2", "10.10.10.1"
    ]
