"""Web-UI tests (Flask test client)."""
from __future__ import annotations

from netwatcher import db


def test_login_page(client):
    resp = client.get("/login")
    assert resp.status_code == 200


def test_devices_page_requires_login(app):
    with app.test_client() as c:
        resp = c.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_devices_page_authenticated(client, tmp_db):
    db.upsert_device(
        "aa:bb:cc:dd:ee:01", "10.0.0.1", "Vend", "AABBCC",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False,
    )
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"aa:bb:cc:dd:ee:01" in resp.data


def test_bulk_update(tmp_db, client):
    db.upsert_device(
        "aa:bb:cc:dd:ee:01", "10.0.0.1", "V", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False,
    )
    db.upsert_device(
        "aa:bb:cc:dd:ee:02", "10.0.0.2", "V", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False,
    )
    devices, _ = db.list_devices(db_path=tmp_db)
    d1, d2 = devices[0]["id"], devices[1]["id"]

    resp = client.post("/devices/bulk-update", data={
        f"name_{d1}": "Gerät 1",
        f"known_{d1}": "1",
        f"notes_{d1}": "Notiz 1",
        f"name_{d2}": "Gerät 2",
        f"known_{d2}": "0",
        f"notes_{d2}": "",
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"2 Ger" in resp.data

    dev1 = db.get_device(d1, tmp_db)
    dev2 = db.get_device(d2, tmp_db)
    assert dev1["name"] == "Gerät 1"
    assert dev1["known"] == 1
    assert dev1["notes"] == "Notiz 1"
    assert dev2["name"] == "Gerät 2"
    assert dev2["known"] == 0
    assert dev2["notes"] is None


def test_bulk_update_preserves_search_params(tmp_db, client):
    db.upsert_device(
        "aa:bb:cc:dd:ee:01", "10.0.0.1", "V", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False,
    )
    devices, _ = db.list_devices(db_path=tmp_db)
    d1 = devices[0]["id"]

    resp = client.post("/devices/bulk-update", data={
        f"name_{d1}": "X",
        "q": "test",
        "known": "1",
        "sort": "mac",
        "dir": "asc",
        "page": "3",
    })
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    assert "q=test" in loc
    assert "known=1" in loc
    assert "sort=mac" in loc
    assert "dir=asc" in loc
    assert "page=3" in loc


def test_cleanup_history_endpoint(client):
    resp = client.post("/config/cleanup-history", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Verlaufsbereinigung" in resp.data or b"bereinigt" in resp.data or b"Bereinigung" in resp.data


def test_config_page_shows_cleanup_section(client):
    resp = client.get("/config")
    assert resp.status_code == 200
    assert b"Verlauf bereinigen" in resp.data


def test_config_page_shows_opnsense_section(client):
    resp = client.get("/config")
    assert resp.status_code == 200
    assert b"OPNsense" in resp.data


def test_manufacturers_page_and_vendor_filter(client, tmp_db):
    db.upsert_device(
        "aa:bb:cc:dd:ff:01", "10.0.0.1", "Vendor A", "O",
        "2024-01-01T00:00:00", db_path=tmp_db, insert_history=False,
    )
    response = client.get("/manufacturers")
    assert response.status_code == 200
    assert b"Vendor A" in response.data
    response = client.get("/?vendor=Vendor%20A")
    assert response.status_code == 200
    assert b"10.0.0.1" in response.data


def test_opnsense_sync_endpoint(client):
    resp = client.post("/config/opnsense-sync", follow_redirects=True)
    assert resp.status_code == 200
