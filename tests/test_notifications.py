"""Tests for notifications.send mocking the gotify HTTP endpoint."""
from __future__ import annotations

import importlib
from unittest.mock import patch


def test_send_no_config(tmp_db, caplog):
    from netwatcher import notifications

    importlib.reload(notifications)
    notifications.send("t", "m", db_path=tmp_db)
    # Should not raise, should silently skip (gotify_url empty)


def test_send_calls_requests_post(tmp_db, monkeypatch):
    from netwatcher import db, notifications

    importlib.reload(notifications)
    db.set_config("gotify_url", "https://gotify.example.com", tmp_db)
    db.set_config("gotify_token", "tok123", tmp_db)

    called = {}

    class FakeResp:
        def raise_for_status(self): return None

    def fake_post(url, data=None, timeout=None):
        called["url"] = url
        called["data"] = data
        return FakeResp()

    monkeypatch.setattr(notifications.requests, "post", fake_post)
    ok = notifications.send("Title", "Body", priority=3, db_path=tmp_db)
    assert ok is True
    assert "tok123" in called["url"]
    assert called["data"]["title"] == "Title"


# uses tmp_db fixture from conftest.py