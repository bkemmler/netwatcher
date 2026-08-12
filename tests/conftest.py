"""Shared pytest fixtures."""
from __future__ import annotations

import bcrypt
import pytest

from netwatcher import db
from netwatcher.web.app import create_app


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    path = tmp_path / "nw.db"
    monkeypatch.setenv("NETWATCHER_DB", str(path))
    db.init_db(str(path))
    return str(path)


@pytest.fixture()
def app(tmp_db):
    app = create_app()
    app.config["TESTING"] = True
    pw = bcrypt.hashpw(b"testpw", bcrypt.gensalt()).decode()
    db.add_user("admin", pw, tmp_db)
    return app


@pytest.fixture()
def client(app):
    with app.test_client() as c:
        c.post("/login", data={"username": "admin", "password": "testpw"})
        yield c