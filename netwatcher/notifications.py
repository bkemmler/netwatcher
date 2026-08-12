"""Gotify notification delivery."""
from __future__ import annotations

import logging
from typing import Any

import requests

from . import db

log = logging.getLogger(__name__)


def _gotify_settings(db_path: str | None = None) -> tuple[str, str]:
    cfg = db.get_config(db_path)
    url = cfg.get("gotify_url", "").strip().rstrip("/")
    token = cfg.get("gotify_token", "").strip()
    return url, token


def is_configured(db_path: str | None = None) -> bool:
    url, token = _gotify_settings(db_path)
    return bool(url and token)


def send(
    title: str,
    message: str,
    priority: int = 4,
    db_path: str | None = None,
) -> bool:
    """Send a message to Gotify. Returns True on success."""
    url, token = _gotify_settings(db_path)
    if not url or not token:
        log.info("gotify not configured - skipping notification: %s", title)
        return False
    endpoint = f"{url}/message?token={token}"
    try:
        resp = requests.post(
            endpoint,
            data={"title": title, "message": message, "priority": priority},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except Exception as exc:
        log.warning("gotify request failed: %s", exc)
        return False


def notify_new_device(
    device_id: int,
    ip: str,
    mac: str,
    vendor: str | None,
    db_path: str | None = None,
) -> bool:
    vendor_txt = vendor or "unbekannt"
    msg = (
        f"Neues Gerät im Netzwerk entdeckt:\n\n"
        f"IP: {ip}\n"
        f"MAC: {mac}\n"
        f"Hersteller: {vendor_txt}\n"
    )
    return send(
        title="Netwatcher – neues Gerät",
        message=msg,
        priority=5,
        db_path=db_path,
    )