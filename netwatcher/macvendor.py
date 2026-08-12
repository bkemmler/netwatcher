"""IEEE OUI vendor lookup with local caching."""
from __future__ import annotations

import csv
import io
import os
import time
from pathlib import Path

import requests

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def cache_dir() -> Path:
    d = Path(os.environ.get("NETWATCHER_CACHE_DIR", str(Path.home() / ".netwatcher" / "cache")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def cache_file() -> Path:
    return cache_dir() / "oui.csv"


def download_oui(force: bool = False) -> Path:
    """Download the IEEE OUI CSV if missing or stale.
    
    Format of the IEEE CSV (columns):
        registry,assignment,organizationName,organizationAddress
    """
    f = cache_file()
    if f.exists() and not force:
        return f
    resp = requests.get(OUI_URL, timeout=60)
    resp.raise_for_status()
    f.write_bytes(resp.content)
    return f


def _parse():
    """Parse cached OUI.csv into a dict {prefix: vendor}.

    The 'assignment' field is the MAC prefix like '00-00-00' (hex). Some rows
    are 'MA-L' / 'MA-M' / 'MA-S' registries with longer/masked prefixes - they
    can be safely ignored here for /24 mac lookup simplicity.
    """
    f = cache_file()
    if not f.exists():
        return {}
    prefix_map: dict[str, str] = {}
    with f.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            assignment = (row.get("assignment") or "").strip().upper()
            vendor = (row.get("organizationName") or row.get("Organization Name") or "").strip()
            if assignment and vendor:
                # normalize to plain AABBCC form
                plain = assignment.replace("-", "").replace(":", "").replace(".", "")
                prefix_map[plain] = vendor
    return prefix_map


_map: dict[str, str] | None = None


def _maybe_download():
    global _map
    if _map is not None:
        return
    if not cache_file().exists():
        try:
            download_oui()
        except Exception:
            _map = {}
            return
    _map = _parse()


def vendor_for(mac: str) -> str | None:
    """Return vendor name for a MAC address (any normalization)."""
    _maybe_download()
    if _map is None:
        return None
    plain = mac.replace("-", "").replace(":", "").replace(".", "").upper()
    if len(plain) < 6:
        return None
    return _map.get(plain[:6])


def oui_prefix(mac: str) -> str | None:
    plain = mac.replace("-", "").replace(":", "").replace(".", "").upper()
    if len(plain) < 6:
        return None
    return plain[:6]
