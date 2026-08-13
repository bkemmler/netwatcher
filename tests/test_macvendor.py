from pathlib import Path

from netwatcher import macvendor


def test_parse_ieee_csv_header_variants(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "oui.csv").write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,AA-BB-CC,Example Devices,Address\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NETWATCHER_CACHE_DIR", str(cache))
    monkeypatch.setattr(macvendor, "_map", None)

    assert macvendor.vendor_for("aa:bb:cc:11:22:33") == "Example Devices"


def test_parse_ieee_csv_lowercase_header(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "oui.csv").write_text(
        "registry,assignment,organizationName,organizationAddress\n"
        "MA-L,11-22-33,Another Vendor,Address\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NETWATCHER_CACHE_DIR", str(cache))
    monkeypatch.setattr(macvendor, "_map", None)

    assert macvendor.vendor_for("11:22:33:44:55:66") == "Another Vendor"
