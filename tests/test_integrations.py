from pathlib import Path

from netwatcher.integrations import read_arpwatch


def test_read_arpwatch(tmp_path: Path):
    path = tmp_path / "arp.dat"
    path.write_text("192.168.1.20 aa-bb-cc-dd-ee-ff 1700000000 printer\n")
    data = read_arpwatch(str(path))
    assert data["aa:bb:cc:dd:ee:ff"]["ip"] == "192.168.1.20"
    assert data["aa:bb:cc:dd:ee:ff"]["hostname"] == "printer"
