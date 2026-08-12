# AGENTS.md - Netwatcher

## Architektur

Python-Paket `netwatcher/` mit drei Betriebsmodi über `python -m netwatcher <cmd>`:

- `scan` — arp-Scan (schnelle Erkennung), getriggert durch `netwatcher-scan.timer` (5 Min)
- `detail-scan` — nmap-OS/Service-Scan für alle bekannten Geräte, getriggert durch `netwatcher-detail.timer` (1 Std)
- `serve` — Flask-Web-UI (dev-only); produktiv via gunicorn (`netwatcher-web.service`)

Web-UI ist die Flask-App in `netwatcher/web/app.py` mit Jinja2-Templates in
`netwatcher/web/templates/`. Sie nutzt Bootstrap 5 via CDN (kein Build-Schritt).

## Wichtige Konventionen

- **DB-Speicherort** wird über `NETWATCHER_DB` (Umgebungsvariable) gesetzt. Default
  ist `~/.netwatcher/netwatcher.db`. Tests überschreiben via pytest-fixture in
  `tests/conftest.py`. Beim Editieren von DB-Helpers immer mit `db_path`-Parameter
  umgehen — niemals hardkodiert.
- **Commit-Verhalten**: Der Context-Manager `db.connect()` committed beim Verlassen
  automatisch. Beim Hinzufügen neuer Writer-Funktionen **kein** explizites `commit()`
  nötig — aber die Funktion muss `with connect(db_path) as conn:` verwenden.
- **MAC-Normalisierung**: MACs intern lowercase. Parser liefern via
  `ArpHost.mac=mak.lower()`. Zentrale Normalisierung, nicht doppelt implementieren.
- **OUI-Vendor-Lookup**: in `macvendor.py` mit Indexed-Cache. IEEE-CSV wird
  lazy geladen (`_maybe_download`). Wenn Download fehlschlägt → leerer Cache,
  Parser fällt auf `arp-scan`-Vendor zurück.

## Testen

```sh
.venv/bin/python -m pytest tests/ -v
```

Tests sind vollständig offline: ARP-/nmap-Parser testen gegen Fixtures in
`tests/fixtures/`, Gotify-Endpoint wird gemockt. Web-UI-Smoke-Test:
`app.test_client()` verwenden.

## LXC/Proxmox-Gotcha

`arp-scan` braucht **`CAP_NET_RAW`**. Im Proxmox unprivileged Container muss
das in `/etc/pve/lxc/CTID.conf` erlaubt sein (kein Drop von `cap_net_raw`).
Sonst schlagen Scans fehl — siehe README. Dieses Repo passt die LXC-Config
nicht an.
- **Scan-Units** laufen absichtlich als `root`, weil `arp-scan` und nmap
  `CAP_NET_RAW` benötigen. Der Python-Scanner verwendet `sudo` nur bei
  manuellen nicht-root CLI-Aufrufen; `NoNewPrivileges=true` kann in den
  systemd-Units aktiv bleiben.

## Sonstiges

- **systemd-Units** in `scripts/` enthalten Platzhalter (`__NETWATCHER_USER__`
  etc.). Installationsanleitung im README. Templates **nicht** direkt
  bearbeiten mit Werten — Platzhalter-Form erhalten und via `sed` fillen.
- **Neue Config-Werte** müssen in `db.DEFAULT_CONFIG` eingetragen werden,
  sonst ist der Wert in der Web-UI nicht sichtbar/editierbar.
- **Frontend**: Bootstrap 5 via CDN. Keine lokalen JS/CSS-Builds.
  Templates nicht mit Tailwind/React etc. mischen.
