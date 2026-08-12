# Netwatcher

Netzwerk-Geräte-Scanner für den Einsatz in einem Proxmox-LXC (Debian 13 / Trixie).
Scanned alle 5 Minuten das lokale Netzwerk nach neuen Geräten (`arp-scan`),
führt alle 6 Stunden Detail-Scans (`nmap -O -sV`) durch, speichert alles in SQLite
und bietet eine Web-UI zur Ansicht/Suche/Filter/Export sowie Konfiguration.
Neu gefundene Geräte lösen eine Gotify-Benachrichtigung aus.

## Voraussetzungen (im LXC)

- Debian 13 (Trixie) – Python 3.12+
- `arp-scan`, `nmap`, `sudo` (Container braucht `CAP_NET_RAW`)
- `python3-venv`

> LXC muss `CAP_NET_RAW` erlaubt haben, sonst kann `arp-scan` keine Layer-2-
> Pakete senden. In der Proxmox-Konfiguration des Containers (`/etc/pve/lxc/CTID.conf`)
> sicherstellen, dass kein `lxc.cap.drop` `net_raw` enthält. Unprivileged
> Container benötigen zusätzlich `/dev/net/just_network_access` – meist
> reicht `CAP_NET_RAW` bis `25` verfügbar.

## Installation (automatisch)

Der Installer `scripts/install.sh` führt alle Schritte automatisiert aus:

```sh
# als root im LXC
bash scripts/install.sh
```

Der Installer fragt interaktiv nach:
- System-User (Default: `netwatcher`)
- Verzeichnisse (Default: `/opt/netwatcher`)
- Web-UI Host/Port
- Admin-Benutzername und Passwort

Anschließend sind alle systemd-Units aktiv und die Web-UI erreichbar.

**Non-interaktive Installation** (CI/Automatisierung):

```sh
INTERACTIVE=0 bash scripts/install.sh
```

**Nach einem Code-Update nur Units + Web-Service aktualisieren:**

```sh
bash scripts/install.sh --update
```

**De-Installation:**

```sh
bash scripts/install.sh --uninstall
```

## Manuelle Installation

```sh
# als root im LXC
apt update
apt install -y python3-venv python3-pip arp-scan nmap sudo

useradd --system --create-home --home-dir /opt/netwatcher netwatcher
sudo -u netwatcher git clone <repo-url> /opt/netwatcher/app

sudo -u netwatcher bash -lc '
  cd /opt/netwatcher/app
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
'

export NETWATCHER_DB=/opt/netwatcher/data/netwatcher.db
export NETWATCHER_SECRET="$(openssl rand -hex 32)"
mkdir -p /opt/netwatcher/data
chown -R netwatcher:netwatcher /opt/netwatcher/data

sudo -u netwatcher bash -lc "
  export NETWATCHER_DB=$NETWATCHER_DB
  cd /opt/netwatcher/app
  .venv/bin/python -m netwatcher init-db
  .venv/bin/python -m netwatcher add-user admin
"
```

## systemd-Units (manuell)

Die Templates in `scripts/` enthalten Platzhalter (`__NETWATCHER_USER__` etc.).
Der `install.sh`-Installer befüllt diese automatisch. Für manuelle Installation:

| Platzhalter | Beispiel |
|---|---|
| `__NETWATCHER_USER__` | `netwatcher` |
| `__NETWATCHER_DIR__` | `/opt/netwatcher/app` |
| `__NETWATCHER_DB__` | `/opt/netwatcher/data/netwatcher.db` |
| `__NETWATCHER_DB_DIR__` | `/opt/netwatcher/data` |
| `__NETWATCHER_BIN__` | `/opt/netwatcher/app/.venv/bin/python -m netwatcher` |
| `__GUNICORN_BIN__` | `/opt/netwatcher/app/.venv/bin/gunicorn` |
| `__NETWATCHER_SECRET__` | `<Secret aus Step Setup>` |
| `__WEB_BIND__` | `0.0.0.0` |
| `__WEB_PORT__` | `5000` |

```sh
# Platzhalter via sed ersetzen (Beispiel: SERVICEFILE ersetzen)
SUD_BIN="/opt/netwatcher/app/.venv/bin/python -m netwatcher"
for f in scripts/netwatcher-*.service; do
  sed -e "s|__NETWATCHER_USER__|netwatcher|g" \
      -e "s|__NETWATCHER_DIR__|/opt/netwatcher/app|g" \
      -e "s|__NETWATCHER_DB__|/opt/netwatcher/data/netwatcher.db|g" \
      -e "s|__NETWATCHER_DB_DIR__|/opt/netwatcher/data|g" \
      -e "s|__NETWATCHER_BIN__|$SUD_BIN|g" \
      -e "s|__GUNICORN_BIN__|/opt/netwatcher/app/.venv/bin/gunicorn|g" \
      -e "s|__NETWATCHER_SECRET__|$NETWATCHER_SECRET|g" \
      -e "s|__WEB_BIND__|0.0.0.0|g" \
      -e "s|__WEB_PORT__|5000|g" \
      $f > /etc/systemd/system/$(basename $f)
done

cp scripts/netwatcher-*.timer /etc/systemd/system/

systemctl daemon-reload
mkdir -p /opt/netwatcher/data
chown -R netwatcher:netwatcher /opt/netwatcher/data
systemctl enable --now netwatcher-web.service
systemctl enable --now netwatcher-scan.timer
systemctl enable --now netwatcher-detail.timer
```

## Bedienung

- **Web-UI**: `http://<lxc-ip>:5000/`
- Login mit angelegtem Benutzer
- Geräte: suchen/filtern/sortieren, Spalten ein-/ausblenden, inline bearbeiten (Name/Status/Notizen)
- Export: CSV/JSON über Buttons in der Geräte-Liste
- Konfiguration: IP-Bereich, Interface, Scan-Intervall, Detail-Scan alle 6h, DNS/mDNS/IPv6/HTTP/TLS/UPnP/SMB aktivieren, Gotify, OPNsense-Sync, Datumsformat
- Externe Integrationen: arpwatch (`/var/lib/arpwatch/arp.dat`), LibreNMS REST-API und Greenbone-Report-URL; alle sind optional und über die Konfiguration synchronisierbar
- LibreNMS und Greenbone sind standardmäßig ausgeblendet. Aktivierung erfolgt serverseitig mit `NETWATCHER_REMOTE_INTEGRATIONS=1` beim Installer beziehungsweise beim systemd-Update.
- "Jetzt scannen" / "Detail-Scan" triggert manuelle Scans
- Scan-Profile: Schnellscan, Detailscan und Vollscan (alle Ports) über die Geräteliste
- OPNsense-Dnsmasq-Integration: statische DHCP-Hosts über API auslesen und MAC-abgleichen

## CLI-Kommandos

```sh
python -m netwatcher init-db              # DB initialisieren
python -m netwatcher add-user <name>     # Web-UI User anlegen
python -m netwatcher scan                # arp-Scan jetzt (wie timer)
python -m netwatcher detail-scan         # nmap-Detail für alle Geräte
python -m netwatcher cleanup-history     # Verlaufseinträge vom Vortag löschen
python -m netwatcher opnsense-sync       # OPNsense Dnsmasq-Hosts synchronisieren
python -m netwatcher profile-scan --profile quick   # Top-20-Ports
python -m netwatcher profile-scan --profile detail  # OS und Dienste
python -m netwatcher profile-scan --profile full    # alle TCP-Ports
python -m netwatcher integrations-sync              # arpwatch, LibreNMS, Greenbone
python -m netwatcher serve               # Flask dev-server (nur Test)
```

## Tests

```sh
.venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -v
```

Tests laufen vollständig offline (arp-scan-Fixtures statt Echt-Scans,
Gotify-Endpoint wird gemockt).

## Datenbank-Schema

Siehe `netwatcher/db.py`. Die Tabellen:
- `devices`: alle jemals gefundenen Geräte (eindeutig über MAC)
- `scan_history`: jeder Scan-Eintrag pro Gerät + Typ (`arp`/`detail`)
- `config`: Key/Value-Konfig (in Web-UI editierbar)
- `users`: Web-UI-Logins (bcrypt-Hashes)

## Gotify

In der Web-UI unter *Konfiguration*:
- `Gotify Server URL` (z.B. `https://gotify.example.com`)
- `App Token` (Gotify-App-Token, nicht Client-Token!)
- "Test-Nachricht senden" prüft die Verbindung

Bei neu gefundenen Geräten wird eine Nachricht mit IP/MAC/Hersteller versandt.
