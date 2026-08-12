#!/usr/bin/env bash
# Netwatcher installer für Debian 13 (Trixie) LXC.
#
# Führt alle Schritte aus dem README automatisiert aus:
#   - System-Dependencies (arp-scan, nmap, sudo, python3-venv)
#   - System-User + Verzeichnisse
#   - venv + pip install
#   - DB initialisieren
#   - Admin-User anlegen (interaktiv)
#   - systemd-Units aus Templates fillen + aktivieren
#
# Aufruf als root im LXC:
#   bash scripts/install.sh
#
# Env-Vars können vorab gesetzt werden, um Defaults zu überschreiben;
# andernfalls werden sie interaktiv abgefragt (jeweils mit Default in [ ]):
#   NETWATCHER_USER, NETWATCHER_HOME, NETWATCHER_REPO, NETWATCHER_DB,
#   WEB_BIND, WEB_PORT
#
# Für non-interactive Runs alle Defaults (für CI/automatisierung):
#   INTERACTIVE=0 bash scripts/install.sh
#
# Für De-Installation: bash scripts/install.sh --uninstall
set -euo pipefail

# --- defaults ---
NETWATCHER_USER="${NETWATCHER_USER:-netwatcher}"
NETWATCHER_HOME="${NETWATCHER_HOME:-/opt/netwatcher}"
NETWATCHER_REPO="${NETWATCHER_REPO:-$NETWATCHER_HOME/app}"
NETWATCHER_DB="${NETWATCHER_DB:-$NETWATCHER_HOME/data/netwatcher.db}"
NETWATCHER_DB_DIR="$(dirname "$NETWATCHER_DB")"
WEB_BIND="${WEB_BIND:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-5000}"
# Pfad zum Repo-Checkout mit diesem installer (für sed-Templates):
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Farben nur bei TTY
if [[ -t 1 ]]; then
  C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'; C_RED='\033[0;31m'; C_OFF='\033[0m'
else
  C_GREEN=''; C_YELLOW=''; C_RED=''; C_OFF=''
fi
log()  { printf "${C_GREEN}[%s]%s %s\n${C_OFF}" "$(date +%H:%M:%S)" "" "$*"; }
warn() { printf "${C_YELLOW}[!] %s\n${C_OFF}" "$*" >&2; }
err()  { printf "${C_RED}[X] %s\n${C_OFF}" "$*" >&2; }
fatal(){ err "$*"; exit 1; }

# Interaktive Abfrage mit Default-Wert.
#   ask "Prompt" "default" -> schreibt Antwort in $REPLY
# Bei INTERACTIVE=0 wird ohne Rueckfrage der Default geliefert.
ask() {
  local prompt="$1" default="$2"
  if [[ "${INTERACTIVE:-1}" == "0" ]]; then
    REPLY="$default"
    printf "%s [%s]: %s\n" "$prompt" "$default" "$REPLY"
    return
  fi
  read -rp "$(printf '%s [%s]: ' "$prompt" "$default")" REPLY
  REPLY="${REPLY:-$default}"
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || fatal "Bitte als root ausführen (sudo bash scripts/install.sh)."
}

uninstall() {
  log "Stoppe systemd-Units …"
  systemctl disable --now netwatcher-web.service        2>/dev/null || true
  systemctl disable --now netwatcher-scan.timer         2>/dev/null || true
  systemctl disable --now netwatcher-detail.timer       2>/dev/null || true
  systemctl disable --now netwatcher-history-cleanup.timer 2>/dev/null || true
  systemctl disable --now netwatcher-scan.service       2>/dev/null || true
  systemctl disable --now netwatcher-detail.service     2>/dev/null || true
  systemctl disable --now netwatcher-history-cleanup.service 2>/dev/null || true
  for f in /etc/systemd/system/netwatcher-*.service /etc/systemd/system/netwatcher-*.timer; do
    [[ -f "$f" ]] && rm -f "$f"
  done
  systemctl daemon-reload
  warn "Datenbank, venv, Repo und User bleiben erhalten. Zum vollständigen Entfernen:"
  warn "  userdel -r $NETWATCHER_USER && rm -rf $NETWATCHER_HOME"
  log "De-Installation abgeschlossen."
  exit 0
}

[[ "${1:-}" == "--uninstall" ]] && uninstall

# --update: nur Units + Web-Service neu starten (kein Admin, kein venv, kein apt)
if [[ "${1:-}" == "--update" ]]; then
  require_root
  log "Update-Modus: Units + Web-Service ..."
  NETWATCHER_DB_DIR="$(dirname "$NETWATCHER_DB")"
  NW_BIN="$NETWATCHER_REPO/.venv/bin/python -m netwatcher"
  GUNICORN_BIN="$NETWATCHER_REPO/.venv/bin/gunicorn"
  SECRET="$(grep '^NETWATCHER_SECRET=' /etc/default/netwatcher 2>/dev/null | cut -d= -f2 || echo '')"
  [[ -z "$SECRET" ]] && fatal "/etc/default/netwatcher fehlt oder kein Secret gesetzt."
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  fill() {
    local src="$1" dst="$2"
    sed \
      -e "s|__NETWATCHER_USER__|$NETWATCHER_USER|g" \
      -e "s|__NETWATCHER_DIR__|$NETWATCHER_REPO|g" \
      -e "s|__NETWATCHER_DB__|$NETWATCHER_DB|g" \
      -e "s|__NETWATCHER_DB_DIR__|$NETWATCHER_DB_DIR|g" \
      -e "s|__NETWATCHER_BIN__|$NW_BIN|g" \
      -e "s|__GUNICORN_BIN__|$GUNICORN_BIN|g" \
      -e "s|__NETWATCHER_SECRET__|$SECRET|g" \
      -e "s|__WEB_BIND__|$WEB_BIND|g" \
      -e "s|__WEB_PORT__|$WEB_PORT|g" \
      "$src" > "$dst"
  }
  # Repo-Dateien kopieren
  if [[ "$REPO_ROOT" != "$NETWATCHER_REPO" ]]; then
    log "Kopiere Repo nach $NETWATCHER_REPO …"
    mkdir -p "$NETWATCHER_REPO"
    tar -C "$REPO_ROOT" \
      --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='.git' --exclude='.pytest_cache' \
      -cf - . | tar -C "$NETWATCHER_REPO" -xf -
    chown -R "$NETWATCHER_USER":"$NETWATCHER_USER" "$NETWATCHER_REPO"
  fi
  # Cache-Verzeichnis
  mkdir -p "$NETWATCHER_DB_DIR/cache"
  chown -R "$NETWATCHER_USER":"$NETWATCHER_USER" "$NETWATCHER_DB_DIR"
  # Units generieren
  for f in "$REPO_ROOT"/scripts/netwatcher-*.service; do
    out="$TMP_DIR/$(basename "$f")"
    fill "$f" "$out"
  done
  install -m 0644 "$TMP_DIR"/netwatcher-*.service /etc/systemd/system/
  for f in "$REPO_ROOT"/scripts/netwatcher-*.timer; do
    install -m 0644 "$f" /etc/systemd/system/"$(basename "$f")"
  done
  systemctl daemon-reload
  # Timer neu starten
  systemctl restart netwatcher-scan.timer
  systemctl restart netwatcher-detail.timer
  systemctl restart netwatcher-history-cleanup.timer
  # Web-Service robust neu starten
  bash "$REPO_ROOT/scripts/restart-web.sh"
  log "Update abgeschlossen. Web-Unit sollte jetzt gthread verwenden."
  exit 0
fi

require_root

# --- interaktive Abfrage der Env-Overrides ---
log "Installations-Parameter (jeweils Enter für Default):"
echo
ask "  System-User" "$NETWATCHER_USER";            NETWATCHER_USER="$REPLY"
ask "  Home-Verzeichnis" "$NETWATCHER_HOME";       NETWATCHER_HOME="$REPLY"
ask "  Repo/Pfad der App" "$NETWATCHER_REPO";      NETWATCHER_REPO="$REPLY"
ask "  Pfad zur SQLite-DB" "$NETWATCHER_DB";        NETWATCHER_DB="$REPLY"
ask "  Web-UI Bind-Host" "$WEB_BIND";              WEB_BIND="$REPLY"
ask "  Web-UI Port" "$WEB_PORT";                   WEB_PORT="$REPLY"
NETWATCHER_DB_DIR="$(dirname "$NETWATCHER_DB")"
echo
log "Zusammenfassung:"
printf "  User:    %s\n" "$NETWATCHER_USER"
printf "  Home:    %s\n" "$NETWATCHER_HOME"
printf "  App:     %s\n" "$NETWATCHER_REPO"
printf "  DB:      %s\n" "$NETWATCHER_DB"
printf "  Web:     %s:%s\n" "$WEB_BIND" "$WEB_PORT"
echo
if [[ "${INTERACTIVE:-1}" != "0" ]]; then
  read -rp "Fortfahren? [Y/n] " CONFIRM
  case "${CONFIRM:-Y}" in
    n|N|no|NO) fatal "Abbruch durch Benutzer."; exit 1;;
  esac
fi

# 1) Systemabhängigkeiten
log "Installiere System-Dependencies …"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  python3-venv python3-pip \
  arp-scan nmap arpwatch sudo \
  openssl ca-certificates git tar procps

# 2) User & Verzeichnisse
if ! id -u "$NETWATCHER_USER" >/dev/null 2>&1; then
  log "Lege System-User '$NETWATCHER_USER' an …"
  useradd --system --create-home --home-dir "$NETWATCHER_HOME" --shell /usr/sbin/nologin "$NETWATCHER_USER"
else
  warn "User '$NETWATCHER_USER' existiert bereits – überspringe Anlage."
fi
usermod -aG arpwatch "$NETWATCHER_USER" 2>/dev/null || true

log "Erstelle Verzeichnisse …"
mkdir -p "$NETWATCHER_DB_DIR"
chown -R "$NETWATCHER_USER":"$NETWATCHER_USER" "$NETWATCHER_HOME"

# 3) Repo-Dateien kopieren (falls wir nicht schon im Ziel liegen)
if [[ "$REPO_ROOT" != "$NETWATCHER_REPO" ]]; then
  log "Kopiere Repo nach $NETWATCHER_REPO …"
  mkdir -p "$NETWATCHER_REPO"
  # tar statt rsync (kein Extra-Paket nötig)
  tar -C "$REPO_ROOT" \
    --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.git' --exclude='.pytest_cache' \
    -cf - . | tar -C "$NETWATCHER_REPO" -xf -
  chown -R "$NETWATCHER_USER":"$NETWATCHER_USER" "$NETWATCHER_REPO"
fi

# 4) venv + requirements
log "Richte venv ein und installiere Python-Dependencies …"
sudo -u "$NETWATCHER_USER" bash -lc "
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  cd '$NETWATCHER_REPO' && python3 -m venv .venv && .venv/bin/pip install --quiet --upgrade pip && .venv/bin/pip install --quiet -r requirements.txt
"

# 5) Secret erzeugen (persistiert in /etc/default/netwatcher)
DEFAULTS_FILE=/etc/default/netwatcher
if [[ ! -f "$DEFAULTS_FILE" ]]; then
  log "Erzeuge Runtime-Default-File $DEFAULTS_FILE …"
  SECRET="$(openssl rand -hex 32)"
  cat > "$DEFAULTS_FILE" <<EOF
NETWATCHER_DB=$NETWATCHER_DB
NETWATCHER_SECRET=$SECRET
EOF
else
  warn "$DEFAULTS_FILE existiert – Secret wird wiederverwendet."
fi
# Immer (auch bei vorhandenem File) korrekte Permissions/Ownership setzen,
# damit der System-User die Datei lesen kann (ältere Installer-Version hatte
# chmod 600 gesetzt, was den sudo -u Aufruf blockierte).
chmod 640 "$DEFAULTS_FILE"
chown root:"$NETWATCHER_USER" "$DEFAULTS_FILE"
SECRET="$(grep '^NETWATCHER_SECRET=' "$DEFAULTS_FILE" | cut -d= -f2)"

# 6) DB initialisieren + Admin-User
log "Initialisiere Datenbank …"
sudo -u "$NETWATCHER_USER" bash -lc "
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  set -a; source $DEFAULTS_FILE; set +a
  cd '$NETWATCHER_REPO'
  .venv/bin/python -m netwatcher init-db
"

# Admin-User interaktiv anlegen (nur falls noch keiner existiert)
read -rp "Admin-Benutzername [admin]: " ADMIN_USER
ADMIN_USER="${ADMIN_USER:-admin}"
# Passwort via python prüfen, ob user schon existiert
EXISTING=$(sudo -u "$NETWATCHER_USER" bash -lc "
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  set -a; source $DEFAULTS_FILE; set +a
  cd '$NETWATCHER_REPO'
  .venv/bin/python -c 'from netwatcher import db,os; u=db.get_user(\"$ADMIN_USER\"); print(\"1\" if u else \"0\")'
" 2>/dev/null || echo "0")
if [[ "$EXISTING" == "1" ]]; then
  warn "Benutzer '$ADMIN_USER' existiert bereits – kein neues Passwort erforderlich."
else
  while true; do
    read -srp "Passwort für '$ADMIN_USER': " ADMIN_PW; echo
    read -srp "Wiederholung: " ADMIN_PW2; echo
    if [[ "$ADMIN_PW" == "$ADMIN_PW2" && -n "$ADMIN_PW" ]]; then
      if [[ ${#ADMIN_PW} -lt 6 ]]; then warn "Passwort zu kurz (min. 6 Zeichen)"; continue; fi
      break
    fi
    warn "Passwörter stimmen nicht überein oder sind leer – erneut versuchen."
  done
  if [[ "$ADMIN_PW" == *"'"* ]]; then fatal "Passwort darf kein Hochkomma enthalten."; fi
  sudo -u "$NETWATCHER_USER" bash -lc "
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    set -a; source $DEFAULTS_FILE; set +a
    cd '$NETWATCHER_REPO'
    .venv/bin/python -m netwatcher add-user '$ADMIN_USER' --password '$ADMIN_PW'
  "
fi

# 7) sudoers-Eintrag, damit der System-User arp-scan/nmap als root ausführen darf.
#   arp-scan wie auch nmap -O brauchen capabilities; das ist im LXC die einfachste
#   Variante, ohne den gesamten Scanner als root laufen zu lassen.
SUDOERS_FILE=/etc/sudoers.d/netwatcher
log "Schreibe sudoers-Regel $SUDOERS_FILE …"
cat > "$SUDOERS_FILE" <<EOF
# Auto-generated by netwatcher install.sh
$NETWATCHER_USER ALL=(root) NOPASSWD: /usr/sbin/arp-scan *
$NETWATCHER_USER ALL=(root) NOPASSWD: /usr/bin/nmap *
EOF
chmod 0440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" >/dev/null

# 8) systemd-Units aus Templates fillen
log "Generiere systemd-Units …"
NW_BIN="$NETWATCHER_REPO/.venv/bin/python -m netwatcher"
GUNICORN_BIN="$NETWATCHER_REPO/.venv/bin/gunicorn"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fill() {
  local src="$1" dst="$2"
  sed \
    -e "s|__NETWATCHER_USER__|$NETWATCHER_USER|g" \
    -e "s|__NETWATCHER_DIR__|$NETWATCHER_REPO|g" \
    -e "s|__NETWATCHER_DB__|$NETWATCHER_DB|g" \
    -e "s|__NETWATCHER_DB_DIR__|$NETWATCHER_DB_DIR|g" \
    -e "s|__NETWATCHER_BIN__|$NW_BIN|g" \
    -e "s|__GUNICORN_BIN__|$GUNICORN_BIN|g" \
    -e "s|__NETWATCHER_SECRET__|$SECRET|g" \
    -e "s|__WEB_BIND__|$WEB_BIND|g" \
    -e "s|__WEB_PORT__|$WEB_PORT|g" \
    "$src" > "$dst"
}

for f in "$REPO_ROOT"/scripts/netwatcher-*.service; do
  out="$TMP_DIR/$(basename "$f")"
  fill "$f" "$out"
done

install -m 0644 "$TMP_DIR"/netwatcher-*.service /etc/systemd/system/
for f in "$REPO_ROOT"/scripts/netwatcher-*.timer; do
  install -m 0644 "$f" /etc/systemd/system/"$(basename "$f")"
done

# 9) Timer aktivieren + Web-Service robust (neu) starten
log "Aktiviere Timer …"
systemctl stop netwatcher-scan.timer 2>/dev/null || true
systemctl stop netwatcher-detail.timer 2>/dev/null || true
systemctl stop netwatcher-history-cleanup.timer 2>/dev/null || true
systemctl daemon-reload
systemctl enable netwatcher-scan.timer
systemctl enable netwatcher-detail.timer
systemctl enable netwatcher-history-cleanup.timer
systemctl start netwatcher-scan.timer
systemctl start netwatcher-detail.timer
systemctl start netwatcher-history-cleanup.timer

# Web-Service über das dedizierte Restart-Skript starten. Das killt einen
# evtl. noch laufenden ALTEN gunicorn-Master hart (systemctl allein schafft
# das nicht, wenn sich die Unit-Definition geändert hat) und verifiziert,
# dass wirklich die NEUE Unit (gthread-Worker) aktiv ist.
log "Starte Web-Service (robuster Restart) …"
bash "$REPO_ROOT/scripts/restart-web.sh" || warn "Web-Service-Start meldete ein Problem (Details oben)."

# 10) Ersten Scan direkt anstoßen (optional, nicht blockierend)
log "Triggere ersten Scan …"
sudo -u "$NETWATCHER_USER" bash -lc "
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  set -a; source $DEFAULTS_FILE; set +a
  cd '$NETWATCHER_REPO'
  .venv/bin/python -m netwatcher scan
" || warn "Erster Scan gestartet aber nicht erfolgreich (vermutlich CAP_NET_RAW im LXC prüfen)."

# 11) Status ausgeben
IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
: "${IP:=<lxc-ip>}"
printf "\n${C_GREEN}========================================\n Netwatcher installiert\n========================================${C_OFF}\n\n"
printf "  Web-UI:        http://%s:%s/\n" "$IP" "$WEB_PORT"
printf "  DB:            %s\n" "$NETWATCHER_DB"
printf "  Benutzer:      %s\n" "$ADMIN_USER"
printf "  Repo:          %s\n" "$NETWATCHER_REPO"
printf "  Daemon:        systemctl status netwatcher-web.service\n"
printf "  Timer:         systemctl list-timers 'netwatcher-*'\n\n"
printf "  Logs:\n    journalctl -u netwatcher-web.service -f\n    journalctl -u netwatcher-scan.service -f\n\n"
printf "  Nächste Schritte:\n    - In der Web-UI unter Konfiguration den IP-Bereich + Gotify eintragen\n"
printf "    - Falls Scans leer sind: im Proxmox CAP_NET_RAW für den Container erlauben (siehe README)\n\n"
printf "  De-Installation:\n    bash %s/scripts/install.sh --uninstall\n" "$REPO_ROOT"
