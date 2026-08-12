#!/usr/bin/env bash
# recover-web.sh — stellt den Netwatcher-Web-Service in einem Schritt wieder her.
#
# Egal in welchem Zustand (tot, alte Unit, falsche Worker): dieses Skript
#   1. erkennt das installierte App-Verzeichnis,
#   2. liest DB-Pfad + Secret aus /etc/default/netwatcher,
#   3. schreibt eine known-good systemd-Unit (gthread + Restart=always),
#   4. killt alle alten gunicorn-Prozesse,
#   5. lädt neu, startet und verifiziert.
#
# Aufruf als root:   bash scripts/recover-web.sh
# (funktioniert aus dem Quell-Checkout ODER aus /opt/netwatcher/app/scripts/)
set -uo pipefail   # kein -e: wir laufen immer bis zur Verifikation durch

SERVICE=netwatcher-web.service

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[X] Bitte als root ausführen." >&2
  exit 1
fi

# --- 1) App-Verzeichnis bestimmen ---
# Bevorzugt die installierte Instanz unter /opt/netwatcher/app; Fallback: das
# Verzeichnis, in dem dieses Skript liegt (Elternverzeichnis von scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANDIDATES=(
  "/opt/netwatcher/app"
  "$(cd "$SCRIPT_DIR/.." && pwd)"
)
APP_DIR=""
for c in "${CANDIDATES[@]}"; do
  if [[ -x "$c/.venv/bin/gunicorn" ]]; then
    APP_DIR="$c"
    break
  fi
done
if [[ -z "$APP_DIR" ]]; then
  echo "[X] Kein installiertes gunicorn gefunden. Prüfe /opt/netwatcher/app/.venv/bin/gunicorn" >&2
  exit 1
fi
GUNICORN="$APP_DIR/.venv/bin/gunicorn"
PYTHON="$APP_DIR/.venv/bin/python"

# --- 2) DB + Secret lesen ---
DEFAULTS=/etc/default/netwatcher
NW_DB="" ; NW_SECRET=""
if [[ -f "$DEFAULTS" ]]; then
  NW_DB="$(grep '^NETWATCHER_DB=' "$DEFAULTS" | head -n1 | cut -d= -f2-)"
  NW_SECRET="$(grep '^NETWATCHER_SECRET=' "$DEFAULTS" | head -n1 | cut -d= -f2-)"
fi
[[ -n "$NW_DB" ]] || NW_DB="$(dirname "$APP_DIR")/data/netwatcher.db"
[[ -n "$NW_SECRET" ]] || NW_SECRET="$(openssl rand -hex 32)"

# --- 3) Bind/Port aus der DB-Config lesen (Fallback 0.0.0.0:5000) ---
WEB_BIND="0.0.0.0" ; WEB_PORT="5000"
if [[ -x "$PYTHON" && -f "$NW_DB" ]]; then
  read -r WEB_BIND WEB_PORT < <(NETWATCHER_DB="$NW_DB" "$PYTHON" -c '
from netwatcher import db
c = db.get_config()
print(c.get("web_bind_host","0.0.0.0") or "0.0.0.0", c.get("web_bind_port","5000") or "5000")
' 2>/dev/null || echo "0.0.0.0 5000")
fi

# --- 4) Service-User bestimmen (Owner des venv) ---
NW_USER="$(stat -c '%U' "$APP_DIR/.venv" 2>/dev/null || echo netwatcher)"

echo "=== Netwatcher Web-Recovery ==="
echo "  App:      $APP_DIR"
echo "  User:     $NW_USER"
echo "  DB:       $NW_DB"
echo "  Bind:     $WEB_BIND:$WEB_PORT"
echo "  gunicorn: $GUNICORN"
echo ""

# --- 5) known-good Unit schreiben ---
cat > "/etc/systemd/system/$SERVICE" <<EOF
[Unit]
Description=Netwatcher Web UI (gunicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$NW_USER
WorkingDirectory=$APP_DIR
Environment="NETWATCHER_DB=$NW_DB"
Environment="NETWATCHER_SECRET=$NW_SECRET"
ExecStart=$GUNICORN --worker-class gthread --workers 2 --threads 4 --timeout 120 --graceful-timeout 30 --keep-alive 5 --bind $WEB_BIND:$WEB_PORT --chdir $APP_DIR --worker-tmp-dir /dev/shm --access-logfile - --error-logfile - netwatcher.web.app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
echo "[1/4] Unit geschrieben: /etc/systemd/system/$SERVICE"

# --- 6) alte Prozesse hart entfernen ---
systemctl stop "$SERVICE" 2>/dev/null || true
pkill -KILL -f 'netwatcher[.]web[.]app:app' 2>/dev/null || true
sleep 2
echo "[2/4] Alte gunicorn-Prozesse entfernt."

# --- 7) neu laden + starten ---
systemctl daemon-reload
systemctl enable "$SERVICE" 2>/dev/null || true
systemctl restart "$SERVICE"
sleep 3
echo "[3/4] Service gestartet."

# --- 8) verifizieren ---
echo "[4/4] Verifikation:"
if systemctl is-active --quiet "$SERVICE"; then
  echo "  Status: active ✓"
else
  echo "  Status: NICHT active ✗ — Logs:" >&2
  journalctl -u "$SERVICE" -n 30 --no-pager >&2
  exit 1
fi

MAINPID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
if [[ "$MAINPID" != "0" && -d "/proc/$MAINPID" ]]; then
  CMD="$(tr '\0' ' ' < "/proc/$MAINPID/cmdline" 2>/dev/null || echo '?')"
  echo "  MainPID: $MAINPID"
  if echo "$CMD" | grep -q -- '--worker-class gthread'; then
    echo "  Worker:  gthread ✓ (neue Unit aktiv)"
  else
    echo "  Worker:  ⚠ gthread NICHT in Cmdline:" >&2
    echo "           $CMD" >&2
  fi
fi

echo ""
echo "Erreichbarkeit testen:"
echo "  curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:$WEB_PORT/login"
echo "Logs:"
echo "  journalctl -u $SERVICE -f"
