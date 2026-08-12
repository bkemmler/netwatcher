#!/usr/bin/env bash
# Robuster Neustart des Netwatcher-Web-Service.
#
# Problem das hier gelöst wird: Wenn sich die systemd-Unit ändert (z.B. neue
# gunicorn-Flags), trackt systemd den ALTEN Master-Prozess oft nicht mehr
# korrekt. `systemctl restart` schlägt dann fehl und der alte Prozess läuft
# mit alter Konfiguration weiter (erkennbar an gleichbleibender Master-PID und
# 'Using worker: sync' im Log, obwohl gthread konfiguriert ist).
#
# Lösung: alten Prozess hart killen, Port-Freigabe abwarten, daemon-reload,
# frisch starten und das Ergebnis verifizieren.
#
# Aufruf:  bash scripts/restart-web.sh     (als root)
set -uo pipefail   # bewusst KEIN -e: wir wollen immer bis zur Verifikation laufen

SERVICE=netwatcher-web.service
# Bracket-Trick verhindert, dass pkill die eigene Shell matcht
PATTERN='netwatcher[.]web[.]app:app'

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[X] Bitte als root ausführen." >&2
  exit 1
fi

echo "[1/5] Stoppe $SERVICE via systemd (falls trackbar) …"
systemctl stop "$SERVICE" 2>/dev/null || true

echo "[2/5] Kille alle verbliebenen gunicorn-Prozesse der App …"
pkill -TERM -f "$PATTERN" 2>/dev/null || true
sleep 2
# harte Variante für Prozesse, die SIGTERM ignorieren
pkill -KILL -f "$PATTERN" 2>/dev/null || true
sleep 1

# Port-Freigabe abwarten (max. 10s)
echo "[3/5] Warte auf Port-Freigabe …"
for i in $(seq 1 10); do
  if ! pgrep -f "$PATTERN" >/dev/null 2>&1; then
    echo "      keine App-Prozesse mehr."
    break
  fi
  sleep 1
done
if pgrep -f "$PATTERN" >/dev/null 2>&1; then
  echo "[!] WARNUNG: es laufen noch App-Prozesse:" >&2
  pgrep -af "$PATTERN" >&2 || true
fi

echo "[4/5] daemon-reload + Start …"
systemctl daemon-reload
systemctl enable "$SERVICE" 2>/dev/null || true
systemctl start "$SERVICE"
sleep 3

echo "[5/5] Verifikation …"
if systemctl is-active --quiet "$SERVICE"; then
  echo "      systemd-Status: active"
else
  echo "[!] Service NICHT active. Letzte Logs:" >&2
  journalctl -u "$SERVICE" -n 25 --no-pager >&2 || true
  exit 1
fi

MAINPID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
echo "      MainPID: $MAINPID"
if [[ "$MAINPID" != "0" && -n "$MAINPID" && -d "/proc/$MAINPID" ]]; then
  CMDLINE="$(tr '\0' ' ' < "/proc/$MAINPID/cmdline" 2>/dev/null || echo '?')"
  echo "      CmdLine: $CMDLINE"
  if echo "$CMDLINE" | grep -q -- '--worker-class gthread'; then
    echo "      Worker-Klasse: gthread -> NEUE Unit aktiv. OK."
  else
    echo "[!] CmdLine enthält kein 'gthread' -> ALTE Unit läuft noch!" >&2
    echo "    Prüfe: cat /etc/systemd/system/$SERVICE" >&2
    exit 1
  fi
fi

echo ""
echo "Fertig. Test:  curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:5000/login"
