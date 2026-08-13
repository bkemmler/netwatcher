"""Flask web UI for Netwatcher."""
from __future__ import annotations

import csv
import io
import json
import os
import secrets
from collections import Counter
from functools import wraps
from typing import Any

import bcrypt
from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .. import db, notifications, scanner

DB_PATH = os.environ.get("NETWATCHER_DB")


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get(
        "NETWATCHER_SECRET", secrets.token_hex(32)
    )
    app.permanent_session_lifetime = 7 * 24 * 3600  # 7 days in seconds

    # ensure db exists
    db.init_db(DB_PATH)

    @app.context_processor
    def inject_version():
        from .. import __version__
        return {
            "netwatcher_version": __version__,
            "remote_integrations_enabled": os.environ.get(
                "NETWATCHER_REMOTE_INTEGRATIONS", "0"
            ) == "1",
        }

    @app.context_processor
    def inject_format_date():
        from datetime import datetime, timedelta, timezone as tz

        def _stale(iso: str | None) -> bool:
            if not iso:
                return False
            try:
                dt = datetime.fromisoformat(
                    iso.replace("Z", "+00:00").split("+")[0].split("[")[0]
                ).replace(tzinfo=tz.utc)
                return datetime.now(tz.utc) - dt > timedelta(hours=24)
            except ValueError:
                return False

        def _fmt(iso: str | None, fallback: str = "—") -> str:
            if not iso:
                return fallback
            try:
                dt = datetime.fromisoformat(iso.replace("Z", "+00:00").split("+")[0].split("[")[0])
                dt = dt.replace(tzinfo=tz.utc)
                tz_name = db.get_config(DB_PATH).get("timezone", "Europe/Berlin")
                from zoneinfo import ZoneInfo
                dt = dt.astimezone(ZoneInfo(tz_name))
            except (ValueError, Exception):
                return iso[:19] if len(iso) >= 19 else iso
            fmt_key = db.get_config(DB_PATH).get("date_format", "de")
            if fmt_key == "de":
                return dt.strftime("%d.%m.%Y %H:%M")
            else:
                return dt.strftime("%Y-%m-%d %H:%M")

        import json as _json

        def _ips(raw: str | None) -> str:
            if not raw:
                return ""
            try:
                lst = _json.loads(raw)
                return ", ".join(lst) if isinstance(lst, list) else str(raw)
            except (_json.JSONDecodeError, TypeError):
                return str(raw)

        return {"format_date": _fmt, "format_ips": _ips, "is_stale": _stale}

    @app.context_processor
    def inject_render_detail():
        import json

        def _render(raw: str | None, key: str) -> str:
            if not raw:
                return '<span class="text-muted">keine Daten</span>'
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return f'<pre class="mb-0 small">{raw[:500]}</pre>'
            if not data:
                return '<span class="text-muted">keine Daten</span>'

            lines: list[str] = []

            if key == "os":
                lines.append('<table class="table table-sm mb-0 small">')
                lines.append('<thead><tr><th>Name</th><th>Accuracy</th></tr></thead>')
                lines.append("<tbody>")
                for item in data:
                    name = item.get("name", "?")
                    acc = item.get("accuracy", "")
                    lines.append(f'<tr><td>{name}</td><td>{acc}%</td></tr>')
                lines.append("</tbody></table>")

            elif key == "services":
                lines.append('<table class="table table-sm mb-0 small">')
                lines.append('<thead><tr><th>Port</th><th>Protokoll</th><th>Dienst</th><th>Produkt</th><th>Version</th></tr></thead>')
                lines.append("<tbody>")
                for s in data:
                    lines.append(
                        f'<tr><td>{s.get("port","")}</td><td>{s.get("proto","")}</td>'
                        f'<td>{s.get("service","") or "—"}</td>'
                        f'<td>{s.get("product","") or "—"}</td>'
                        f'<td>{s.get("version","") or "—"}</td></tr>'
                    )
                lines.append("</tbody></table>")

            elif key == "http":
                rows = [
                    ("Status", str(data.get("status", ""))),
                    ("Server", str(data.get("server", ""))),
                    ("Title", str(data.get("title", ""))),
                ]
                lines.append('<dl class="row mb-0 small">')
                for label, val in rows:
                    if val:
                        lines.append(f'<dt class="col-sm-3">{label}</dt><dd class="col-sm-9">{val}</dd>')
                lines.append("</dl>")

            elif key == "tls":
                rows = [
                    ("Subject", str(data.get("subject", ""))),
                    ("Issuer", str(data.get("issuer", ""))),
                    ("Gültig ab", str(data.get("not_before", ""))),
                    ("Gültig bis", str(data.get("not_after", ""))),
                ]
                lines.append('<dl class="row mb-0 small">')
                for label, val in rows:
                    if val:
                        lines.append(f'<dt class="col-sm-3">{label}</dt><dd class="col-sm-9">{val}</dd>')
                lines.append("</dl>")

            elif key == "network":
                lines.append('<dl class="row mb-0 small">')
                if "upnp" in data:
                    upnp = data["upnp"]
                    server = upnp.get("server", "")
                    usn = upnp.get("usn", "")
                    loc = upnp.get("location", "")
                    lines.append('<dt class="col-sm-3">UPnP</dt><dd class="col-sm-9">')
                    if server:
                        lines.append(f"Server: {server}<br>")
                    if usn:
                        lines.append(f"USN: {usn}<br>")
                    if loc:
                        lines.append(f"Location: {loc}")
                    lines.append("</dd>")
                if "smb" in data:
                    smb = data["smb"]
                    cn = smb.get("computer_name", "")
                    wg = smb.get("workgroup", "")
                    lines.append('<dt class="col-sm-3">SMB</dt><dd class="col-sm-9">')
                    if cn:
                        lines.append(f"Computer: {cn}<br>")
                    if wg:
                        lines.append(f"Workgroup: {wg}")
                    names = smb.get("names", [])
                    if names:
                        for n in names:
                            lines.append(f'{n.get("name","")} {n.get("flags","")}<br>')
                    lines.append("</dd>")
                lines.append("</dl>")

            elif key == "external":
                lines.append('<dl class="row mb-0 small">')
                for source, value in data.items():
                    rendered = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
                    lines.append(f'<dt class="col-sm-3">{source}</dt><dd class="col-sm-9"><code>{rendered}</code></dd>')
                lines.append("</dl>")

            else:
                return f'<pre class="mb-0 small">{raw[:1000]}</pre>'

            return "\n".join(lines) if lines else '<span class="text-muted">keine Daten</span>'

        return {"render_detail": _render}

    # --- auth ---


    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("user"):
                return redirect(url_for("login", next=request.path))
            return fn(*a, **kw)

        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user = db.get_user(username, DB_PATH)
            if user and bcrypt.checkpw(
                password.encode(), user["pw_hash"].encode()
            ):
                session.permanent = True
                session["user"] = username
                nxt = request.args.get("next") or url_for("devices")
                return redirect(nxt)
            return render_template("login.html", error="Login fehlgeschlagen")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/favicon.ico")
    def favicon():
        # 16x16 transparent icon -> vermeidet 404-Rauschen im Access-Log
        return Response(
            b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00"
            b"\x30\x04\x00\x00\x16\x00\x00\x00",
            mimetype="image/x-icon",
        )

    # --- devices ---


    @app.route("/")
    @login_required
    def devices():
        search = request.args.get("q", "").strip() or None
        known_filter = request.args.get("known", "")
        known_only = None
        if known_filter == "1":
            known_only = True
        elif known_filter == "0":
            known_only = False
        sort = request.args.get("sort", "first_seen")
        dirn = request.args.get("dir", "desc")
        page = max(1, int(request.args.get("page", "1")))
        page_size = 25

        items, total = db.list_devices(
            search=search,
            known_only=known_only,
            sort=sort,
            sort_dir=dirn,
            page=page,
            page_size=page_size,
            db_path=DB_PATH,
        )
        all_ips = Counter(
            d["ip_last"] for d in db.all_devices(DB_PATH) if d.get("ip_last")
        )
        duplicate_ips = {ip for ip, count in all_ips.items() if count > 1}
        pages = max(1, (total + page_size - 1) // page_size)
        return render_template(
            "devices.html",
            devices=items,
            total=total,
            pages=pages,
            page=page,
            search=search or "",
            known_filter=known_filter,
            sort=sort,
            dir=dirn,
            duplicate_ips=duplicate_ips,
        )

    @app.route("/devices/<int:id>", methods=["GET", "POST"])
    @login_required
    def device_detail(id: int):
        device = db.get_device(id, DB_PATH)
        if not device:
            abort(404)
        if request.method == "POST":
            name = request.form.get("name") or None
            notes = request.form.get("notes") or None
            known = 1 if request.form.get("known") else 0
            db.update_device_meta(id, name, notes, known, DB_PATH)
            flash("Gerät aktualisiert", "success")
            return redirect(url_for("device_detail", id=id))
        history = db.device_history(id, db_path=DB_PATH)
        return render_template(
            "device_detail.html", device=device, history=history
        )

    @app.route("/devices/bulk-update", methods=["POST"])
    @login_required
    def bulk_update():
        device_ids = set()
        for key in request.form:
            if key.startswith("name_"):
                device_ids.add(int(key.split("_", 1)[1]))
            elif key.startswith("notes_"):
                device_ids.add(int(key.split("_", 1)[1]))

        updated = 0
        for did in sorted(device_ids):
            name = request.form.get(f"name_{did}") or None
            notes = request.form.get(f"notes_{did}") or None
            known = 1 if request.form.get(f"known_{did}") == "1" else 0
            db.update_device_meta(did, name, notes, known, DB_PATH)
            updated += 1

        flash(f"{updated} Geräte aktualisiert", "success")
        return redirect(url_for(
            "devices",
            q=request.form.get("q", ""),
            known=request.form.get("known", ""),
            sort=request.form.get("sort", "first_seen"),
            dir=request.form.get("dir", "desc"),
            page=request.form.get("page", "1"),
        ))

    # --- export ---


    @app.route("/export")
    @login_required
    def export():
        fmt = request.args.get("format", "csv").lower()
        search = request.args.get("q", "").strip() or None
        known_filter = request.args.get("known", "")
        known_only = None
        if known_filter == "1":
            known_only = True
        elif known_filter == "0":
            known_only = False
        sort = request.args.get("sort", "first_seen")
        dirn = request.args.get("dir", "desc")
        # fetch all (paging disabled)
        items, _ = db.list_devices(
            search=search,
            known_only=known_only,
            sort=sort,
            sort_dir=dirn,
            page=1,
            page_size=10**9,
            db_path=DB_PATH,
        )
        if fmt == "json":
            resp = Response(
                json.dumps(items, indent=2, ensure_ascii=False),
                mimetype="application/json",
            )
            resp.headers["Content-Disposition"] = "attachment; filename=netwatcher-devices.json"
            return resp
        out = io.StringIO()
        writer = csv.DictWriter(
            out,
            fieldnames=[
                "id", "mac", "ip_last", "hostname", "vendor", "oui",
                "first_seen", "last_seen", "name", "notes", "known",
                "os_info", "services", "last_detail_scan",
            ],
        )
        writer.writeheader()
        for d in items:
            writer.writerow({k: d.get(k, "") for k in writer.fieldnames})
        resp = Response(out.getvalue(), mimetype="text/csv")
        resp.headers["Content-Disposition"] = "attachment; filename=netwatcher-devices.csv"
        return resp

    # --- config ---


    @app.route("/config", methods=["GET", "POST"])
    @login_required
    def config_page():
        if request.method == "POST":
            # checkbox handling
            def checkbox(key: str) -> str:
                return "1" if key in request.form else "0"

            keys = [
                "scan_range", "scan_interface", "scan_interval_seconds",
                "detail_scan_interval_hours",
                "gotify_url", "gotify_token", "web_bind_host", "web_bind_port",
                "date_format",
                "timezone",
                "opnsense_url", "opnsense_api_key", "opnsense_api_secret",
                "opnsense_timeout",
            ]
            if os.environ.get("NETWATCHER_REMOTE_INTEGRATIONS", "0") == "1":
                keys += [
                    "arpwatch_path", "librenms_url", "librenms_token",
                    "librenms_timeout", "greenbone_report_url",
                    "greenbone_username", "greenbone_password", "greenbone_timeout",
                ]
            for k in keys:
                val = request.form.get(k, "")
                if val is not None:
                    db.set_config(k, val, DB_PATH)
            db.set_config("notify_on_new", checkbox("notify_on_new"), DB_PATH)
            db.set_config(
                "detail_interval_enabled",
                checkbox("detail_interval_enabled"),
                DB_PATH,
            )
            for ck in ("detail_dns_enabled", "detail_mdns_enabled",
                       "detail_ipv6_enabled", "detail_http_tls_enabled",
                       "detail_upnp_enabled", "detail_smb_enabled"):
                db.set_config(ck, checkbox(ck), DB_PATH)
            db.set_config("opnsense_enabled", checkbox("opnsense_enabled"), DB_PATH)
            db.set_config("opnsense_verify_tls", checkbox("opnsense_verify_tls"), DB_PATH)
            if os.environ.get("NETWATCHER_REMOTE_INTEGRATIONS", "0") == "1":
                db.set_config("arpwatch_enabled", checkbox("arpwatch_enabled"), DB_PATH)
                db.set_config("librenms_enabled", checkbox("librenms_enabled"), DB_PATH)
                db.set_config("librenms_verify_tls", checkbox("librenms_verify_tls"), DB_PATH)
                db.set_config("greenbone_enabled", checkbox("greenbone_enabled"), DB_PATH)
                db.set_config("greenbone_verify_tls", checkbox("greenbone_verify_tls"), DB_PATH)
            if request.form.get("test_gotify"):
                ok = notifications.send(
                    title="Netwatcher Test",
                    message="Test-Benachrichtigung – Gotify ist korrekt konfiguriert.",
                    priority=4,
                    db_path=DB_PATH,
                )
                if ok:
                    flash("Test-Nachricht verschickt", "success")
                else:
                    flash("Test-Nachricht fehlgeschlagen (URL/Token prüfen)", "error")
            else:
                flash("Konfiguration gespeichert", "success")
            return redirect(url_for("config_page"))
        cfg = db.get_config(DB_PATH)
        return render_template("config.html", cfg=cfg)

    @app.route("/config/users", methods=["POST"])
    @login_required
    def add_user():
        username = request.form.get("new_username", "").strip()
        password = request.form.get("new_password", "")
        if not username or not password:
            flash("Benutzername und Passwort erforderlich", "error")
            return redirect(url_for("config_page"))
        if len(password) < 6:
            flash("Passwort zu kurz (min. 6 Zeichen)", "error")
            return redirect(url_for("config_page"))
        if db.get_user(username, DB_PATH):
            flash("Benutzer existiert bereits", "error")
            return redirect(url_for("config_page"))
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db.add_user(username, pw_hash, DB_PATH)
        flash(f"Benutzer '{username}' angelegt", "success")
        return redirect(url_for("config_page"))

# --- scan trigger ---


    @app.route("/scan-now")
    @login_required
    def scan_now():
        """Trigger a scan in the background (non-blocking).

        We spawn `python -m netwatcher scan` as a detached subprocess so the
        HTTP worker returns immediately — arp-scan over a /24 with --retry=3
        can take 30+ seconds, which would otherwise exceed gunicorn's worker
        timeout and kill the worker mid-scan.
        """
        import subprocess
        import sys

        try:
            env = os.environ.copy()
            env["NETWATCHER_DB"] = DB_PATH or ""
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            subprocess.Popen(
                [sys.executable, "-m", "netwatcher", "scan"],
                cwd=None,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,  # detach: survives the request
            )
            flash("Scan im Hintergrund gestartet — in ~1 Minute aktualisieren", "success")
        except Exception as exc:
            flash(f"Scan-Start fehlgeschlagen: {exc}", "error")
        return redirect(url_for("devices"))

    @app.route("/detail-scan-now")
    @login_required
    def detail_scan_now():
        import subprocess
        import sys

        try:
            env = os.environ.copy()
            env["NETWATCHER_DB"] = DB_PATH or ""
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            subprocess.Popen(
                [sys.executable, "-m", "netwatcher", "detail-scan"],
                cwd=None,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            flash("Detail-Scan im Hintergrund gestartet", "success")
        except Exception as exc:
            flash(f"Detail-Scan-Start fehlgeschlagen: {exc}", "error")
        return redirect(url_for("devices"))

    @app.route("/profile-scan-now", methods=["POST"])
    @login_required
    def profile_scan_now():
        import subprocess
        import sys

        profile = request.form.get("profile", "detail")
        if profile not in scanner.SCAN_PROFILES:
            flash("Unbekanntes Scan-Profil", "error")
            return redirect(url_for("devices"))
        env = os.environ.copy()
        env["NETWATCHER_DB"] = DB_PATH or ""
        env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        try:
            subprocess.Popen(
                [sys.executable, "-m", "netwatcher", "profile-scan", "--profile", profile],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, start_new_session=True,
            )
            flash(f"{scanner.SCAN_PROFILES[profile]} im Hintergrund gestartet", "success")
        except Exception as exc:
            flash(f"Scan-Start fehlgeschlagen: {exc}", "error")
        return redirect(url_for("devices"))

    @app.route("/config/cleanup-history", methods=["POST"])
    @login_required
    def cleanup_history():
        import subprocess
        import sys

        try:
            env = os.environ.copy()
            env["NETWATCHER_DB"] = DB_PATH or ""
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            subprocess.Popen(
                [sys.executable, "-m", "netwatcher", "cleanup-history"],
                cwd=None,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            flash("Verlaufsbereinigung im Hintergrund gestartet", "success")
        except Exception as exc:
            flash(f"Bereinigung fehlgeschlagen: {exc}", "error")
        return redirect(url_for("config_page"))

    @app.route("/config/opnsense-sync", methods=["POST"])
    @login_required
    def opnsense_sync():
        try:
            cfg = db.get_config(DB_PATH)
            enabled = cfg.get("opnsense_enabled", "0") == "1"
            if not enabled:
                flash("OPNsense-Synchronisierung ist deaktiviert", "error")
                return redirect(url_for("config_page"))
            url = cfg.get("opnsense_url", "").strip()
            if not url:
                flash("OPNsense-URL nicht konfiguriert", "error")
                return redirect(url_for("config_page"))
            synced = scanner.sync_opnsense(DB_PATH)
            if synced > 0:
                flash(f"OPNsense-Sync: {synced} Geräte synchronisiert", "success")
            else:
                flash("OPNsense-Sync abgeschlossen — keine neuen Daten zugeordnet. API-URL und Zugangsdaten prüfen.", "warning")
        except Exception as exc:
            flash(f"OPNsense-Sync fehlgeschlagen: {exc}", "error")
        return redirect(url_for("config_page"))

    @app.route("/config/integrations-sync", methods=["POST"])
    @login_required
    def integrations_sync():
        try:
            if os.environ.get("NETWATCHER_REMOTE_INTEGRATIONS", "0") != "1":
                flash("LibreNMS/Greenbone-Integrationen sind serverseitig deaktiviert", "warning")
                return redirect(url_for("config_page"))
            counts = scanner.sync_external_integrations(DB_PATH)
            flash("Integrationen synchronisiert: " + ", ".join(
                f"{key}={value}" for key, value in counts.items()
            ), "success")
        except Exception as exc:
            flash(f"Integrations-Sync fehlgeschlagen: {exc}", "error")
        return redirect(url_for("config_page"))

    return app


# WSGI entrypoint
app = create_app()


if __name__ == "__main__":
    cfg = db.get_config(DB_PATH)
    host = cfg.get("web_bind_host", "0.0.0.0")
    port = int(cfg.get("web_bind_port", "5000"))
    app.run(host=host, port=port, debug=False)
