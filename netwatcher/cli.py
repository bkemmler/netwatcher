"""CLI entrypoints: init-db, add-user, scan, detail-scan, serve."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import db, scanner


def cmd_init_db(args: argparse.Namespace) -> None:
    path = db.init_db(args.db)
    print(f"DB initialisiert: {path}")


def cmd_add_user(args: argparse.Namespace) -> None:
    import bcrypt

    username = args.username
    password = args.password
    if not password:
        password = getpass.getpass("Passwort: ")
        if not password:
            print("Passwort erforderlich", file=sys.stderr)
        if password != getpass.getpass("wiederholen: "):
            print("Passwörter stimmen nicht überein", file=sys.stderr)
            sys.exit(1)
    if db.get_user(username, args.db):
        print(f"Benutzer '{username}' existiert bereits", file=sys.stderr)
        sys.exit(1)
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db.add_user(username, pw_hash, args.db)
    print(f"Benutzer '{username}' angelegt")


def cmd_scan(args: argparse.Namespace) -> None:
    summary = scanner.run_scan(args.db)
    print(
        f"Scan ok: {summary['total']} Geräte gesamt, "
        f"{summary['new']} neu (Macs: {', '.join(summary['new_macs']) or 'keine'})."
    )


def cmd_detail_scan(args: argparse.Namespace) -> None:
    summary = scanner.run_detail_scan_for_all(args.db)
    print(
        f"Detail-Scan ok: {summary['updated']} aktualisiert von "
        f"{summary['scanned']} Geräten."
    )


def cmd_cleanup_history(args: argparse.Namespace) -> None:
    deleted = db.cleanup_old_history(args.db)
    print(f"Verlauf bereinigt: {deleted} Einträge gelöscht.")


def cmd_opnsense_sync(args: argparse.Namespace) -> None:
    synced = scanner.sync_opnsense(args.db)
    print(f"OPNsense-Sync: {synced} Geräte synchronisiert.")


def cmd_profile_scan(args: argparse.Namespace) -> None:
    summary = scanner.run_profile_scan(args.profile, args.ip, args.db)
    print(
        f"{scanner.SCAN_PROFILES[args.profile]}: "
        f"{summary['updated']} von {summary['scanned']} Geräten aktualisiert."
    )


def cmd_serve(args: argparse.Namespace) -> None:
    """Run development server (use gunicorn in production)."""
    from .web.app import create_app

    app = create_app()
    cfg = db.get_config(args.db)
    host = args.host or cfg.get("web_bind_host", "0.0.0.0")
    port = int(args.port or cfg.get("web_bind_port", "5000"))
    app.run(host=host, port=port, debug=args.debug)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netwatcher")
    p.add_argument(
        "--db", default=os.environ.get("NETWATCHER_DB"),
        help="Pfad zur SQLite-DB (default: ~/.netwatcher/netwatcher.db)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init-db", help="Datenbank initialisieren")
    sp.set_defaults(func=cmd_init_db)

    sp = sub.add_parser("add-user", help="Web-UI Benutzer anlegen")
    sp.add_argument("username")
    sp.add_argument("--password", default=None)
    sp.set_defaults(func=cmd_add_user)

    sp = sub.add_parser("scan", help="arp-scan ausführen")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("detail-scan", help="nmap Detail-Scan für alle Geräte")
    sp.set_defaults(func=cmd_detail_scan)

    sp = sub.add_parser("cleanup-history", help="Alte Verlaufseinträge löschen")
    sp.set_defaults(func=cmd_cleanup_history)

    sp = sub.add_parser("opnsense-sync", help="OPNsense Dnsmasq Hosts synchronisieren")
    sp.set_defaults(func=cmd_opnsense_sync)

    sp = sub.add_parser("profile-scan", help="Nmap-Scanprofil ausführen")
    sp.add_argument("--profile", choices=sorted(scanner.SCAN_PROFILES), default="detail")
    sp.add_argument("--ip", default=None, help="Nur diese IPv4-Adresse scannen")
    sp.set_defaults(func=cmd_profile_scan)

    sp = sub.add_parser("serve", help="Flask dev-server starten")
    sp.add_argument("--host", default=None)
    sp.add_argument("--port", default=None)
    sp.add_argument("--debug", action="store_true")
    sp.set_defaults(func=cmd_serve)

    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
