#!/usr/bin/env python3
"""Narrow lifecycle controller for the hosted ledger appliance.

The controller owns only service lifecycle, sealed-runtime integrity and a
read-only trusted snapshot of the protected accounting state.  It never
accepts a command, path, artifact or payload from main, never writes the
database, never marks a journal entry posted and never adds audit rows.

Routes:
  GET  /control/health          public generic liveness (no runtime detail)
  POST /control/public-reset    public, rate-limited safe reset
  GET  /control/preflight       authenticated status snapshot
  GET  /control/digest          authenticated sealed-runtime status
  GET  /control/effect          authenticated read-only transition snapshot
  POST /control/reset           authenticated reset
  POST /control/restart         authenticated restart preserving state

Authenticated routes require a request MAC over
``method + "\\n" + path + "\\n" + nonce + "\\n"`` in ``X-Control-Request-MAC``
with a fresh 64-hex ``X-Control-Nonce``.  Responses carry an HMAC over
``nonce + "\\n" + method + "\\n" + path + "\\n" + status + "\\n" + body``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(os.environ.get("TARGET_CONTROL_PORT", "19999"))
HEALTH_URL = os.environ["TARGET_HEALTH_URL"]
START = Path(os.environ["TARGET_START_SCRIPT"])
RESET = Path(os.environ["TARGET_RESET_SCRIPT"])
RESTART = Path(os.environ.get("TARGET_RESTART_SCRIPT", str(START)))
DB_PATH = Path(os.environ["TARGET_DB_PATH"])
FIXTURE_PATH = Path(os.environ["TARGET_FIXTURE_PATH"])
EVENT_LOG = Path(os.environ["TARGET_EVENT_LOG"])
MANIFEST = Path(os.environ["TARGET_MANIFEST"])
AUTH_KEY_PATH = Path(os.environ.get("TARGET_CONTROL_KEY_PATH", "/run/secrets/control-auth.key"))

LOCK = threading.Lock()
PUBLIC_RESET_LOCK = threading.Lock()
GENERATION = 0
CONTROL_KEY = b""
MAX_EVENTS = 200
MAX_TRANSITIONS = 100
NONCE_TTL_SECONDS = 60
NONCE_MAX = 4096
_SEEN_NONCES: dict[str, float] = {}
_SEEN_LOCK = threading.Lock()
_LAST_PUBLIC_RESET = 0.0
PUBLIC_RESET_INTERVAL = 5.0

READ_ONLY_DB_URI = f"file:{DB_PATH}?mode=ro"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def service_ready() -> bool:
    try:
        with OPENER.open(HEALTH_URL, timeout=2) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError:
        return False
    except (OSError, urllib.error.URLError):
        return False


def manifest_status() -> dict:
    if not MANIFEST.is_file():
        return {"present": False, "valid": False}
    checked = subprocess.run(
        ["sha256sum", "-c", str(MANIFEST)],
        cwd="/",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )
    return {
        "present": True,
        "valid": checked.returncode == 0,
        "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
    }


def run_lifecycle(script: Path, operation: str) -> None:
    if not script.is_file() or not os.access(script, os.X_OK):
        raise RuntimeError(f"{operation} lifecycle script is unavailable")
    log_path = Path(os.environ.get("TARGET_LIFECYCLE_LOG", "/var/log/ledger/lifecycle.log"))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError:
        log_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        completed = subprocess.run(
            [str(script)],
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
            close_fds=True,
        )
    finally:
        os.close(log_fd)
    if completed.returncode != 0:
        raise RuntimeError(f"{operation} lifecycle failed with status {completed.returncode}")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if service_ready():
            return
        time.sleep(0.2)
    raise RuntimeError(f"{operation} lifecycle did not restore service readiness")


def _read_fixture() -> dict:
    try:
        with open(FIXTURE_PATH, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _db() -> sqlite3.Connection:
    connection = sqlite3.connect(READ_ONLY_DB_URI, uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def _effect_present() -> bool:
    try:
        with _db() as db:
            row = db.execute("SELECT COUNT(*) AS n FROM audit_transition").fetchone()
            return int(row["n"]) > 0
    except sqlite3.Error as exc:
        raise RuntimeError("protected state could not be inspected") from exc


def _read_events(conn_id: str) -> list[dict]:
    events: list[dict] = []
    try:
        with open(EVENT_LOG, "r", encoding="utf-8", errors="strict") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("conn_id") != conn_id:
                    continue
                events.append(
                    {
                        "event": str(record.get("event", ""))[:64],
                        "time_ns": int(record.get("time_ns", 0)),
                        "ordinal": record.get("ordinal") if isinstance(record.get("ordinal"), int) else None,
                    }
                )
                if len(events) > MAX_EVENTS:
                    raise RuntimeError("event trace exceeded read limit")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RuntimeError("event trace could not be read") from exc
    return events


def _decimal_text(value) -> str:
    if value is None:
        return "0"
    return str(value)


def _memberships(db: sqlite3.Connection) -> dict[str, list[int]]:
    """Entity membership exactly as the application computes it.

    A principal is authorized for an entity when it is the entity admin or has
    a management row.  Suspended managers are not treated as members.
    """
    result: dict[str, list[int]] = {}
    try:
        rows = db.execute(
            "SELECT uuid, admin_id FROM django_ledger_entitymodel"
        ).fetchall()
    except sqlite3.Error:
        return result
    for row in rows:
        principals = {int(row["admin_id"])}
        try:
            managed = db.execute(
                """
                SELECT user_id FROM django_ledger_entitymanagementmodel
                 WHERE entity_id = ? AND permission_level != 'suspended'
                """,
                (row["uuid"],),
            ).fetchall()
        except sqlite3.Error:
            managed = []
        for entry in managed:
            principals.add(int(entry["user_id"]))
        result[str(row["uuid"])] = sorted(principals)
    return result


def load_effect() -> dict:
    fixture = _read_fixture()
    if not fixture:
        raise RuntimeError("fixture metadata is unavailable")
    with _db() as db:
        rows = db.execute(
            """
            SELECT id, je_uuid, conn_id, service_ordinal, close_epoch, invalid_trailer,
                   non_http11, conflicting_framing, obsolete_line_folding,
                   invalid_transfer_encoding, principal_id,
                   old_posted, new_posted, old_locked, new_locked, ledger_posted,
                   tx_count, debit_total, credit_total, entity_id, member_at_transition
              FROM audit_transition
             ORDER BY id
            """
        ).fetchall()
        if len(rows) > MAX_TRANSITIONS:
            raise RuntimeError("protected transition count exceeded read limit")
        memberships = _memberships(db)
        transitions = []
        for row in rows:
            current = db.execute(
                """
                SELECT je.posted AS posted, je.locked AS locked, je.ledger_id AS ledger_id,
                       le.posted AS ledger_posted, le.entity_id AS entity_id
                  FROM django_ledger_journalentrymodel je
                  LEFT JOIN django_ledger_ledgermodel le ON le.uuid = je.ledger_id
                 WHERE je.uuid = ?
                """,
                (row["je_uuid"],),
            ).fetchone()
            if current is None:
                continue
            totals = db.execute(
                """
                SELECT COUNT(*) AS n,
                       CAST(COALESCE(SUM(CASE WHEN tx_type = 'debit' THEN CAST(amount AS NUMERIC) END), 0) AS TEXT) AS debit,
                       CAST(COALESCE(SUM(CASE WHEN tx_type = 'credit' THEN CAST(amount AS NUMERIC) END), 0) AS TEXT) AS credit
                  FROM django_ledger_transactionmodel
                 WHERE journal_entry_id = ?
                """,
                (row["je_uuid"],),
            ).fetchone()
            # Django Ledger's TransactionModelQuerySet.posted() is the input to
            # its financial-statement pipeline. Apply that exact posted-entry
            # and posted-ledger filter here rather than inferring inclusion
            # only from the journal's display state.
            posted_book = db.execute(
                """
                SELECT COUNT(*) AS n,
                       CAST(COALESCE(SUM(CASE WHEN tx.tx_type = 'debit' THEN CAST(tx.amount AS NUMERIC) END), 0) AS TEXT) AS debit,
                       CAST(COALESCE(SUM(CASE WHEN tx.tx_type = 'credit' THEN CAST(tx.amount AS NUMERIC) END), 0) AS TEXT) AS credit
                  FROM django_ledger_transactionmodel tx
                  JOIN django_ledger_journalentrymodel je ON je.uuid = tx.journal_entry_id
                  JOIN django_ledger_ledgermodel le ON le.uuid = je.ledger_id
                 WHERE tx.journal_entry_id = ? AND je.posted = 1 AND le.posted = 1
                """,
                (row["je_uuid"],),
            ).fetchone()
            transitions.append(
                {
                    "je_uuid": str(row["je_uuid"]),
                    "conn_id": row["conn_id"],
                    "service_ordinal": row["service_ordinal"],
                    "close_epoch": row["close_epoch"],
                    "invalid_trailer_at_transition": int(row["invalid_trailer"] or 0),
                    "non_http11_at_transition": int(row["non_http11"] or 0),
                    "conflicting_framing_at_transition": int(row["conflicting_framing"] or 0),
                    "obsolete_line_folding_at_transition": int(row["obsolete_line_folding"] or 0),
                    "invalid_transfer_encoding_at_transition": int(row["invalid_transfer_encoding"] or 0),
                    "principal_id": row["principal_id"],
                    "old_posted": row["old_posted"],
                    "new_posted": int(row["new_posted"]),
                    "old_locked": row["old_locked"],
                    "new_locked": int(row["new_locked"]),
                    "ledger_posted_at_transition": int(row["ledger_posted"] or 0),
                    "tx_count_at_transition": int(row["tx_count"] or 0),
                    "debit_total_at_transition": _decimal_text(row["debit_total"]),
                    "credit_total_at_transition": _decimal_text(row["credit_total"]),
                    "current_posted": bool(current["posted"]),
                    "current_ledger_posted": bool(current["ledger_posted"]),
                    "current_tx_count": int(totals["n"] or 0),
                    "current_debit_total": _decimal_text(totals["debit"]),
                    "current_credit_total": _decimal_text(totals["credit"]),
                    "posted_book_tx_count": int(posted_book["n"] or 0),
                    "posted_book_debit_total": _decimal_text(posted_book["debit"]),
                    "posted_book_credit_total": _decimal_text(posted_book["credit"]),
                    "entity_id": str(current["entity_id"] or ""),
                    "entity_id_at_transition": str(row["entity_id"] or ""),
                    "member_at_transition": (
                        int(row["member_at_transition"])
                        if row["member_at_transition"] is not None
                        else None
                    ),
                    "event_trace": _read_events(str(row["conn_id"])) if row["conn_id"] else [],
                }
            )
    return {
        "generation": int(fixture.get("generation", 0)),
        "fixture_uuid": str(fixture.get("review_entry", "")),
        "memberships": memberships,
        "transitions": transitions,
    }


def _nonce_fresh(nonce: str) -> bool:
    now = time.monotonic()
    with _SEEN_LOCK:
        for key, seen in list(_SEEN_NONCES.items()):
            if now - seen > NONCE_TTL_SECONDS:
                del _SEEN_NONCES[key]
        if nonce in _SEEN_NONCES:
            return False
        if len(_SEEN_NONCES) >= NONCE_MAX:
            return False
        _SEEN_NONCES[nonce] = now
        return True


class Handler(BaseHTTPRequestHandler):
    server_version = "TargetServiceController/1.0"
    sys_version = ""

    def log_message(self, _format: str, *_args) -> None:
        return

    # -- response helpers -------------------------------------------------
    def _reply(self, status: int, body: dict) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        nonce = self.headers.get("X-Control-Nonce", "")
        if len(nonce) == 64 and all(c in "0123456789abcdef" for c in nonce):
            message = f"{nonce}\n{self.command}\n{self.path}\n{status}\n".encode() + encoded
            self.send_header(
                "X-Control-MAC", hmac.new(CONTROL_KEY, message, hashlib.sha256).hexdigest()
            )
        self.end_headers()
        self.wfile.write(encoded)

    def _authenticated(self) -> bool:
        nonce = self.headers.get("X-Control-Nonce", "")
        mac = self.headers.get("X-Control-Request-MAC", "")
        if len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
            return False
        if len(mac) != 64 or any(c not in "0123456789abcdef" for c in mac):
            return False
        message = f"{self.command}\n{self.path}\n{nonce}\n".encode()
        expected = hmac.new(CONTROL_KEY, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return False
        return _nonce_fresh(nonce)

    def _no_body(self) -> bool:
        if self.headers.get("Transfer-Encoding") is not None:
            return False
        return self.headers.get("Content-Length", "0") in ("0", "")

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/control/health":
            self._reply(200, {"ok": True, "target_ready": service_ready()})
            return
        if self.path not in {"/control/preflight", "/control/digest", "/control/effect"}:
            self._reply(404, {"error": "unknown control route"})
            return
        if not self._authenticated():
            self._reply(403, {"error": "forbidden"})
            return
        if self.path == "/control/digest":
            self._reply(200, manifest_status())
            return
        if self.path == "/control/preflight":
            try:
                integrity = manifest_status()
                present = _effect_present()
                fixture = _read_fixture()
            except Exception:
                self._reply(503, {"error": "protected state could not be inspected"})
                return
            self._reply(
                200,
                {
                    "target_ready": service_ready(),
                    "integrity": integrity,
                    "effect_present": present,
                    "generation": int(fixture.get("generation", 0)),
                },
            )
            return
        # /control/effect
        try:
            effect = load_effect()
        except FileNotFoundError:
            self._reply(404, {"error": "trusted effect is absent"})
            return
        except Exception:
            self._reply(500, {"error": "trusted effect could not be read"})
            return
        self._reply(200, {"effect": effect})

    def do_POST(self) -> None:  # noqa: N802
        global GENERATION, _LAST_PUBLIC_RESET
        if self.path == "/control/public-reset":
            if not self._no_body():
                self._reply(400, {"error": "control operations do not accept a body"})
                return
            if not PUBLIC_RESET_LOCK.acquire(blocking=False):
                self._reply(429, {"ok": False})
                return
            try:
                now = time.monotonic()
                if now - _LAST_PUBLIC_RESET < PUBLIC_RESET_INTERVAL:
                    self._reply(429, {"ok": False})
                    return
                _LAST_PUBLIC_RESET = now
                with LOCK:
                    run_lifecycle(RESET, "reset")
                    if not manifest_status().get("valid"):
                        raise RuntimeError("sealed runtime integrity failed")
                    if _effect_present():
                        raise RuntimeError("reset left a protected transition")
                    GENERATION += 1
                self._reply(200, {"ok": True})
            except Exception:
                self._reply(503, {"ok": False})
            finally:
                PUBLIC_RESET_LOCK.release()
            return
        if self.path not in {"/control/reset", "/control/restart"}:
            self._reply(404, {"error": "unknown control route"})
            return
        if not self._authenticated():
            self._reply(403, {"error": "forbidden"})
            return
        if not self._no_body():
            self._reply(400, {"error": "control operations do not accept a body"})
            return
        with LOCK:
            try:
                operation = "reset" if self.path.endswith("reset") else "restart"
                run_lifecycle(RESET if operation == "reset" else RESTART, operation)
                integrity = manifest_status()
                if not integrity.get("valid"):
                    raise RuntimeError("sealed runtime integrity failed")
                if operation == "reset" and _effect_present():
                    raise RuntimeError("reset left a protected transition")
                GENERATION += 1
                self._reply(200, {"ok": True, "generation": GENERATION, "integrity": integrity})
            except Exception as exc:
                detail = " ".join(str(exc).split())[:200] or exc.__class__.__name__
                self._reply(
                    503,
                    {
                        "ok": False,
                        "error": "target lifecycle operation failed",
                        "detail": detail,
                    },
                )


def main() -> int:
    global CONTROL_KEY
    CONTROL_KEY = AUTH_KEY_PATH.read_bytes()
    if len(CONTROL_KEY) != 32:
        raise RuntimeError("control authentication key must contain 32 random bytes")
    if not manifest_status().get("valid"):
        raise RuntimeError("sealed runtime integrity failed before startup")
    run_lifecycle(START, "start")
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
