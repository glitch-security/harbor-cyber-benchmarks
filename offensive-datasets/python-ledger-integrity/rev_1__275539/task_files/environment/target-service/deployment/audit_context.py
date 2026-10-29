"""Worker-thread request context used by private measurement instrumentation.

The transport layer sets the connection identity and service ordinal; the
read-only middleware records the authenticated principal.  The values are
exposed to SQLite as scalar functions so that transition triggers can stamp
them inside the same database transaction as the application write.

The request-local observations stored here also feed the WSGI boundary's
request-integrity gate, which refuses known invalid single-request wire forms
before Django dispatch.  Connection lifecycle fields (close epoch, ordinals)
remain measurement-only and never affect request handling.
"""
from __future__ import annotations

import threading

_STATE = threading.local()


def reset() -> None:
    _STATE.conn_id = None
    _STATE.service_ordinal = None
    _STATE.close_epoch = None
    _STATE.invalid_trailer = False
    _STATE.non_http11 = False
    _STATE.conflicting_framing = False
    _STATE.obsolete_line_folding = False
    _STATE.invalid_transfer_encoding = False
    _STATE.principal_id = None


def begin(
    conn_id: str | None,
    service_ordinal: int | None,
    close_epoch: int | None,
    *,
    invalid_trailer: bool = False,
    non_http11: bool = False,
    conflicting_framing: bool = False,
    obsolete_line_folding: bool = False,
    invalid_transfer_encoding: bool = False,
) -> None:
    _STATE.conn_id = conn_id
    _STATE.service_ordinal = service_ordinal
    _STATE.close_epoch = close_epoch
    _STATE.invalid_trailer = bool(invalid_trailer)
    _STATE.non_http11 = bool(non_http11)
    _STATE.conflicting_framing = bool(conflicting_framing)
    _STATE.obsolete_line_folding = bool(obsolete_line_folding)
    _STATE.invalid_transfer_encoding = bool(invalid_transfer_encoding)
    _STATE.principal_id = None


def clear() -> None:
    reset()


def set_principal(principal_id: int | None) -> None:
    _STATE.principal_id = principal_id


def snapshot() -> dict:
    return {
        "conn_id": getattr(_STATE, "conn_id", None),
        "service_ordinal": getattr(_STATE, "service_ordinal", None),
        "close_epoch": getattr(_STATE, "close_epoch", None),
        "invalid_trailer": getattr(_STATE, "invalid_trailer", False),
        "non_http11": getattr(_STATE, "non_http11", False),
        "conflicting_framing": getattr(_STATE, "conflicting_framing", False),
        "obsolete_line_folding": getattr(_STATE, "obsolete_line_folding", False),
        "invalid_transfer_encoding": getattr(_STATE, "invalid_transfer_encoding", False),
        "principal_id": getattr(_STATE, "principal_id", None),
    }


def _conn_id() -> str | None:
    return getattr(_STATE, "conn_id", None)


def _service_ordinal() -> int | None:
    return getattr(_STATE, "service_ordinal", None)


def _close_epoch() -> int | None:
    return getattr(_STATE, "close_epoch", None)


def _invalid_trailer() -> int:
    return int(getattr(_STATE, "invalid_trailer", False))


def _non_http11() -> int:
    return int(getattr(_STATE, "non_http11", False))


def _conflicting_framing() -> int:
    return int(getattr(_STATE, "conflicting_framing", False))


def _obsolete_line_folding() -> int:
    return int(getattr(_STATE, "obsolete_line_folding", False))


def _invalid_transfer_encoding() -> int:
    return int(getattr(_STATE, "invalid_transfer_encoding", False))


def _principal_id() -> int | None:
    return getattr(_STATE, "principal_id", None)


def install_sqlite_functions(connection) -> None:
    """Register the context accessors on one SQLite connection."""
    if connection.vendor != "sqlite":
        return
    raw = connection.connection
    if raw is None:
        return
    for name, fn in (
        ("audit_conn_id", _conn_id),
        ("audit_request_ordinal", _service_ordinal),
        ("audit_close_epoch", _close_epoch),
        ("audit_invalid_trailer", _invalid_trailer),
        ("audit_non_http11", _non_http11),
        ("audit_conflicting_framing", _conflicting_framing),
        ("audit_obsolete_line_folding", _obsolete_line_folding),
        ("audit_invalid_transfer_encoding", _invalid_transfer_encoding),
        ("audit_principal_id", _principal_id),
    ):
        try:
            raw.create_function(name, 0, fn, deterministic=False)
        except Exception:
            pass
