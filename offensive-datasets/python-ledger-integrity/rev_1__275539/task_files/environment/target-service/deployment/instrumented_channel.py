"""Bounded I/O scheduling hooks around the unmodified HTTP channel.

The subclass below changes *when* bytes are read and written relative to the
server's own close decision.  It never marks a channel open, never creates or
edits a request, never rewrites parser output, and never touches application
state.  The identical subclass and settings are used for both pinned server
revisions so the only difference under test is upstream code.

Request-local wire observations recorded here are also consumed by the WSGI
boundary's request-integrity gate, which refuses known invalid single-request
forms before Django dispatch; connection lifecycle scheduling itself remains
observation-only.  Every observation is written to a private, bounded,
append-only event log that is readable only inside the appliance.  The log
contains connection identity, service ordinal, monotonic timestamps and event
names -- never credentials, cookies, or request bodies.
"""
from __future__ import annotations

import json
import os
import re
import select
import socket
import threading
import time
import uuid

from waitress.channel import HTTPChannel
from waitress.parser import HTTPRequestParser

from deployment import audit_context

EVENT_LOG_PATH = os.environ.get("LEDGER_EVENT_LOG", "/var/lib/ledger/events.jsonl")
MAX_EVENTS = int(os.environ.get("LEDGER_MAX_EVENTS", "4000"))

_LOCK = threading.Lock()
_COUNT = 0
_OVERFLOW = False
_FIELD_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class ObservedParser(HTTPRequestParser):
    """Retain wire facts that Waitress discards after parsing.

    Waitress removes Transfer-Encoding and replaces Content-Length with the
    decoded body size before service. It also unfolds obsolete continuation
    lines. Observe both facts at parse time; delegate the original bytes
    unchanged to the upstream parser.
    """

    conflicting_framing = False
    obsolete_line_folding = False
    invalid_transfer_encoding = False

    def parse_header(self, header_plus):
        fields = set()
        transfer_values = []
        for line in header_plus.split(b"\r\n")[1:]:
            if line.startswith((b" ", b"\t")):
                self.obsolete_line_folding = True
            name, separator, value = line.partition(b":")
            if separator:
                lower_name = name.lower()
                fields.add(lower_name)
                if lower_name == b"transfer-encoding":
                    transfer_values.append(value)
        self.conflicting_framing = (
            b"transfer-encoding" in fields and b"content-length" in fields
        )
        if transfer_values:
            codings = [part.strip(b" \t").lower()
                       for value in transfer_values for part in value.split(b",")]
            self.invalid_transfer_encoding = codings != [b"chunked"]
        return super().parse_header(header_plus)


def _invalid_chunk_trailer(request) -> bool:
    """Observe HTTP field-line syntax without changing Waitress's parser.

    Waitress stores the raw trailer on the chunk receiver. A request with a
    malformed trailer can reach the application, so the audit trigger needs a
    request-time witness instead of inferring validity from its response.
    """
    if request is None or request.error or not request.chunked:
        return False
    trailer = getattr(request.body_rcv, "trailer", b"")
    if not trailer:
        return False
    if not isinstance(trailer, bytes) or not trailer.endswith(b"\r\n\r\n"):
        return True
    lines = trailer[:-4].split(b"\r\n")
    for line in lines:
        name, separator, value = line.partition(b":")
        if not separator or _FIELD_NAME.fullmatch(name) is None:
            return True
        if any(byte not in (9, 32) and not 33 <= byte <= 126 and byte < 128 for byte in value):
            return True
    return False


def _append_event(payload: dict) -> None:
    global _COUNT, _OVERFLOW
    with _LOCK:
        if _OVERFLOW:
            return
        _COUNT += 1
        if _COUNT > MAX_EVENTS:
            _OVERFLOW = True
            payload = {"event": "event_log_overflow", "time_ns": time.monotonic_ns()}
        try:
            directory = os.path.dirname(EVENT_LOG_PATH) or "."
            os.makedirs(directory, exist_ok=True)
            with open(EVENT_LOG_PATH, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
        except OSError:
            pass


class ScheduledChannel(HTTPChannel):
    """Adds bounded read/write scheduling around the upstream channel."""

    parser_class = ObservedParser

    def __init__(self, *args, **kwargs):
        self.conn_id = uuid.uuid4().hex
        self.service_ordinal = 0
        self._approved = threading.Event()
        self._closed_decided = threading.Event()
        self._postclose_queued = threading.Event()
        self._postclose_serviced = threading.Event()
        self._close_epoch = None
        super().__init__(*args, **kwargs)

    # -- close decision observation -------------------------------------
    def __setattr__(self, name, value):
        if (
            name == "close_when_flushed"
            and value is True
            and getattr(self, "_close_epoch", None) is None
        ):
            object.__setattr__(self, "_close_epoch", time.monotonic_ns())
            event = getattr(self, "_closed_decided", None)
            if event is not None:
                event.set()
            _append_event(
                {
                    "event": "close_set",
                    "time_ns": self._close_epoch,
                    "conn_id": getattr(self, "conn_id", None),
                    "ordinal": getattr(self, "service_ordinal", None),
                }
            )
        object.__setattr__(self, name, value)

    # -- read scheduling -------------------------------------------------
    def readable(self):
        allowed = super().readable()
        try:
            if (
                allowed
                and self.requests
                and self.requests[0].error
                and not self._approved.is_set()
            ):
                self._approved.set()
                _append_event(
                    {
                        "event": "preclose_read_approved",
                        "time_ns": time.monotonic_ns(),
                        "conn_id": self.conn_id,
                        "ordinal": self.service_ordinal,
                    }
                )
                if self._closed_decided.wait(2.0):
                    try:
                        select.select([self.socket], [], [], 0.5)
                    except (OSError, ValueError):
                        pass
        except Exception:
            pass
        return allowed

    # -- receive observation --------------------------------------------
    def received(self, data):
        closed_before = bool(self.close_when_flushed or self.will_close)
        queued_before = len(self.requests)
        if data and closed_before:
            _append_event(
                {
                    "event": "received_after_close",
                    "time_ns": time.monotonic_ns(),
                    "conn_id": self.conn_id,
                    "ordinal": self.service_ordinal,
                    "bytes": len(data),
                }
            )
        result = super().received(data)
        try:
            if data and closed_before and len(self.requests) > queued_before:
                self._postclose_queued.set()
                _append_event(
                    {
                        "event": "postclose_queued",
                        "time_ns": time.monotonic_ns(),
                        "conn_id": self.conn_id,
                        "ordinal": self.service_ordinal,
                    }
                )
        except Exception:
            pass
        return result

    # -- write scheduling ------------------------------------------------
    def handle_write(self):
        if self._postclose_queued.is_set() and not self._postclose_serviced.is_set():
            self._postclose_serviced.wait(0.5)
        return super().handle_write()

    # -- request service -------------------------------------------------
    def service(self):
        request = self.requests[0] if self.requests else None
        if request is not None and request.error and not self._approved.is_set():
            self._approved.wait(2.0)

        self.service_ordinal += 1
        ordinal = self.service_ordinal
        is_error = bool(request.error) if request is not None else False
        if is_error:
            _append_event(
                {
                    "event": "parser_error_service_start",
                    "time_ns": time.monotonic_ns(),
                    "conn_id": self.conn_id,
                    "ordinal": ordinal,
                }
            )
        elif self._close_epoch is not None:
            _append_event(
                {
                    "event": "second_service_start",
                    "time_ns": time.monotonic_ns(),
                    "conn_id": self.conn_id,
                    "ordinal": ordinal,
                }
            )
        audit_context.begin(
            self.conn_id, ordinal, self._close_epoch,
            invalid_trailer=_invalid_chunk_trailer(request),
            non_http11=bool(request is not None and not request.error and request.version != "1.1"),
            conflicting_framing=bool(
                request is not None and not request.error and request.conflicting_framing
            ),
            obsolete_line_folding=bool(
                request is not None and not request.error and request.obsolete_line_folding
            ),
            invalid_transfer_encoding=bool(
                request is not None and not request.error and request.invalid_transfer_encoding
            ),
        )
        try:
            return super().service()
        finally:
            if ordinal >= 2 and self._close_epoch is not None:
                _append_event(
                    {
                        "event": "second_service_end",
                        "time_ns": time.monotonic_ns(),
                        "conn_id": self.conn_id,
                        "ordinal": ordinal,
                    }
                )
                self._postclose_serviced.set()
            audit_context.clear()
