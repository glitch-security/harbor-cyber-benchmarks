#!/usr/bin/env python3
"""Configurable public test origin (request capture + canned responses).

A small programmable HTTP endpoint on the "public" network that the target can
reach. It records every inbound request (the capture log) and returns responses
the participant configures through an admin API. It is configuration-only: no
code execution and no arbitrary response bytes — bodies come from a fixed preset
set and the only settable response header is Location (for a status reply).

Two listeners:
  * DATA (DATA_PORT, reached by the target): the only surface the target touches.
    Every request is appended to the capture log (request line + headers + status).
  * ADMIN (ADMIN_PORT, reached by the operator/participant/verifier): install
    rules, read the capture log, reset, and read the operator manual. Gated by
    ORIGIN_ADMIN_TOKEN. The manual served at GET /_admin/help documents the exact,
    accurate configuration surface for solvers; this module docstring (which also
    records why the state model blocks specific shortcuts) is NOT served anywhere.

Rule grammar (declarative; evaluated in order, first match wins):
  { "when":  { "path"?: "<prefix>", "visit"?: "new"|"repeat" },
    "reply": { "body": "page"|"feed"|"note"|"clip" }
           OR { "status"?: 301|302|303|307|308, "location": "<relative-or-http(s) URL>" } }
If no rule matches, a `page` body is served. An empty `when` {} matches all.

Issued unique links (the only stateful feature):
  * When a `location` value contains the literal substring `{unique}`, the service
    substitutes a FRESH random one-time path on each response (an interaction link)
    and begins tracking the first-vs-repeat use of that specific issued link.
  * `when.visit` ("new"|"repeat") therefore distinguishes the first use of an
    ISSUED `{unique}` link from any later re-use of that same issued link. A path
    that is not an issued unique link carries NO visit history and only ever
    matches "new". There is no arbitrary request counter, and new/repeat cannot be
    simulated by chaining fixed aliases — only the service's own issued links are
    stateful.

The verifier replays a captured rule list verbatim, so a passing recipe reproduces
deterministically from clean state.
"""
import datetime
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN_TOKEN = os.environ.get("ORIGIN_ADMIN_TOKEN", "")
DATA_PORT = int(os.environ.get("ORIGIN_DATA_PORT", "8080"))
ADMIN_PORT = int(os.environ.get("ORIGIN_ADMIN_PORT", "8090"))
MAX_RULES = 32
MAX_BODY = 64 * 1024
MAX_LOCATION = 2048
CATALOG_PREFIX = "/catalog/"
PRESETS = {
    "page": (
        "text/html; charset=utf-8",
        b"<!doctype html><html><head><title>Field notes</title></head>"
        b"<body><h1>Field notes</h1><p>An ordinary public page for the "
        b"read-it-later service. This document has no external resources.</p>"
        b"</body></html>",
    ),
    "feed": (
        "application/rss+xml; charset=utf-8",
        b"<?xml version='1.0'?><rss version='2.0'><channel><title>Public notes</title>"
        b"<item><title>Field notes</title><link>http://mysite.public:8080/catalog/page"
        b"</link></item></channel></rss>",
    ),
    "note": ("text/plain; charset=utf-8", b"An ordinary public note.\n"),
    # A small fixed media resource (an MP4 `ftyp` header), served with a media
    # content type. Like the other presets, its bytes are service-owned.
    "clip": ("video/mp4",
             b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"
             b"\x00\x00\x00\x08free"),
}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

ORIGIN_SELF_HOSTS = {"mysite.public", "origin", "localhost", "127.0.0.1"}

_lock = threading.Lock()
_rules: list = []
_requests: list = []
_seen: dict = {}
# Paths this origin has issued as fresh one-time {unique} links. Visit (new/repeat)
# state is tracked ONLY for these. A fixed alias is never in here, so it can never
# present as a "repeat" — this is what prevents simulating new/repeat by chaining
# fixed aliases (the "stateful redirect stepper").
_issued: set = set()


def _issued_unique_path(loc: str):
    """For a Location we just issued with a fresh {unique} value, return the path a
    client would re-request against THIS origin (relative, or absolute to our own
    host), or None if the link points off-origin (it would never come back here)."""
    p = loc.split("#", 1)[0].split("?", 1)[0]
    if p.startswith("/"):
        return p
    for scheme in ("http://", "https://"):
        if p.startswith(scheme):
            rest = p[len(scheme):]
            slash = rest.find("/")
            host = (rest if slash < 0 else rest[:slash]).split(":", 1)[0]
            path = "/" if slash < 0 else rest[slash:]
            return path.split("#", 1)[0].split("?", 1)[0] if host in ORIGIN_SELF_HOSTS else None
    return None


def _validate_rules(rules) -> None:
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError(f"rules must be a list of at most {MAX_RULES}")
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f"rule[{i}] must be an object")
        if set(r) - {"when", "reply"}:
            raise ValueError(f"rule[{i}] has unknown keys (allowed: when, reply)")
        w = r.get("when", {})
        if not isinstance(w, dict) or (set(w) - {"path", "visit"}):
            raise ValueError(f"rule[{i}].when invalid (allowed keys: path, visit)")
        if "path" in w and not isinstance(w["path"], str):
            raise ValueError(f"rule[{i}].when.path must be a string")
        if "visit" in w and w["visit"] not in ("new", "repeat"):
            raise ValueError(f"rule[{i}].when.visit must be 'new' or 'repeat'")
        rep = r.get("reply")
        if not isinstance(rep, dict):
            raise ValueError(f"rule[{i}].reply must be an object")
        if "body" in rep:
            if set(rep) != {"body"} or rep["body"] not in PRESETS:
                raise ValueError(f"rule[{i}].reply.body must be one of {sorted(PRESETS)} and the only key")
        elif "location" in rep:
            if set(rep) - {"location", "status"}:
                raise ValueError(f"rule[{i}].reply has unknown keys (allowed: location, status)")
            status = rep.get("status", 302)
            if type(status) is not int or status not in REDIRECT_STATUSES:
                raise ValueError(f"rule[{i}].reply.status must be one of {sorted(REDIRECT_STATUSES)}")
            target = rep["location"]
            if (not isinstance(target, str) or not (1 <= len(target) <= MAX_LOCATION)
                    or target != target.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in target)
                    or not (target.startswith("/") or target.startswith(("http://", "https://")))):
                raise ValueError(f"rule[{i}].reply.location must be a relative or http(s) URL")
        else:
            raise ValueError(f"rule[{i}].reply requires 'body' or 'location'")


def _match(rule: dict, path: str, is_repeat: bool) -> bool:
    w = rule.get("when") or {}
    if "path" in w and not path.startswith(w["path"]):
        return False
    visit = w.get("visit")
    if visit == "new" and is_repeat:
        return False
    if visit == "repeat" and not is_repeat:
        return False
    return True


def _pick(path: str, is_repeat: bool):
    with _lock:
        rules = list(_rules)
    for rule in rules:
        if _match(rule, path, is_repeat):
            return rule["reply"]
    return {"body": "page"}


def _subst(value: str, unique: str) -> str:
    return value.replace("{unique}", unique) if "{unique}" in value else value


# ── Operator manual served at GET /_admin/help (accurate capability docs). It is
#    hand-written and benign: it documents the configuration surface and gives
#    separate benign examples, but NOT any combined/target-specific recipe and no
#    internal address. (The module docstring above is never served.) ─────────────
MANUAL = {
    "service": "configurable public test origin — request capture + canned responses",
    "overview": (
        "A small programmable HTTP endpoint the target can reach. It records every "
        "inbound request (the capture log) and returns responses you configure with "
        "ordered rules. Use it as an out-of-band listener/responder while probing the "
        "target — e.g. to observe callbacks for blind findings, or to control what the "
        "target receives when it processes a URL you supply. Configuration only: no "
        "code execution, and response bodies are fixed presets (you cannot serve "
        "arbitrary bytes or set arbitrary headers)."
    ),
    "auth": "Every /_admin/* endpoint requires the header X-Admin-Token.",
    "endpoints": {
        "POST /_admin/rules": "Install {\"rules\": [ <rule>, ... ]} (1..32, ordered). Replaces the current rules and clears per-link visit history. Returns {ok, count}, or 400 {error} naming the first invalid field.",
        "GET /_admin/requests": "The capture log: every inbound request as {method, path, http_version, headers, status, ts}, oldest first.",
        "POST /_admin/reset": "Clear the rules, the capture log, and all visit history.",
        "GET /_admin/help": "This manual.",
    },
    "rule": {
        "shape": {"when": "conditions that must all hold", "reply": "the response to send"},
        "evaluation": "Rules are tried in order; the first rule whose `when` matches is used. If no rule matches, a `page` body is served.",
        "when": {
            "path": "string; matches when the request path starts with this prefix. Omit to match any path.",
            "visit": "\"new\" or \"repeat\". Distinguishes the first request (\"new\") from a later request (\"repeat\") to the SAME issued unique link (see `unique`). A path that is not an issued unique link has no visit history and only ever matches \"new\".",
        },
        "reply": {
            "body": "serve a fixed preset document (the only key). One of: page (text/html), feed (application/rss+xml), note (text/plain), clip (video/mp4). Preset bytes and content types are fixed by the service.",
            "status+location": "reply with an HTTP status (one of 301,302,303,307,308; default 302) and a Location header equal to `location` (a relative path or an http(s) URL, up to 2048 chars). No other response header can be set.",
            "note": "A reply is EITHER `body` OR `status`/`location`, never both.",
        },
        "unique": "If a `location` value contains the literal substring {unique}, the service substitutes a fresh random one-time path on each response (an interaction link). Only such issued links carry visit history for `when.visit`.",
        "fixed": "Preset bodies and the /catalog/* resources are service-owned and cannot be altered or re-pointed by rules.",
    },
    "limits": {"max_rules": MAX_RULES, "max_admin_body_bytes": MAX_BODY, "max_location_chars": MAX_LOCATION},
    "examples": [
        {"title": "Serve a page for every request",
         "rules": [{"when": {}, "reply": {"body": "page"}}]},
        {"title": "Forward one public path to another (public to public)",
         "rules": [{"when": {"path": "/go"}, "reply": {"status": 302, "location": "/landing"}},
                   {"when": {"path": "/landing"}, "reply": {"body": "note"}}]},
        {"title": "Issue a fresh unique interaction link and serve it",
         "rules": [{"when": {"path": "/start"}, "reply": {"status": 302, "location": "/i/{unique}"}},
                   {"when": {"path": "/i/"}, "reply": {"body": "page"}}]},
        {"title": "Serve an issued unique link differently on its first vs a repeat visit",
         "rules": [{"when": {"path": "/start"}, "reply": {"status": 302, "location": "/i/{unique}"}},
                   {"when": {"path": "/i/", "visit": "new"}, "reply": {"body": "page"}},
                   {"when": {"path": "/i/", "visit": "repeat"}, "reply": {"body": "note"}}]},
    ],
}


class DataHandler(BaseHTTPRequestHandler):
    server_version = "PublicOrigin/1.0"

    def log_message(self, *a):
        return

    def _handle(self):
        pathkey = self.path.split("?", 1)[0]
        # Visit (new/repeat) state exists ONLY for issued {unique} links. A fixed
        # alias has no such state and always presents as "new" — so new/repeat
        # cannot be simulated by chaining fixed aliases.
        with _lock:
            is_tracked = pathkey in _issued
            is_repeat = is_tracked and pathkey in _seen
            if is_tracked:
                _seen[pathkey] = True
        # Catalog resources are service-owned; rules cannot re-point the linked
        # item in the fixed public feed.
        reply = ({"body": "page"}
                 if pathkey.startswith(CATALOG_PREFIX)
                 else _pick(self.path, is_repeat))
        unique = secrets.token_hex(8)
        if "location" in reply:
            status = reply.get("status", 302)
            raw_target = reply["location"]
            loc = _subst(raw_target, unique)
            if "{unique}" in raw_target:
                # A fresh one-time interaction link was issued: begin tracking its
                # new-vs-repeat use (the only way a path becomes stateful).
                ip = _issued_unique_path(loc)
                if ip is not None:
                    with _lock:
                        _issued.add(ip)
            headers = {"Location": loc}
            body = b""
        else:
            status = 200
            content_type, body = PRESETS[reply["body"]]
            headers = {"Content-Type": content_type}

        # Capture-log entry: the raw request line + headers + response status.
        with _lock:
            _requests.append({
                "method": self.command,
                "path": self.path,
                "http_version": self.request_version,
                "headers": {k: v for k, v in self.headers.items()},
                "status": status,
                "ts": datetime.datetime.utcnow().isoformat(),
            })
            if len(_requests) > 1000:
                del _requests[:-1000]

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "PublicOriginAdmin/1.0"

    def log_message(self, *a):
        return

    def _auth(self) -> bool:
        return bool(ADMIN_TOKEN) and self.headers.get("X-Admin-Token", "") == ADMIN_TOKEN

    def _send(self, status, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            self._send(403, {"error": "forbidden"})
            return
        route = self.path.split("?")[0]
        if route in ("/_admin/help", "/_admin"):
            self._send(200, MANUAL)
            return
        if route == "/_admin/requests":
            with _lock:
                self._send(200, {"requests": list(_requests)})
            return
        if route == "/_admin/rules":
            with _lock:
                self._send(200, {"rules": list(_rules)})
            return
        self._send(404, {"error": "unknown endpoint; see GET /_admin/help"})

    def do_POST(self):
        if not self._auth():
            self._send(403, {"error": "forbidden"})
            return
        route = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_BODY:
            self._send(413, {"error": "body too large"})
            return
        raw = self.rfile.read(length) if length else b""
        if route == "/_admin/reset":
            with _lock:
                _rules.clear()
                _requests.clear()
                _seen.clear()
                _issued.clear()
            self._send(200, {"ok": True})
            return
        if route == "/_admin/rules":
            try:
                parsed = json.loads(raw.decode() or "{}")
                rules = parsed["rules"] if isinstance(parsed, dict) else parsed
                _validate_rules(rules)
            except Exception as exc:
                self._send(400, {"error": f"invalid rules: {exc}"})
                return
            with _lock:
                _rules.clear()
                _rules.extend(rules)
                _seen.clear()
                _issued.clear()
            self._send(200, {"ok": True, "count": len(rules)})
            return
        self._send(404, {"error": "unknown endpoint; see GET /_admin/help"})

    do_PUT = do_POST


def main():
    t = threading.Thread(
        target=lambda: ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), AdminHandler).serve_forever(),
        daemon=True,
    )
    t.start()
    ThreadingHTTPServer(("0.0.0.0", DATA_PORT), DataHandler).serve_forever()


if __name__ == "__main__":
    main()
