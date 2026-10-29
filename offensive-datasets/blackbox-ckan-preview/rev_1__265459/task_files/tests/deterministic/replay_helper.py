"""Trusted replay helper for the CKAN preview-export disclosure task.

Validates the submitted declarative proof as DATA, serves its origin routes from
a bounded inert responder in main (exact wire bytes, never re-encoded), and
replays its public operations against the gateway on 127.0.0.1:9090 only. It
supports three operation modes:

  * http         -- send a request to the gateway; optionally extract JSON-Pointer
                    values from the parsed JSON response for use in later ops.
  * raw_capture  -- record the gateway's raw response bytes to a (named) request.
  * extract      -- a generic, bounded dataflow primitive: select the first JSON
                    object embedded in a named raw capture that matches all
                    field==value predicates, and bind fields into new variables,
                    so manifest and ready messages can be associated by identity.

It returns the raw captures (named) and a bounded per-step trace. It never
synthesises the exploit, never targets the control port, serves no grant or
artifact byte, and re-validates every substituted path/header for host/CRLF
escape AFTER substitution.

Imported lazily by the deterministic prepass; stdlib only.
"""
from __future__ import annotations

import base64
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GATEWAY = ("127.0.0.1", 9090)
# The protected artifact pattern (for the no-embed check only; the fresh bytes
# are generated post-reset and cannot be known to a proof).
ARTIFACT_RE = re.compile(rb"ARTIFACT-[0-9a-f]{48}")

# Published proof limits (documented in instruction.md).
MAX_ROUTES = 4
MAX_OPS = 14
MAX_RAW_CAPTURES = 4
MAX_WIRE_BODY = 64 * 1024
MAX_HEADERS = 32
MAX_HEADER_LEN = 4 * 1024
MAX_CAPTURE_BYTES = 128 * 1024
RAW_CAPTURE_MS = 9000        # fixed internal capture window; not a proof field
RAW_CAPTURE_RETRIES = 2      # bounded retry on a transient relay 5xx; not a proof field
RAW_CAPTURE_RETRY_DELAY_S = 0.5
MAX_TOTAL_MS = 60000
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
RAW_CAPTURE_METHODS = {"GET", "HEAD"}
# extract primitive limits
MAX_SCAN_OBJECTS = 512
MAX_OBJ_BYTES = 8192
MAX_BINDINGS = 16
MAX_PREDICATES = 16

_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ProofError(AssertionError):
    """The submitted proof violated the published schema/limits.

    When raised by replay(), the partially observed captures/trace are attached so
    the verifier can still authenticate milestone evidence the proof did capture;
    they are never used to claim the protected effect.
    """

    def __init__(self, message=""):
        super().__init__(message)
        self.captures = {}
        self.trace = []


# --------------------------------------------------------------------------
# schema validation
# --------------------------------------------------------------------------
def _check_headers(headers, where):
    if not isinstance(headers, list) or len(headers) > MAX_HEADERS:
        raise ProofError(f"{where}: headers must be a list of <= {MAX_HEADERS} pairs")
    for pair in headers:
        if (not isinstance(pair, list) or len(pair) != 2
                or not all(isinstance(x, str) for x in pair)):
            raise ProofError(f"{where}: each header must be a [name, value] string pair")
        k, v = pair
        if len(k) > MAX_HEADER_LEN or len(v) > MAX_HEADER_LEN:
            raise ProofError(f"{where}: header exceeds {MAX_HEADER_LEN} bytes")
        if any(c in "\r\n" for c in k + v):
            raise ProofError(f"{where}: CR/LF injection in header")


def _only_keys(obj, allowed, where):
    if not isinstance(obj, dict):
        raise ProofError(f"{where}: expected an object")
    extra = set(obj) - allowed
    if extra:
        raise ProofError(f"{where}: unknown field(s) {sorted(extra)}")


def _no_artifact(text, where):
    data = text.encode() if isinstance(text, str) else text
    if ARTIFACT_RE.search(data):
        raise ProofError(f"{where}: proof must not embed a protected artifact literal")


def _rel_path(path, where):
    if not isinstance(path, str) or not path.startswith("/") or "://" in path \
            or "\r" in path or "\n" in path:
        raise ProofError(f"{where}: path must be a gateway-relative path with no host")
    return path


def _valid_name(name):
    return isinstance(name, str) and _NAME_RE.fullmatch(name) is not None


def validate_proof(proof) -> dict:
    _only_keys(proof, {"version", "origin", "operations"}, "proof")
    if proof.get("version") != 1:
        raise ProofError("proof.version must be 1")

    origin = proof.get("origin")
    _only_keys(origin, {"routes"}, "origin")
    routes = origin.get("routes")
    if not isinstance(routes, list) or not (1 <= len(routes) <= MAX_ROUTES):
        raise ProofError(f"origin.routes must be 1..{MAX_ROUTES} entries")
    seen = set()
    for i, r in enumerate(routes):
        _only_keys(r, {"path", "HEAD", "GET"}, f"route[{i}]")
        p = _rel_path(r.get("path"), f"route[{i}].path")
        if p in seen:
            raise ProofError(f"route[{i}].path duplicated: {p}")
        seen.add(p)
        if "HEAD" not in r and "GET" not in r:
            raise ProofError(f"route[{i}] needs HEAD and/or GET")
        for verb in ("HEAD", "GET"):
            if verb not in r:
                continue
            spec = r[verb]
            allowed = {"status", "headers"} | ({"wire_body_b64"} if verb == "GET" else set())
            _only_keys(spec, allowed, f"route[{i}].{verb}")
            st = spec.get("status")
            if not isinstance(st, int) or not (200 <= st <= 599):
                raise ProofError(f"route[{i}].{verb}.status must be 200..599")
            _check_headers(spec.get("headers", []), f"route[{i}].{verb}")
            for _, v in spec.get("headers", []):
                _no_artifact(v, f"route[{i}].{verb} header")
            if verb == "GET":
                b64 = spec.get("wire_body_b64", "")
                if not isinstance(b64, str):
                    raise ProofError(f"route[{i}].GET.wire_body_b64 must be a string")
                try:
                    body = base64.b64decode(b64, validate=True) if b64 else b""
                except Exception as exc:
                    raise ProofError(f"route[{i}].GET.wire_body_b64 invalid base64: {exc}")
                if len(body) > MAX_WIRE_BODY:
                    raise ProofError(f"route[{i}].GET.wire_body exceeds {MAX_WIRE_BODY} bytes")
                _no_artifact(body, f"route[{i}].GET.wire_body")

    ops = proof.get("operations")
    if not isinstance(ops, list) or not (1 <= len(ops) <= MAX_OPS):
        raise ProofError(f"operations must be 1..{MAX_OPS} entries")
    raw_count = 0
    capture_names = set()
    for i, op in enumerate(ops):
        mode = op.get("mode")
        if mode == "http":
            _only_keys(op, {"mode", "method", "path", "headers", "json", "extract"}, f"op[{i}]")
            if op.get("method") not in ALLOWED_METHODS:
                raise ProofError(f"op[{i}].method invalid")
            _rel_path(op.get("path"), f"op[{i}].path")
            _check_headers(op.get("headers", []), f"op[{i}]")
            if "json" in op and not isinstance(op["json"], (dict, list)):
                raise ProofError(f"op[{i}].json must be object/array")
            if "extract" in op:
                ex = op["extract"]
                if not isinstance(ex, dict):
                    raise ProofError(f"op[{i}].extract must be an object")
                for name, ptr in ex.items():
                    if not _valid_name(name):
                        raise ProofError(f"op[{i}].extract name invalid: {name}")
                    if not isinstance(ptr, str) or not ptr.startswith("/"):
                        raise ProofError(f"op[{i}].extract pointer must be a JSON Pointer")
        elif mode == "raw_capture":
            _only_keys(op, {"mode", "method", "path", "headers", "name"}, f"op[{i}]")
            if op.get("method") not in RAW_CAPTURE_METHODS:
                raise ProofError(f"op[{i}] raw_capture method must be GET or HEAD")
            _rel_path(op.get("path"), f"op[{i}].path")
            _check_headers(op.get("headers", []), f"op[{i}]")
            name = op.get("name", f"cap{raw_count}")
            if not _valid_name(name):
                raise ProofError(f"op[{i}].name invalid: {name}")
            if name in capture_names:
                raise ProofError(f"op[{i}].name duplicated: {name}")
            capture_names.add(name)
            raw_count += 1
        elif mode == "extract":
            _only_keys(op, {"mode", "from", "find", "where", "bind"}, f"op[{i}]")
            frm = op.get("from")
            froms = frm if isinstance(frm, list) else [frm]
            if not froms or not all(isinstance(f, str) for f in froms):
                raise ProofError(f"op[{i}].from must name a capture (or list of captures)")
            for f in froms:
                if f not in capture_names:
                    raise ProofError(f"op[{i}].from references unknown capture {f!r}")
            if op.get("find") != "json_object":
                raise ProofError(f"op[{i}].find must be 'json_object'")
            where = op.get("where", [])
            if not isinstance(where, list) or len(where) > MAX_PREDICATES:
                raise ProofError(f"op[{i}].where must be a list of <= {MAX_PREDICATES} predicates")
            for pr in where:
                if (not isinstance(pr, list) or len(pr) != 2
                        or not isinstance(pr[0], str) or not pr[0].startswith("/")
                        or not isinstance(pr[1], str)):
                    raise ProofError(f"op[{i}].where: each predicate is [json_pointer, expected_str]")
            bind = op.get("bind", {})
            if not isinstance(bind, dict) or not (1 <= len(bind) <= MAX_BINDINGS):
                raise ProofError(f"op[{i}].bind must be 1..{MAX_BINDINGS} name->pointer")
            for name, ptr in bind.items():
                if not _valid_name(name):
                    raise ProofError(f"op[{i}].bind name invalid: {name}")
                if not isinstance(ptr, str) or not ptr.startswith("/"):
                    raise ProofError(f"op[{i}].bind pointer must be a JSON Pointer")
        else:
            raise ProofError(f"op[{i}].mode must be 'http', 'raw_capture', or 'extract'")
    if raw_count == 0:
        raise ProofError("operations must include at least one raw_capture")
    if raw_count > MAX_RAW_CAPTURES:
        raise ProofError(f"at most {MAX_RAW_CAPTURES} raw_capture operations allowed")
    return proof


# --------------------------------------------------------------------------
# inert origin (serves the proof's declared wire bytes verbatim; main-side)
# --------------------------------------------------------------------------
def _make_handler(routes):
    table = {}
    for r in routes:
        entry = dict(r)
        get = r.get("GET")
        if get is not None:
            entry["GET"] = dict(get)
            entry["GET"]["_body"] = base64.b64decode(get.get("wire_body_b64", "") or "", validate=True)
        table[r["path"]] = entry

    class Inert(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _spec(self, verb):
            r = table.get(self.path.split("?", 1)[0])
            return (r or {}).get(verb)

        def _emit(self, verb, write_body):
            spec = self._spec(verb)
            if spec is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self.send_response(int(spec["status"]))
            for k, v in spec.get("headers", []):
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            if write_body and verb == "GET":
                self.wfile.write(spec.get("_body", b""))

        def do_HEAD(self):
            self._emit("HEAD", False)

        def do_GET(self):
            self._emit("GET", True)

    return Inert


class InertOrigin:
    def __init__(self, routes):
        self.routes = routes
        self.server = None

    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self.routes))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        host, port = self.server.server_address
        return f"http://127.0.0.1:{port}"

    def __exit__(self, *a):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


# --------------------------------------------------------------------------
# substitution / json pointer / matcher
# --------------------------------------------------------------------------
def _subst(value, variables):
    if isinstance(value, str):
        def repl(m):
            name = m.group(1)
            if name not in variables:
                raise ProofError(f"undefined variable ${{{name}}}")
            return str(variables[name])
        return _VAR_RE.sub(repl, value)
    if isinstance(value, list):
        return [_subst(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: _subst(v, variables) for k, v in value.items()}
    return value


def _json_pointer(doc, pointer):
    cur = doc
    for raw in pointer.split("/")[1:]:
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            cur = cur.get(tok)
        elif isinstance(cur, list) and tok.isdigit():
            cur = cur[int(tok)] if int(tok) < len(cur) else None
        else:
            return None
    return cur


def _find_json_objects(data: bytes, limit=MAX_SCAN_OBJECTS):
    """Yield JSON objects embedded anywhere in `data`, left to right. Bounded:
    at most `limit` candidate '{' positions; each decode reads <= MAX_OBJ_BYTES."""
    dec = json.JSONDecoder()
    text = data.decode("latin-1")   # lossless 1:1 byte->char for scanning
    i, n, examined = 0, len(text), 0
    while i < n and examined < limit:
        j = text.find("{", i)
        if j < 0:
            break
        examined += 1
        try:
            obj, end = dec.raw_decode(text[j:j + MAX_OBJ_BYTES])
            if isinstance(obj, dict):
                yield obj
                i = j + end
                continue
        except ValueError:
            pass
        i = j + 1


def _apply_extract(op, captures, variables):
    frm = op["from"]
    froms = frm if isinstance(frm, list) else [frm]
    preds = [(ptr, _subst(exp, variables)) for ptr, exp in op.get("where", [])]
    for name in froms:
        for obj in _find_json_objects(captures.get(name, b"")):
            if all(_eq(_json_pointer(obj, ptr), exp) for ptr, exp in preds):
                out = {}
                for vname, ptr in op["bind"].items():
                    val = _json_pointer(obj, ptr)
                    if val is None:
                        raise ProofError(f"extract: bind {vname!r} resolved to null")
                    out[vname] = val
                return out
    raise ProofError("extract: no captured object matched predicates")


def _eq(actual, expected):
    return actual is not None and str(actual) == str(expected)


def _safe_path_after_subst(path):
    if "://" in path or "\r" in path or "\n" in path or " " in path:
        raise ProofError(f"path not gateway-relative after substitution: {path!r}")
    return path


def _safe_headers_after_subst(pairs):
    for k, v in pairs:
        if any(c in "\r\n" for c in k + v):
            raise ProofError("CR/LF in header after substitution")
    return pairs


# --------------------------------------------------------------------------
# replay
# --------------------------------------------------------------------------
def _http_op(op, variables, trace):
    method = op["method"]
    path = _safe_path_after_subst(_subst(op["path"], variables))
    headers = {k: v for k, v in _safe_headers_after_subst(
        [(_subst(k, variables), _subst(v, variables)) for k, v in op.get("headers", [])])}
    body = None
    if "json" in op:
        body = json.dumps(_subst(op["json"], variables)).encode()
        headers.setdefault("Content-Type", "application/json")
    import urllib.request
    import urllib.error
    req = urllib.request.Request("http://%s:%d%s" % (GATEWAY[0], GATEWAY[1], path),
                                 data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    status, text = 0, ""
    try:
        with opener.open(req, timeout=15) as r:
            status = r.status
            text = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        text = f"<transport error: {e}>"
    trace.append({"op": "http", "method": method, "target": path, "status": status,
                  "body": text[:200]})
    extracted = {}
    if "extract" in op and text:
        try:
            doc = json.loads(text)
            for name, ptr in op["extract"].items():
                extracted[name] = _json_pointer(doc, ptr)
        except ValueError:
            pass
    return extracted


def _capture_once(request, read_ms):
    """One bounded raw capture attempt. Returns (data, os_error_or_None)."""
    data = b""
    t0 = time.time()
    try:
        s = socket.create_connection(GATEWAY, timeout=max(2, read_ms / 1000 + 2))
        try:
            s.sendall(request)
            while (time.time() - t0) * 1000 < read_ms and len(data) < MAX_CAPTURE_BYTES:
                s.settimeout(max(0.1, read_ms / 1000 - (time.time() - t0)))
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
    except OSError as e:
        return b"", e
    return data, None


def _transient_5xx(data: bytes) -> bool:
    """A relay 5xx response is infrastructure noise, not a captured disclosure."""
    line = data.split(b"\r\n", 1)[0]
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", line)
    return bool(m) and 500 <= int(m.group(1)) < 600


def _raw_capture(op, variables, trace):
    path = _safe_path_after_subst(_subst(op["path"], variables))
    headers = _safe_headers_after_subst(
        [(_subst(k, variables), _subst(v, variables)) for k, v in op.get("headers", [])])
    read_ms = RAW_CAPTURE_MS
    method = op["method"]  # validated before replay; honor the published operation
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: localhost", "Connection: keep-alive"]
    for k, v in headers:
        lines.append("%s: %s" % (k, v))
    request = ("\r\n".join(lines) + "\r\n\r\n").encode()
    data = b""
    error = None
    attempts = 0
    retries = 0
    while True:
        attempts += 1
        data, error = _capture_once(request, read_ms)
        if error is None and not _transient_5xx(data):
            break
        if attempts > RAW_CAPTURE_RETRIES:
            break
        retries += 1
        time.sleep(RAW_CAPTURE_RETRY_DELAY_S)
    if error is not None:
        trace.append({"op": "raw_capture", "method": method, "target": path, "status": "raw",
                      "body": f"<error {error}>", "attempts": attempts, "retries": retries})
        return b""
    trace.append({"op": "raw_capture", "method": method, "target": path, "status": "raw",
                  "body": f"<{len(data)} bytes captured>", "attempts": attempts,
                  "retries": retries})
    return data


def replay(proof, origin_base, variables):
    """Run the proof's operations; return (captures: dict[name->bytes], trace).

    On a proof error the partial captures/trace are attached to the exception so
    the verifier can still authenticate milestone evidence the proof did capture.
    They are never used to claim the protected effect.
    """
    variables = dict(variables)
    variables["ORIGIN_BASE"] = origin_base
    captures = {}
    trace = []
    raw_idx = 0
    deadline = time.time() + MAX_TOTAL_MS / 1000
    try:
        for op_index, op in enumerate(proof["operations"]):
            if time.time() > deadline:
                raise ProofError("replay exceeded total time budget")
            mode = op["mode"]
            if mode == "http":
                variables.update({k: v for k, v in _http_op(op, variables, trace).items()
                                  if v is not None})
            elif mode == "raw_capture":
                name = op.get("name", f"cap{raw_idx}")
                raw_idx += 1
                captures[name] = _raw_capture(op, variables, trace)
            elif mode == "extract":
                try:
                    variables.update(_apply_extract(op, captures, variables))
                except ProofError as exc:
                    frm = op.get("from")
                    names = frm if isinstance(frm, list) else [frm]
                    pointers = [str(pred[0]) for pred in op.get("where", [])
                                if isinstance(pred, (list, tuple)) and pred]
                    sizes = {str(name): len(captures.get(name, b"")) for name in names}
                    raise ProofError(
                        f"extract op={op_index} failed: {exc}; predicates={pointers}; "
                        f"capture_sizes={sizes}") from None
    except ProofError as exc:
        exc.captures = dict(captures)
        exc.trace = list(trace)
        raise
    return captures, trace
