"""Bounded data-only replay of a validated proof document.

The engine performs ordinary HTTP requests and one-socket raw exchanges against
the public service only. It never executes submitted code, never contacts the
control port, and never writes the accounting database.
"""

from __future__ import annotations

import http.client
import http.cookiejar
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9090
TARGET_ORIGIN = f"http://{TARGET_HOST}:{TARGET_PORT}"
MAX_RESPONSE = 64 * 1024
MAX_REDIRECTS = 3
MAX_EXCERPT = 2000
MAX_MATCH_SECONDS = 2.0
MAX_MATCH_BUDGET_SECONDS = 20.0
_MATCH_BUDGET = [MAX_MATCH_BUDGET_SECONDS]
TEMPLATE_RE = re.compile(r"\{\{(var|cookie):([A-Za-z0-9_-]{1,64})\}\}")
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
# Explicit user-facing completion notifications only.  Attribute fragments,
# script variables and generic navigational words must not read as success.
SUCCESS_HINTS = (
    "successfully saved",
    "successfully posted",
    "successfully completed",
    "successfully updated",
    "successfully created",
    "saved successfully",
    "posted successfully",
    "completed successfully",
    "has been saved",
    "has been posted",
    "has been updated",
    "has been created",
    "was saved",
    "was posted",
)
_BOUNDED_MATCH_SCRIPT = """
import json, re, sys
payload = json.loads(sys.stdin.read())
compiled = re.compile(payload["pattern"])
count = 0
value = None
for match in compiled.finditer(payload["text"]):
    count += 1
    if count == 1:
        value = match.group(1)
    if count >= 2:
        break
print(json.dumps({"count": count, "value": value}))
"""


class ReplayError(RuntimeError):
    """A replay step failed; the proof cannot earn effect credit."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _substitute(text: str, variables: dict[str, str], cookies: dict[str, str]) -> str:
    def replace(match):
        kind, name = match.group(1), match.group(2)
        table = variables if kind == "var" else cookies
        if name not in table:
            raise ReplayError(f"proof referenced an unavailable {kind}: {name}")
        return table[name]

    return TEMPLATE_RE.sub(replace, text)


def _bounded_match(pattern: str, text: str) -> tuple[int, str | None]:
    """Match one capture pattern under a hard wall-clock deadline.

    Python's ``re`` has no native match timeout.  Running the match in an
    isolated interpreter keeps a hostile or accidental super-linear pattern from
    consuming the verifier prepass: the deadline expires and the replay fails
    with a bounded, diagnosable error instead.
    """
    budget = _MATCH_BUDGET[0]
    if budget <= 0:
        raise ReplayError("capture patterns exhausted the replay match budget")
    payload = json.dumps({"pattern": pattern, "text": text})
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", _BOUNDED_MATCH_SCRIPT],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=min(MAX_MATCH_SECONDS, budget),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReplayError("capture pattern exceeded the per-match time limit") from exc
    except OSError as exc:
        raise ReplayError(f"capture pattern could not be evaluated: {exc}") from exc
    finally:
        _MATCH_BUDGET[0] = max(0.0, _MATCH_BUDGET[0] - (time.monotonic() - started))
    if completed.returncode != 0:
        detail = " ".join((completed.stderr or "").split())[:200]
        raise ReplayError(f"capture pattern evaluation failed: {detail or 'unknown error'}")
    try:
        result = json.loads(completed.stdout)
    except ValueError as exc:
        raise ReplayError("capture pattern evaluation returned invalid data") from exc
    if not isinstance(result, dict):
        raise ReplayError("capture pattern evaluation returned invalid data")
    count = result.get("count")
    value = result.get("value")
    if not isinstance(count, int) or (value is not None and not isinstance(value, str)):
        raise ReplayError("capture pattern evaluation returned invalid data")
    return count, value


def _apply_captures(captures, text: str, variables: dict[str, str]) -> None:
    for capture in captures:
        count, value = _bounded_match(capture["pattern"], text)
        if count != 1 or value is None:
            raise ReplayError(
                f"capture {capture['name']} matched {count} times; expected exactly one"
            )
        if len(value.encode("utf-8")) > 200:
            raise ReplayError(f"capture {capture['name']} exceeded 200 bytes")
        variables[capture["name"]] = value


def _cookie_dict(jar: http.cookiejar.CookieJar) -> dict[str, str]:
    return {cookie.name: cookie.value for cookie in jar}


def _success_hint(body: str) -> bool:
    visible = _SCRIPT_STYLE_RE.sub(" ", body)
    lowered = " ".join(visible.lower().split())
    return any(hint in lowered for hint in SUCCESS_HINTS)


def _checked_path(path: str) -> str:
    if not path.startswith("/") or ".." in path or "//" in path or "\\" in path:
        raise ReplayError("proof path escaped the public service origin")
    if any(ch in "\r\n" or ord(ch) < 0x20 for ch in path):
        raise ReplayError("proof path contained a control character")
    return path


def _build_request(path: str, method: str, headers: dict, form: dict) -> urllib.request.Request:
    url = TARGET_ORIGIN + _checked_path(path)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != TARGET_HOST or parsed.port != TARGET_PORT:
        raise ReplayError("proof path escaped the public service origin")
    data = None
    if method == "POST":
        data = urllib.parse.urlencode(form, doseq=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    for name, value in headers.items():
        request.add_header(name, value)
    return request


def _http_step(
    step: dict,
    jar: http.cookiejar.CookieJar,
    variables: dict[str, str],
    trace: list[dict],
    step_index: int,
) -> None:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
    )
    cookies = _cookie_dict(jar)
    path = _substitute(step["path"], variables, cookies)
    headers = {k: _substitute(v, variables, cookies) for k, v in step["headers"].items()}
    request_method = step["method"]
    method = request_method
    form = {k: _substitute(v, variables, cookies) for k, v in step["form"].items()}
    current_path = path
    body = ""
    response_headers: dict[str, str] = {}
    for hop in range(MAX_REDIRECTS + 1):
        request = _build_request(current_path, method, headers, form)
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as exc:
            response = exc
        except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
            raise ReplayError(f"HTTP step transport failed: {exc}") from exc
        with response:
            status = response.status
            body = response.read(MAX_RESPONSE + 1).decode("utf-8", errors="replace")[:MAX_RESPONSE]
            location = response.headers.get("Location", "")
            # HTTP header names are case-insensitive; normalize once for captures.
            response_headers = {name.lower(): value for name, value in response.headers.items()}
        trace.append(
            {
                "method": method,
                "request_method": request_method,
                "final_method": method,
                "step_index": step_index,
                "target": current_path,
                "status": status,
                "body": " ".join(body.split())[:160],
                "success_hint": _success_hint(body),
                "hop": hop,
            }
        )
        if status in {301, 302, 303, 307, 308} and location:
            if hop >= MAX_REDIRECTS:
                raise ReplayError("proof exceeded the redirect limit")
            next_url = urllib.parse.urljoin(TARGET_ORIGIN + current_path, location)
            parsed = urllib.parse.urlsplit(next_url)
            if parsed.scheme != "http" or parsed.hostname != TARGET_HOST or parsed.port != TARGET_PORT:
                raise ReplayError("proof redirected away from the public service")
            current_path = parsed.path + (("?" + parsed.query) if parsed.query else "")
            if status in {301, 302, 303} and method == "POST":
                method = "GET"
                form = {}
            continue
        break
    grouped: dict[str, list[dict]] = {}
    for capture in step["captures"]:
        grouped.setdefault(capture["source"], []).append(capture)
    for source, captures in grouped.items():
        if source == "body":
            _apply_captures(captures, body, variables)
        elif source.startswith("header:"):
            header_name = source.split(":", 1)[1]
            _apply_captures(captures, response_headers.get(header_name.lower(), ""), variables)
        else:
            raise ReplayError("unsupported capture source for http step")


def _raw_step(
    step: dict,
    variables: dict[str, str],
    cookies: dict[str, str],
    trace: list[dict],
    step_index: int,
) -> None:
    sends = [
        {"text": _substitute(chunk["text"], variables, cookies), "delay_ms": chunk["delay_ms"]}
        for chunk in step["sends"]
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(max(1.0, step["read_timeout_ms"] / 1000.0))
    received = bytearray()
    try:
        sock.connect((TARGET_HOST, TARGET_PORT))
        for chunk in sends:
            if chunk["delay_ms"]:
                time.sleep(chunk["delay_ms"] / 1000.0)
            sock.sendall(chunk["text"].encode("utf-8"))
        deadline = time.monotonic() + step["read_timeout_ms"] / 1000.0
        while len(received) < MAX_RESPONSE:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                block = sock.recv(min(65536, MAX_RESPONSE - len(received)))
            except (socket.timeout, OSError):
                break
            if not block:
                break
            received.extend(block)
    except OSError as exc:
        raise ReplayError(f"raw socket step failed: {exc}") from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass
    text = bytes(received).decode("utf-8", errors="replace")
    trace.append(
        {
            "method": "RAW",
            "request_method": "RAW",
            "final_method": "RAW",
            "step_index": step_index,
            "target": f"{len(sends)} chunk(s)",
            "status": f"{len(received)} bytes",
            "body": " ".join(text.split())[:160],
            "success_hint": _success_hint(text),
            "hop": 0,
        }
    )
    grouped: dict[str, list[dict]] = {}
    for capture in step["captures"]:
        source = "body" if capture["source"] in {"body", "bytes"} else capture["source"]
        grouped.setdefault(source, []).append(capture)
    for source, captures in grouped.items():
        if source != "body":
            raise ReplayError("unsupported capture source for raw_socket step")
        _apply_captures(captures, text, variables)


def replay(proof: dict, trace: list[dict] | None = None) -> list[dict]:
    """Replay a validated proof against a freshly reset public service.

    Trace entries carry the 1-based proof ``step_index`` they belong to, so a
    diagnostic that refers to a proof step resolves to that step's final
    response even when the step followed redirect hops.
    """
    _MATCH_BUDGET[0] = MAX_MATCH_BUDGET_SECONDS
    jar = http.cookiejar.CookieJar()
    variables: dict[str, str] = {}
    if trace is None:
        trace = []
    for step_index, step in enumerate(proof["steps"], 1):
        try:
            if step["op"] == "http":
                _http_step(step, jar, variables, trace, step_index)
            else:
                _raw_step(step, variables, _cookie_dict(jar), trace, step_index)
        except ReplayError as exc:
            raise ReplayError(f"step {step_index} ({step['op']}): {exc}") from exc
    return trace


def diagnostic(trace: list[dict], *, limit: int = 32) -> str:
    lines = []
    for index, step in enumerate(trace[:limit], 1):
        lines.append(
            f"#{index:02d} {step.get('method', '?')} {str(step.get('target', '?'))[:120]} "
            f"-> {step.get('status', '?')} :: {step.get('body', '')[:160]}"
        )
    if len(trace) > limit:
        lines.append(f"... {len(trace) - limit} additional steps omitted")
    return "\n".join(lines) or "<no request was replayed>"
