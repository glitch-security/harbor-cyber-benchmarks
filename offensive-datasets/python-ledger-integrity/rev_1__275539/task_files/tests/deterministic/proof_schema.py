"""Strict validator for the submitted proof document.

The validator is pure: it never contacts the target. It enforces the published
data-only contract in ``/testbed/proof-format.md`` before any traffic is sent.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field

MAX_PROOF_BYTES = 64 * 1024
MAX_STEPS = 20
MAX_SENDS = 8
MAX_HEADERS = 24
MAX_FORM_FIELDS = 24
MAX_CAPTURES = 16
MAX_CAPTURE_NAME = 64
MAX_CAPTURE_VALUE = 200
MAX_EXPLANATION = 500
MAX_STEP_BYTES = 16 * 1024
MAX_TOTAL_BYTES = 256 * 1024
MAX_DIAGNOSTIC_TEXT = 500

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,64}$")
_PATH_RE = re.compile(
    r"^(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/\-{}]*|\{\{var:[A-Za-z0-9_-]{1,64}\}\})$"
)
_TEMPLATE_RE = re.compile(r"\{\{(var|cookie):([A-Za-z0-9_-]{1,64})\}\}")
_SOURCE_RE = re.compile(r"^(body|bytes|header:[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,64})$")


class ProofError(ValueError):
    """The proof document violates the published contract."""


def _object_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProofError(f"duplicate proof field: {key}")
        value[key] = item
    return value


def _no_constants(value):
    raise ProofError(f"non-finite JSON number: {value}")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ProofError("JSON number exceeds finite range")
    return number


def load_proof_bytes(raw: bytes):
    if len(raw) > MAX_PROOF_BYTES:
        raise ProofError("proof exceeded the 64 KiB limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProofError("proof must be UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_no_constants,
            parse_float=_finite_float,
        )
    except ProofError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ProofError(f"proof is not valid JSON: {exc}") from exc


def _exact_keys(value: dict, required: set[str], optional: set[str], where: str) -> None:
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        raise ProofError(f"{where}: missing field(s) {sorted(missing)}")
    if extra:
        raise ProofError(f"{where}: unknown field(s) {sorted(extra)}")


def _string(value, where: str, *, max_len: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ProofError(f"{where}: expected a string")
    if not allow_empty and not value:
        raise ProofError(f"{where}: must not be empty")
    if len(value) > max_len:
        raise ProofError(f"{where}: exceeds {max_len} characters")
    return value


def _int(value, where: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        raise ProofError(f"{where}: expected an integer")
    if not minimum <= value <= maximum:
        raise ProofError(f"{where}: out of range {minimum}..{maximum}")
    return value


def _no_control(text: str, where: str) -> None:
    for ch in text:
        if ch in "\r\n" or ord(ch) < 0x20:
            raise ProofError(f"{where}: contains a control character")


def _validate_templates(text: str, where: str, *, allow_cookie: bool) -> None:
    for match in _TEMPLATE_RE.finditer(text):
        kind = match.group(1)
        if kind == "cookie" and not allow_cookie:
            raise ProofError(f"{where}: cookie substitution is not allowed here")
    stripped = _TEMPLATE_RE.sub("", text)
    if "{{" in stripped or "}}" in stripped:
        raise ProofError(f"{where}: malformed substitution")


_UNSAFE_GROUP_PREFIXES = ("(?=", "(?!", "(?<=", "(?<!", "(?(", "(?>", "(?#", "(?P=")


def _skip_escape(pattern: str, index: int) -> int:
    """Return the index after the escape sequence starting at ``index``."""
    if index + 1 >= len(pattern):
        return index + 1
    nxt = pattern[index + 1]
    if nxt.isdigit() and nxt != "0":
        raise ProofError("capture pattern uses a numeric backreference")
    if nxt in "gk" and index + 2 < len(pattern) and pattern[index + 2] == "<":
        raise ProofError("capture pattern uses a named backreference")
    return index + 2


def _skip_class(pattern: str, index: int) -> int:
    """Return the index after the character class starting at ``index``."""
    cursor = index + 1
    if cursor < len(pattern) and pattern[cursor] == "^":
        cursor += 1
    if cursor < len(pattern) and pattern[cursor] == "]":
        cursor += 1
    while cursor < len(pattern) and pattern[cursor] != "]":
        if pattern[cursor] == "\\":
            cursor = _skip_escape(pattern, cursor)
        else:
            cursor += 1
    if cursor >= len(pattern):
        raise ProofError("capture pattern has an unterminated character class")
    return cursor + 1


def _read_quantifier(pattern: str, index: int):
    """Return ``(end_index, kind)`` when a quantifier starts at ``index``."""
    if index >= len(pattern):
        return index, None
    char = pattern[index]
    if char in "*+?":
        end = index + 1
        if end < len(pattern) and pattern[end] == "+":
            raise ProofError("capture pattern uses a possessive quantifier")
        if end < len(pattern) and pattern[end] == "?":
            end += 1
        return end, char
    if char == "{":
        match = re.match(r"\{\d*(?:,\d*)?\}", pattern[index:])
        if match:
            end = index + len(match.group(0))
            if end < len(pattern) and pattern[end] == "+":
                raise ProofError("capture pattern uses a possessive quantifier")
            if end < len(pattern) and pattern[end] == "?":
                end += 1
            return end, "{}"
    return index, None


def _validate_safe_pattern(pattern: str, where: str) -> None:
    """Reject capture constructs that can make matching super-linear.

    The replay engine bounds every match with a hard deadline, but rejecting
    ambiguous repetition up front keeps honest proofs fast and gives the author
    a precise validation error instead of a replay timeout.
    """
    stack = [{"quantified": False, "alternation": False}]
    index = 0
    length = len(pattern)

    def note_quantifier() -> None:
        stack[-1]["quantified"] = True

    while index < length:
        char = pattern[index]
        if char == "\\":
            index = _skip_escape(pattern, index)
            index, kind = _read_quantifier(pattern, index)
            if kind is not None:
                note_quantifier()
            continue
        if char == "[":
            index = _skip_class(pattern, index)
            index, kind = _read_quantifier(pattern, index)
            if kind is not None:
                note_quantifier()
            continue
        if char == "(":
            if pattern.startswith(_UNSAFE_GROUP_PREFIXES, index):
                raise ProofError(f"{where}: lookaround, conditional or comment groups are not supported")
            index += 1
            if index < length and pattern[index] == "?":
                if pattern.startswith("?P<", index):
                    end = pattern.find(">", index + 3)
                    if end == -1:
                        raise ProofError("capture pattern has an unterminated named group")
                    index = end + 1
                elif index + 1 < length and pattern[index + 1] == "<":
                    raise ProofError("capture pattern uses unsupported group syntax")
                else:
                    cursor = index + 1
                    while cursor < length and pattern[cursor].isalpha():
                        cursor += 1
                    if cursor < length and pattern[cursor] == ":":
                        index = cursor + 1
                    elif cursor < length and pattern[cursor] == ")":
                        # A global inline-flag group such as (?i) is not an atom.
                        index = cursor + 1
                        continue
                    else:
                        raise ProofError("capture pattern uses unsupported group syntax")
            stack.append({"quantified": False, "alternation": False})
            continue
        if char == ")":
            if len(stack) == 1:
                raise ProofError("capture pattern has an unbalanced group")
            group = stack.pop()
            risky = group["quantified"] or group["alternation"]
            index += 1
            index, kind = _read_quantifier(pattern, index)
            if kind is not None:
                if risky:
                    raise ProofError(
                        "capture pattern applies repetition to a group with nested repetition or alternation"
                    )
                note_quantifier()
            if group["quantified"]:
                note_quantifier()
            if group["alternation"]:
                stack[-1]["alternation"] = True
            continue
        if char == "|":
            stack[-1]["alternation"] = True
            index += 1
            continue
        if char in "*+?":
            raise ProofError("capture pattern has a misplaced repetition operator")
        if char == "{":
            index, kind = _read_quantifier(pattern, index)
            if kind is not None:
                raise ProofError("capture pattern has a misplaced repetition operator")
            index += 1
            continue
        index += 1
        index, kind = _read_quantifier(pattern, index)
        if kind is not None:
            note_quantifier()
    if len(stack) != 1:
        raise ProofError("capture pattern has an unterminated group")


def _validate_captures(value, where: str, *, allow_bytes: bool, allow_header: bool) -> list[dict]:
    if not isinstance(value, list):
        raise ProofError(f"{where}: expected a list")
    if len(value) > MAX_CAPTURES:
        raise ProofError(f"{where}: too many captures")
    names = set()
    captures = []
    for index, capture in enumerate(value):
        spot = f"{where}[{index}]"
        if not isinstance(capture, dict):
            raise ProofError(f"{spot}: expected an object")
        _exact_keys(capture, {"name", "source", "pattern"}, set(), spot)
        name = _string(capture["name"], f"{spot}.name", max_len=MAX_CAPTURE_NAME)
        if not _NAME_RE.match(name):
            raise ProofError(f"{spot}.name: invalid characters")
        if name in names:
            raise ProofError(f"{spot}.name: duplicate capture name")
        names.add(name)
        source = _string(capture["source"], f"{spot}.source", max_len=96)
        if not _SOURCE_RE.match(source):
            raise ProofError(f"{spot}.source: unsupported source")
        if source == "bytes" and not allow_bytes:
            raise ProofError(f"{spot}.source: 'bytes' is only available for raw_socket")
        if source.startswith("header:") and not allow_header:
            raise ProofError(f"{spot}.source: 'header' captures are not available for raw_socket steps")
        pattern = _string(capture["pattern"], f"{spot}.pattern", max_len=400)
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ProofError(f"{spot}.pattern: invalid regular expression: {exc}") from exc
        _validate_safe_pattern(pattern, f"{spot}.pattern")
        if compiled.groups != 1:
            raise ProofError(f"{spot}.pattern: must contain exactly one capture group")
        captures.append({"name": name, "source": source, "pattern": pattern})
    return captures


def _validate_headers(value, where: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ProofError(f"{where}: expected an object")
    if len(value) > MAX_HEADERS:
        raise ProofError(f"{where}: too many headers")
    headers = {}
    for name, item in value.items():
        if not isinstance(name, str) or not _HEADER_RE.match(name):
            raise ProofError(f"{where}: invalid header name")
        text = _string(item, f"{where}.{name}", max_len=1024, allow_empty=True)
        _no_control(text, f"{where}.{name}")
        if name.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
            raise ProofError(f"{where}: header {name} is managed by the replay engine")
        _validate_templates(text, f"{where}.{name}", allow_cookie=True)
        headers[name] = text
    return headers


def _validate_form(value, where: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ProofError(f"{where}: expected an object")
    if len(value) > MAX_FORM_FIELDS:
        raise ProofError(f"{where}: too many form fields")
    form = {}
    for name, item in value.items():
        if not isinstance(name, str) or not name or len(name) > 128:
            raise ProofError(f"{where}: invalid field name")
        text = _string(item, f"{where}.{name}", max_len=2048, allow_empty=True)
        _validate_templates(text, f"{where}.{name}", allow_cookie=True)
        form[name] = text
    return form


def validate_proof(document) -> dict:
    if not isinstance(document, dict):
        raise ProofError("proof must be a JSON object")
    _exact_keys(document, {"schema_version", "steps", "diagnostic"}, set(), "proof")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise ProofError("schema_version must be the integer 1")
    steps_value = document["steps"]
    if not isinstance(steps_value, list):
        raise ProofError("steps must be a list")
    if not 1 <= len(steps_value) <= MAX_STEPS:
        raise ProofError(f"steps must contain 1..{MAX_STEPS} operations")

    steps = []
    total_bytes = 0
    for index, step in enumerate(steps_value):
        where = f"steps[{index}]"
        if not isinstance(step, dict):
            raise ProofError(f"{where}: expected an object")
        op = step.get("op")
        if op == "http":
            _exact_keys(step, {"op", "method", "path"}, {"headers", "form", "captures"}, where)
            method = _string(step["method"], f"{where}.method", max_len=8)
            if method not in {"GET", "POST"}:
                raise ProofError(f"{where}.method: must be GET or POST")
            path = _string(step["path"], f"{where}.path", max_len=2048)
            if not _PATH_RE.match(path) or ".." in path or "//" in path:
                raise ProofError(f"{where}.path: must be a relative path on the service")
            _validate_templates(path, f"{where}.path", allow_cookie=False)
            headers = _validate_headers(step.get("headers", {}), f"{where}.headers")
            form = _validate_form(step.get("form", {}), f"{where}.form")
            if method == "GET" and form:
                raise ProofError(f"{where}.form: GET requests cannot carry a form body")
            captures = _validate_captures(
                step.get("captures", []), f"{where}.captures", allow_bytes=False, allow_header=True
            )
            size = len(path.encode()) + sum(len(k) + len(v) for k, v in headers.items())
            size += sum(len(k) + len(v) for k, v in form.items())
            total_bytes += size
            steps.append(
                {
                    "op": "http",
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "form": form,
                    "captures": captures,
                }
            )
        elif op == "raw_socket":
            _exact_keys(step, {"op", "sends"}, {"read_timeout_ms", "captures"}, where)
            sends_value = step["sends"]
            if not isinstance(sends_value, list) or not 1 <= len(sends_value) <= MAX_SENDS:
                raise ProofError(f"{where}.sends: must contain 1..{MAX_SENDS} chunks")
            sends = []
            step_bytes = 0
            for send_index, send in enumerate(sends_value):
                spot = f"{where}.sends[{send_index}]"
                if not isinstance(send, dict):
                    raise ProofError(f"{spot}: expected an object")
                _exact_keys(send, {"text"}, {"delay_ms"}, spot)
                text = _string(send["text"], f"{spot}.text", max_len=MAX_STEP_BYTES)
                _validate_templates(text, f"{spot}.text", allow_cookie=True)
                delay = _int(send.get("delay_ms", 0), f"{spot}.delay_ms", minimum=0, maximum=250)
                encoded = text.encode("utf-8")
                if b"\x00" in encoded:
                    raise ProofError(f"{spot}.text: contains a NUL byte")
                step_bytes += len(encoded)
                sends.append({"text": text, "delay_ms": delay})
            if step_bytes > MAX_STEP_BYTES:
                raise ProofError(f"{where}: raw request bytes exceed {MAX_STEP_BYTES}")
            total_bytes += step_bytes
            timeout = _int(step.get("read_timeout_ms", 1000), f"{where}.read_timeout_ms",
                           minimum=100, maximum=2000)
            captures = _validate_captures(
                step.get("captures", []), f"{where}.captures", allow_bytes=True, allow_header=False
            )
            steps.append(
                {
                    "op": "raw_socket",
                    "sends": sends,
                    "read_timeout_ms": timeout,
                    "captures": captures,
                }
            )
        else:
            raise ProofError(f"{where}.op: unsupported operation")
    if total_bytes > MAX_TOTAL_BYTES:
        raise ProofError("proof request bytes exceed the total limit")

    diagnostic = document["diagnostic"]
    if diagnostic is not None:
        if not isinstance(diagnostic, dict):
            raise ProofError("diagnostic must be null or an object")
        _exact_keys(diagnostic, {"apparent_step", "readback_step", "explanation"}, set(), "diagnostic")
        apparent = _int(diagnostic["apparent_step"], "diagnostic.apparent_step", minimum=1, maximum=len(steps))
        readback = _int(diagnostic["readback_step"], "diagnostic.readback_step", minimum=1, maximum=len(steps))
        if readback <= apparent:
            raise ProofError("diagnostic.readback_step must follow diagnostic.apparent_step")
        explanation = _string(diagnostic["explanation"], "diagnostic.explanation", max_len=MAX_EXPLANATION)
        diagnostic = {
            "apparent_step": apparent,
            "readback_step": readback,
            "explanation": explanation,
        }

    return {"schema_version": 1, "steps": steps, "diagnostic": diagnostic}


@dataclass
class CapturePlan:
    name: str
    source: str
    pattern: str = field(repr=False)


def capture_plan(steps: list[dict]) -> list[list[dict]]:
    return [step.get("captures", []) for step in steps]
