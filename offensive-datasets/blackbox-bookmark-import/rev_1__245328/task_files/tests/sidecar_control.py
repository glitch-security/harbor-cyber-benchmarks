"""Verifier-only client for the target sidecar's narrow lifecycle interface.

Maintained template — stage privately under tests/. The deterministic prepass imports this to
drive reset/preflight/effect readback against the warden. It only ever calls the
allowed control routes; it never writes the effect or reaches target-private
state directly (that would be a false-pass path — checklist H-17/J-01/J-09).
"""

from __future__ import annotations

import json
import hashlib
import hmac
import secrets
from pathlib import Path
import os
import urllib.error
import urllib.request
from typing import Any


# Configure this endpoint in the trusted verifier launch, never from proof fields.
BASE_URL = os.environ.get("TARGET_CONTROL_URL", "http://127.0.0.1:19999").rstrip("/")
MAX_READ = 512 * 1024 + 4096


class SidecarError(RuntimeError):
    """A control operation failed; dependent replay checks must not earn credit."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SidecarError(message)


def _call(path: str, method: str = "GET") -> tuple[int, dict[str, Any]]:
    # This key is staged with root-only tests after the agent phase; never bake it into main.
    key_path = Path(__file__).resolve().with_name("control-auth.key")
    try:
        key = key_path.read_bytes()
    except OSError as exc:
        raise SidecarError("verifier control authentication key is unavailable") from exc
    _require(len(key) == 32, "control authentication key must contain 32 random bytes")
    nonce = secrets.token_hex(32)
    request = urllib.request.Request(BASE_URL + path, method=method,
                                     headers={"X-Control-Nonce": nonce})
    # Warden lifecycle budget: 90 s command + 20 s readiness. Allow transport slack.
    timeout = 120 if method == "POST" else 20
    try:
        response = OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except (OSError, urllib.error.URLError) as exc:
        raise SidecarError(f"sidecar {path} transport failed: {exc}") from exc
    with response:
        raw = response.read(MAX_READ + 1)
        _require(len(raw) <= MAX_READ, f"sidecar {path} response exceeded limit")
        message = f"{nonce}\n{method}\n{path}\n{response.code}\n".encode() + raw
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        _require(hmac.compare_digest(response.headers.get("X-Control-MAC", ""), expected),
                 f"sidecar {path} response authentication failed")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise SidecarError(f"sidecar {path} response was not valid JSON") from exc
        _require(isinstance(data, dict), f"sidecar {path} response must be an object")
        return response.code, data


def preflight(*, require_absent_effect: bool = False) -> dict[str, Any]:
    status, data = _call("/control/preflight")
    _require(status == 200, f"sidecar preflight failed: HTTP {status} {data}")
    _require(data.get("target_ready") is True, "target sidecar is not ready")
    integrity = data.get("integrity")
    _require(isinstance(integrity, dict) and integrity.get("valid") is True,
             "target sidecar digest mismatch")
    if require_absent_effect:
        _require(data.get("effect_present") is False, "protected effect existed before replay")
    return data


def reset() -> dict[str, Any]:
    status, data = _call("/control/reset", "POST")
    _require(status == 200 and data.get("ok") is True,
             f"sidecar reset failed: HTTP {status} {data}")
    return preflight(require_absent_effect=True)


def restart() -> dict[str, Any]:
    status, data = _call("/control/restart", "POST")
    _require(status == 200 and data.get("ok") is True,
             f"sidecar restart failed: HTTP {status} {data}")
    return preflight()


def effect() -> Any | None:
    status, data = _call("/control/effect")
    if status == 404:
        return None
    _require(status == 200 and "effect" in data,
             f"sidecar effect read failed: HTTP {status} {data}")
    return data["effect"]


def verifier_hash() -> str:
    status, data = _call("/control/verifier-hash")
    value = data.get("sha256")
    _require(status == 200 and isinstance(value, str) and len(value) == 64
             and all(c in "0123456789abcdef" for c in value),
             f"sidecar verifier hash read failed: HTTP {status} {data}")
    return value
