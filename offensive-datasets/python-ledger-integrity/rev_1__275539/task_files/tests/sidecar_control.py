"""Verifier-only client for the target appliance's narrow lifecycle interface.

This client drives reset / preflight / trusted readback against the controller.
It never writes the protected state and never reaches the appliance database
directly; only the controller's authenticated routes are used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = os.environ.get("TARGET_CONTROL_URL", "http://127.0.0.1:19999").rstrip("/")
MAX_READ = 1024 * 1024


class SidecarError(RuntimeError):
    """A control operation failed; dependent replay checks must not earn credit."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SidecarError(message)


def _key() -> bytes:
    key_path = Path(__file__).resolve().with_name("control-auth.key")
    try:
        key = key_path.read_bytes()
    except OSError as exc:
        raise SidecarError("verifier control authentication key is unavailable") from exc
    _require(len(key) == 32, "control authentication key must contain 32 random bytes")
    return key


def _call(path: str, method: str = "GET") -> tuple[int, dict[str, Any]]:
    key = _key()
    nonce = secrets.token_hex(32)
    request_mac = hmac.new(
        key, f"{method}\n{path}\n{nonce}\n".encode(), hashlib.sha256
    ).hexdigest()
    request = urllib.request.Request(
        BASE_URL + path,
        method=method,
        headers={"X-Control-Nonce": nonce, "X-Control-Request-MAC": request_mac},
    )
    timeout = 240 if method == "POST" else 30
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
        _require(
            hmac.compare_digest(response.headers.get("X-Control-MAC", ""), expected),
            f"sidecar {path} response authentication failed",
        )
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise SidecarError(f"sidecar {path} response was not valid JSON") from exc
        _require(isinstance(data, dict), f"sidecar {path} response must be an object")
        return response.code, data


def preflight(*, require_absent_effect: bool = False) -> dict[str, Any]:
    status, data = _call("/control/preflight")
    _require(status == 200, f"sidecar preflight failed: HTTP {status} {data}")
    _require(data.get("target_ready") is True, "target appliance is not ready")
    integrity = data.get("integrity")
    _require(
        isinstance(integrity, dict) and integrity.get("valid") is True,
        "target appliance digest mismatch",
    )
    if require_absent_effect:
        _require(data.get("effect_present") is False, "a protected transition existed before replay")
    return data


def reset() -> dict[str, Any]:
    status, data = _call("/control/reset", "POST")
    _require(
        status == 200 and data.get("ok") is True,
        f"sidecar reset failed: HTTP {status} {data}",
    )
    return preflight(require_absent_effect=True)


def restart() -> dict[str, Any]:
    status, data = _call("/control/restart", "POST")
    _require(
        status == 200 and data.get("ok") is True,
        f"sidecar restart failed: HTTP {status} {data}",
    )
    return preflight()


def effect() -> dict[str, Any] | None:
    status, data = _call("/control/effect")
    if status == 404:
        return None
    _require(status == 200 and "effect" in data, f"sidecar effect read failed: HTTP {status} {data}")
    value = data["effect"]
    _require(isinstance(value, dict), "sidecar effect payload must be an object")
    return value


def public_reset() -> bool:
    """Unauthenticated reset, used only by the verifier's public contract checks."""
    request = urllib.request.Request(BASE_URL + "/control/public-reset", method="POST")
    try:
        with OPENER.open(request, timeout=240) as response:
            raw = response.read(4096)
            return response.status == 200 and json.loads(raw.decode("utf-8")).get("ok") is True
    except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError):
        return False
