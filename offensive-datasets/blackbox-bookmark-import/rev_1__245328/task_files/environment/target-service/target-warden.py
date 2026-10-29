#!/usr/bin/env python3
"""Narrow lifecycle controller for the isolated Karakeep target sidecar.

Adapted from the maintained HARBOR target-service warden. It owns ONLY service
lifecycle, integrity, and trusted readback of the protected effect. It never
accepts a command, artifact, path, or payload from main.

Differences from the file-effect template (validated adaptations):
  * The protected effect is "the internal artifact service recorded an internal fetch
    fetch bound to the current reset nonce". The effect is created by the
    authentic target (Karakeep's server-side fetch), NOT by the warden. The
    warden only READS it, over the internal network, from the marker's
    secret-gated control endpoint. The warden cannot create a hit (it is not
    the thing being fetched; a hit requires a real fetch to the marker's data
    surface, reachable only from inside the target network).
  * Binds 0.0.0.0 for Pattern-2 service-name networking (verifier reaches it at
    target-service:19999). Response provenance is still HMAC-bound so a main-
    local impersonator cannot forge a reply.

Allowed (responses authenticated when a valid nonce is supplied):
  GET  /control/health         GET  /control/preflight    GET  /control/digest
  GET  /control/effect         POST /control/reset        POST /control/restart
Forbidden: creating/writing the effect, marking pass, arbitrary exec, file
browsing, unrestricted paths, service replacement, proxying, bodies on control.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import threading
import time
import urllib.error
import urllib.request

PORT = int(os.environ.get("TARGET_CONTROL_PORT", "19999"))
HEALTH_URL = os.environ["TARGET_HEALTH_URL"]
START = Path(os.environ["TARGET_START_SCRIPT"])
RESET = Path(os.environ["TARGET_RESET_SCRIPT"])
RESTART = Path(os.environ.get("TARGET_RESTART_SCRIPT", str(START)))
MANIFEST = Path(os.environ["TARGET_MANIFEST"])
AUTH_KEY_PATH = Path(os.environ.get("TARGET_CONTROL_KEY_PATH", "/run/secrets/control-auth.key"))
MARKER_CTL_URL = os.environ["MARKER_CTL_URL"].rstrip("/")
MARKER_SECRET = os.environ["MARKER_CONTROL_SECRET"]

MAX_READ = 512 * 1024
LOCK = threading.Lock()
GENERATION = 0
CONTROL_KEY = b""


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
        cwd="/", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=10, check=False,
    )
    return {
        "present": True,
        "valid": checked.returncode == 0,
        "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
    }


def marker_effect() -> dict:
    """Read the protected effect from the internal marker (trusted readback)."""
    req = urllib.request.Request(
        MARKER_CTL_URL + "/_ctl/effect", method="GET",
        headers={"X-Marker-Secret": MARKER_SECRET},
    )
    with OPENER.open(req, timeout=5) as response:
        raw = response.read(MAX_READ + 1)
        data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("marker effect response malformed")
    return data


def marker_reset() -> None:
    req = urllib.request.Request(
        MARKER_CTL_URL + "/_ctl/reset", method="POST",
        headers={"X-Marker-Secret": MARKER_SECRET},
    )
    with OPENER.open(req, timeout=5) as response:
        if not (200 <= response.status < 300):
            raise RuntimeError("marker reset failed")


def run_lifecycle(script: Path, operation: str) -> None:
    if not script.is_file() or not os.access(script, os.X_OK):
        raise RuntimeError(f"{operation} lifecycle script is unavailable")
    completed = subprocess.run(
        [str(script)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=180, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{operation} lifecycle failed: {completed.returncode}: {completed.stdout[-400:]}")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if service_ready():
            return
        time.sleep(0.3)
    raise RuntimeError(f"{operation} did not restore service readiness")


def start_initial() -> None:
    with LOCK:
        if not manifest_status().get("valid"):
            raise RuntimeError("sealed runtime integrity failed before startup")
        run_lifecycle(START, "start")


class Handler(BaseHTTPRequestHandler):
    server_version = "KarakeepTargetController/1.0"

    def log_message(self, *_a):
        return

    def reply(self, status: int, body: object) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        nonce = self.headers.get("X-Control-Nonce", "")
        if len(nonce) == 64 and all(c in "0123456789abcdef" for c in nonce):
            message = f"{nonce}\n{self.command}\n{self.path}\n{status}\n".encode() + encoded
            self.send_header("X-Control-MAC", hmac.new(CONTROL_KEY, message, hashlib.sha256).hexdigest())
        self.end_headers()
        self.wfile.write(encoded)

    def _effect_present(self) -> bool:
        try:
            return bool(marker_effect().get("hit_present"))
        except Exception:
            return False

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/control/health":
            self.reply(200, {"ok": True, "target_ready": service_ready(), "integrity": manifest_status()})
            return
        if self.path == "/control/preflight":
            self.reply(200, {
                "target_ready": service_ready(),
                "integrity": manifest_status(),
                "effect_present": self._effect_present(),
                "generation": GENERATION,
            })
            return
        if self.path == "/control/digest":
            self.reply(200, manifest_status())
            return
        if self.path == "/control/effect":
            try:
                eff = marker_effect()
            except Exception:
                self.reply(500, {"error": "effect readback failed"})
                return
            if eff.get("hit_present"):
                self.reply(200, {"effect": eff, "generation": GENERATION})
            else:
                self.reply(404, {"error": "trusted effect is absent"})
            return
        self.reply(404, {"error": "unknown control route"})

    def do_POST(self) -> None:  # noqa: N802
        global GENERATION
        if self.path not in {"/control/reset", "/control/restart"}:
            self.reply(404, {"error": "unknown control route"})
            return
        if self.headers.get("Transfer-Encoding") is not None or self.headers.get("Content-Length", "0") != "0":
            self.reply(400, {"error": "control operations do not accept a body"})
            return
        with LOCK:
            try:
                is_reset = self.path.endswith("reset")
                run_lifecycle(RESET if is_reset else RESTART, "reset" if is_reset else "restart")
                integrity = manifest_status()
                if not integrity.get("valid"):
                    raise RuntimeError("sealed runtime integrity failed")
                if is_reset and self._effect_present():
                    raise RuntimeError("reset left a protected effect")
                GENERATION += 1
                self.reply(200, {"ok": True, "generation": GENERATION, "integrity": integrity})
            except Exception as exc:
                self.reply(503, {"ok": False, "error": f"target lifecycle operation failed: {exc}"})


def main() -> int:
    global CONTROL_KEY
    CONTROL_KEY = AUTH_KEY_PATH.read_bytes()
    if len(CONTROL_KEY) != 32:
        raise RuntimeError("control authentication key must contain 32 random bytes")
    start_initial()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
