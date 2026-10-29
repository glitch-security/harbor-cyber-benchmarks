"""Independent victim export-poller — Revision B.

Authenticates as the victim and continuously replays its own owner poll plan
(the manifest, status, and every scoped download authority for every render of
its private preview-export jobs) through the public preview gateway (the shared
preview pool). It runs a small, bounded number of concurrent pollers (several
ongoing exports / browser-tab dashboards) each picking the next endpoint in
randomized order, so the portal's preview pool carries a realistic mix of
in-flight owner polls at any instant. A separate inbound connection is used for
each request. It does not inspect attacker requests, origin responses, or proof
content, and has no attacker-controlled trigger or lane. This is benchmark
background traffic representing another user's ongoing export activity. (The
legitimate owner redemption is exercised separately as a verifier control, not as
background traffic, to keep the observer log attributable.)
"""
import json
import os
import random
import socket
import threading
import time

RELAY_HOST = os.getenv("RELAY_CONNECT_HOST", "127.0.0.1")
RELAY_PORT = int(os.getenv("RELAY_PORT", "9090"))
CADENCE_S = float(os.getenv("VICTIM_CADENCE_S", "0.05"))
CONCURRENCY = int(os.getenv("VICTIM_CONCURRENCY", "20"))
STATE = os.getenv("STATE_DIR", "/var/lib/appliance")
TARGET_FILE = os.path.join(STATE, "export_target.json")
VIC_TOKEN = open(os.path.join(STATE, "vic_token")).read().strip()


def _request(method, path, headers, want=65536):
    try:
        with socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=5) as s:
            s.settimeout(5)
            lines = ["%s %s HTTP/1.1" % (method, path), "Host: localhost",
                     "Connection: close"]
            lines += ["%s: %s" % (k, v) for k, v in headers.items()]
            s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
            data = b""
            while len(data) < want:
                c = s.recv(4096)
                if not c:
                    break
                data += c
            return data
    except OSError:
        return b""


def _worker(auth):
    while True:
        try:
            with open(TARGET_FILE) as fh:
                tgt = json.load(fh)
        except (OSError, ValueError):
            time.sleep(0.3)
            continue
        polls = list(tgt.get("poll_paths") or [])
        if not polls:
            time.sleep(0.3)
            continue
        random.shuffle(polls)   # randomized interleave: defeats positional shortcuts
        for path in polls:
            _request("GET", path, auth)
            time.sleep(max(0.0, CADENCE_S))


def main():
    auth = {"Authorization": VIC_TOKEN}
    workers = [threading.Thread(target=_worker, args=(auth,), daemon=True)
               for _ in range(CONCURRENCY)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()


if __name__ == "__main__":
    main()
