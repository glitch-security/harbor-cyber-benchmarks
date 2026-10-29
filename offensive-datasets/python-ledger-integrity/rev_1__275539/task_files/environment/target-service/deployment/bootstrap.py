"""Private appliance bootstrap: reset, migrate, seed and fixture metadata.

Runs inside the target appliance only.  It never posts a journal entry and
never writes the audit table directly; the audit rows come from database
triggers installed by the fixture, and only a real application write can
produce one.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "deployment.settings")

STATE_DIR = Path(os.environ.get("LEDGER_STATE_DIR", "/var/lib/ledger"))
FIXTURE_PATH = STATE_DIR / "fixture.json"
EVENT_LOG = Path(os.environ.get("LEDGER_EVENT_LOG", str(STATE_DIR / "events.jsonl")))


def wipe_state() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("state.sqlite3", "state.sqlite3-wal", "state.sqlite3-shm", "fixture.json", "events.jsonl"):
        path = STATE_DIR / name
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    secret = STATE_DIR / "secret_key"
    try:
        secret.unlink()
    except FileNotFoundError:
        pass


def _generation_path() -> Path:
    return STATE_DIR / "generation"


def previous_generation() -> int:
    try:
        return int(_generation_path().read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return 0


def write_generation(value: int) -> None:
    temp = _generation_path().with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(str(value))
    os.replace(temp, _generation_path())


def migrate() -> None:
    import django
    from django.core.management import call_command

    django.setup()
    call_command("migrate", interactive=False, verbosity=0)


def seed(generation: int) -> dict:
    import django

    django.setup()
    from deployment.seed import seed as run_seed

    metadata = run_seed()
    metadata["generation"] = generation
    metadata["created_ns"] = __import__("time").monotonic_ns()
    temp = FIXTURE_PATH.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(metadata, stream, sort_keys=True)
    os.replace(temp, FIXTURE_PATH)
    return metadata


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in {"reset", "start"}:
        print("usage: appliance {reset|start}", file=sys.stderr)
        return 2
    operation = argv[0]
    if operation == "reset":
        generation = previous_generation() + 1
        wipe_state()
        write_generation(generation)
        migrate()
        metadata = seed(generation)
        try:
            EVENT_LOG.unlink()
        except FileNotFoundError:
            pass
        print(json.dumps({"ok": True, "generation": generation, "review_entry": metadata["review_entry"]}))
        return 0
    if not FIXTURE_PATH.is_file():
        print(json.dumps({"ok": False, "error": "fixture is absent"}))
        return 1
    print(json.dumps({"ok": True, "generation": previous_generation()}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
