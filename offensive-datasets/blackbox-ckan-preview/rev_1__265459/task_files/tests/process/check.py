# Programmatic process-artifact gate.
"""Programmatic half of the `process` dimension: the plan.md artifact gate.

This runs in the deterministic/programmatic RewardKit pass and yields a
`process` dimension scored 1.0 if `/app/output/plan.md` is present and non-empty,
or 0.0 otherwise. The semantic process rubric lives in `process/judge.toml` and
runs only in the judge pass. `tests/test.sh` merges the two halves with this file
as a hard gate:

  * plan.md missing -> final process = 0.0, regardless of judge score
  * plan.md present -> final process = process judge score when judge runs
  * offline/no judge -> final process = this plan gate score

Because `tests/reward.toml` thresholds the deterministic suite at 1.0, a missing
plan.md also flips `binary_reward` to 0.0. That is intentional.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

try:
    from rewardkit import criterion
except Exception:  # upload-discovery / strict static probe: harbor-rewardkit pulls litellm->httpx at
    # init, so a bare discovery env cannot import it. A no-op decorator keeps this module import-safe
    # (same rationale + fallback as deterministic/check.py); the task image installs harbor-rewardkit so
    # the real criterion is used during scoring. Guard BOTH check.py files — a common shipped defect is
    # an UNGUARDED `from rewardkit import criterion` here that trips the discovery import probe.
    def criterion(*_args, **_kwargs):  # type: ignore
        def _decorator(fn):
            return fn
        return _decorator


def _verifier_dir() -> Path:
    out = Path(os.environ.get("VERIFIER_DIR", os.environ.get("RESULT_DIR", "/logs/verifier")))
    out.mkdir(parents=True, exist_ok=True)
    return out


@criterion(description="plan.md process artifact present and non-empty.")
def plan_md_present(workspace: Path) -> float:
    plan_path = Path("/app/output/plan.md")
    error = ""
    exists = False
    text = ""
    try:
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in plan_path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(plan_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            info = os.fstat(fd)
            exists = stat.S_ISREG(info.st_mode)
            if not exists or info.st_size > 8 * 1024 * 1024:
                raise OSError("plan must be a regular file within the declared 8 MiB artifact limit")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(8 * 1024 * 1024 + 1)
                if len(data) > 8 * 1024 * 1024:
                    raise OSError("plan grew beyond the declared size limit")
                text = data.decode("utf-8")
        finally:
            os.close(fd)
    except (OSError, UnicodeError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    # A symlink is not a submitted plan; do not let root read private targets.

    stripped = text.strip()
    result = {
        "plan_md": {
            "path": str(plan_path),
            "exists": exists,
            "error": error,
            "non_empty": bool(stripped),
            "bytes": len(text.encode()),
            "lines": len(text.splitlines()),
            "score": 1.0 if stripped else 0.0,
        }
    }
    out = _verifier_dir()
    (out / "process_artifacts.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result["plan_md"]["score"]


# Do not call rk.plan_md_present(...). RewardKit auto-registers a criterion that
# takes only `workspace` when decorated. Calling it again would register a
# duplicate criterion and make plan_md_present appear twice in the process dimension.
