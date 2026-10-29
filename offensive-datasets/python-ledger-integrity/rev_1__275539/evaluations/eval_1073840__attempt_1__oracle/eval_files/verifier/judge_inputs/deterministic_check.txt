# Deterministic adapter; configure weighted checks and semantic groups for this task.
# This is the SPLIT-FILE adapter layout: task-specific pytest rows live in
# deterministic/pytest_checks.py, and this file owns only RewardKit registration,
# JUnit parsing, deterministic row aggregation, and read-only criterion scoring.
# A compact single-file variant is also acceptable for small suites —
# see the guard-mechanism note at the bottom of this file.
"""RewardKit deterministic adapter for pytest-prepass results.

Contract:
  * tests/test.sh calls this module with --prepass before RewardKit scoring.
  * --prepass runs pytest once, writes internal JUnit XML, then writes
    /logs/verifier/deterministic_reward.json and /logs/verifier/test_output.log.
  * RewardKit criterion calls read deterministic_reward.json only. They do not
    run pytest, restart services, replay proofs, or mutate task state.
  * This module is safe for upload-time RewardKit discovery: stdlib + rewardkit
    imports only at module import time.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import rewardkit as rk
    from rewardkit import criterion
except Exception:  # upload-discovery / local-static fallback; the task image installs harbor-rewardkit
    # harbor-rewardkit transitively imports litellm -> httpx at package init, so a strict
    # discovery probe that blocks non-stdlib deps trips on `import rewardkit`. Guarding it keeps this
    # module import-safe (stdlib-only fallback); when RewardKit is importable (task image + scoring
    # pass) the real objects are used and behavior is unchanged. Matches the accepted split-file pattern.
    class _RKStub:
        def __getattr__(self, _name):
            def _register(*_args, **_kwargs):
                return None
            return _register

    rk = _RKStub()  # type: ignore

    def criterion(*_args, **_kwargs):  # type: ignore
        def _decorator(fn):
            return fn
        return _decorator


# Task-specific weighted rows. Base test names only, without any case suffix.
TEST_WEIGHTS = {
    "test_sec_submitted_proof_effect": 80.0,
    "test_func_proof_contract": 15.0,
    "test_func_optional_near_miss_or_success": 5.0,
}

# Map base check names to stable semantic-effect labels. Each group has one
# budget (the maximum member weight) and earns its minimum member score.
# Split unrelated assertions into separate rows; never group by failure prose.
# Empty mapping preserves ordinary weighted averaging. Legacy (label, None)
# entries are accepted; message-guard tuples are rejected as ambiguous.
ROOT_CAUSE_GROUPS: dict = {}

# Explicit semantic group labels carrying the qualification-critical objective.
# Name prefixes do not define criticality; this set does.
CORE_GROUPS = {"test_sec_submitted_proof_effect"}


def _group_label(name: str) -> str:
    value = ROOT_CAUSE_GROUPS.get(name, name)
    if isinstance(value, (tuple, list)) and len(value) == 2 and value[1] is None:
        value = value[0]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name}: use a stable group label; split message-guarded assertions into independent rows")
    return value


def _validate_configuration() -> None:
    if not TEST_WEIGHTS:
        raise ValueError("TEST_WEIGHTS must contain scoring checks")
    for name, weight in TEST_WEIGHTS.items():
        if not name.startswith(("test_func_", "test_sec_")):
            raise ValueError(f"invalid weighted check name: {name}")
        if type(weight) not in (int, float) or not math.isfinite(weight) or weight <= 0:
            raise ValueError(f"{name}: weight must be a finite positive number")
        _group_label(name)
    if set(ROOT_CAUSE_GROUPS) - set(TEST_WEIGHTS):
        raise ValueError("ROOT_CAUSE_GROUPS names an unweighted check")
    budgets: dict[str, float] = {}
    for name, weight in TEST_WEIGHTS.items():
        label = _group_label(name)
        budgets[label] = max(budgets.get(label, 0.0), float(weight))
    if not CORE_GROUPS or not CORE_GROUPS <= budgets.keys():
        raise ValueError("CORE_GROUPS must name existing independent semantic groups")
    total = sum(budgets.values())
    core = sum(budgets[label] for label in CORE_GROUPS)
    if core / total < 0.60 - 1e-12:
        raise ValueError("qualification-critical core groups need at least 60% effective weight")
    if any(budgets[label] / total < 0.10 - 1e-12 for label in CORE_GROUPS):
        raise ValueError("each independent core group needs at least 10% effective weight")


TESTS_DIR = Path(os.environ.get("TESTS_DIR", str(Path(__file__).resolve().parents[1])))
DEFAULT_TARGET = TESTS_DIR / "deterministic" / "pytest_checks.py"
PYTEST_TARGETS = [
    Path(p) for p in os.environ.get("DETERMINISTIC_PYTEST_TARGETS", str(DEFAULT_TARGET)).split(os.pathsep)
    if p
]


def _verifier_dir() -> Path:
    out = Path(os.environ.get("VERIFIER_DIR", os.environ.get("RESULT_DIR", "/logs/verifier")))
    out.mkdir(parents=True, exist_ok=True)
    return out


def _internal_dir() -> Path:
    path = _verifier_dir() / "internal"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _base_test_name(name: str) -> str:
    """Map a pytest/JUnit row to the TEST_WEIGHTS base function name."""
    leaf = name.rsplit("::", 1)[-1]
    leaf = leaf.split(".", 1)[-1] if "." in leaf and not leaf.startswith("test_") else leaf
    return re.sub(r"\[.*\]$", "", leaf)


def _case_status(case: ET.Element) -> tuple[str, str, str]:
    failure = case.find("failure")
    error = case.find("error")
    skipped = case.find("skipped")
    if failure is not None:
        return "failed", failure.get("message", "") or (failure.text or ""), failure.text or ""
    if error is not None:
        return "failed", error.get("message", "") or (error.text or ""), error.text or ""
    if skipped is not None:
        return "skipped", skipped.get("message", "") or (skipped.text or ""), skipped.text or ""
    return "passed", "", ""


def _parse_junit(junit_path: Path) -> list[dict]:
    if not junit_path.exists():
        raise FileNotFoundError(f"pytest JUnit XML was not created: {junit_path}")
    root = ET.parse(junit_path).getroot()
    cases = []
    for case in root.iter("testcase"):
        classname = case.get("classname", "")
        name = case.get("name", "")
        full_name = f"{classname}::{name}" if classname else name
        status, message, details = _case_status(case)
        cases.append(
            {
                "name": full_name,
                "base_name": _base_test_name(name),
                "status": status,
                "message": " ".join((message or "").split())[:800],
                "details": details or "",
                "duration": int(float(case.get("time", "0") or 0) * 1000),
            }
        )
    return cases


def _summarize_cases(cases: list[dict], *, pytest_exit_code: int, reason: str) -> dict:
    _validate_configuration()
    by_base: dict[str, list[dict]] = {name: [] for name in TEST_WEIGHTS}
    unknown = []
    for case in cases:
        base = case["base_name"]
        if base in by_base:
            by_base[base].append(case)
        else:
            unknown.append(case)

    tests = []
    for name, weight in TEST_WEIGHTS.items():
        rows = by_base.get(name, [])
        if not rows:
            tests.append(
                {
                    "name": name,
                    "status": "failed",
                    "score": 0.0,
                    "weight": weight,
                    "message": f"no pytest rows collected for weighted check {name}",
                    "details": "",
                    "cases": [],
                }
            )
            continue
        passed = sum(1 for row in rows if row["status"] == "passed")
        failed = sum(1 for row in rows if row["status"] == "failed")
        skipped = sum(1 for row in rows if row["status"] == "skipped")
        score = passed / len(rows) if rows else 0.0
        status = "passed" if passed == len(rows) else ("failed" if failed else "skipped")
        first_bad = next((row for row in rows if row["status"] != "passed"), None)
        tests.append(
            {
                "name": name,
                "status": status,
                "score": score,
                "weight": weight,
                "message": (first_bad or {}).get("message", ""),
                "details": (first_bad or {}).get("details", ""),
                "cases": rows,
            }
        )

    groups = {}
    for t in tests:
        groups.setdefault(_group_label(t["name"]), []).append(t)
    group_results = {
        name: {"weight": max(float(t["weight"]) for t in rows),
               "score": min(float(t["score"]) for t in rows),
               "members": [t["name"] for t in rows]}
        for name, rows in groups.items()
    }
    total_weight = sum(g["weight"] for g in group_results.values())
    earned_weight = sum(g["weight"] * g["score"] for g in group_results.values())
    deterministic_score = earned_weight / total_weight if total_weight else 0.0
    strict = (pytest_exit_code == 0 and not unknown and bool(tests)
              and all(t["status"] == "passed" and t["score"] == 1.0 for t in tests))
    # Collection/internal errors and unregistered rows invalidate coverage. Do
    # not treat them as an ordinary partial analytical answer.
    case_names = [row["name"] for row in cases]
    duplicate_rows = len(case_names) != len(set(case_names))
    invalid_status = any(row["status"] not in {"passed", "failed", "skipped"} for row in cases)
    exit_mismatch = (pytest_exit_code == 0 and any(row["status"] == "failed" for row in cases)) or (
        pytest_exit_code == 1 and not any(row["status"] == "failed" for row in cases))
    infrastructure_error = (pytest_exit_code not in (0, 1) or bool(unknown)
                            or duplicate_rows or invalid_status or exit_mismatch)
    strict = strict and not infrastructure_error
    if infrastructure_error:
        deterministic_score = earned_weight = 0.0
        reason = (f"invalid pytest coverage: exit={pytest_exit_code}, unknown_rows={len(unknown)}, "
                  f"duplicate_rows={duplicate_rows}, invalid_status={invalid_status}, exit_mismatch={exit_mismatch}")
    grouped_penalty = total_weight - earned_weight
    root_cause_groups = group_results

    return {
        "coverage_valid": not infrastructure_error,
        "strict_pass": strict,
        "strict_score": 1.0 if strict else 0.0,
        "deterministic_score": deterministic_score,
        "earned_weight": round(earned_weight, 4),
        "total_weight": round(total_weight, 4),
        "grouped_penalty": round(grouped_penalty, 4),
        "root_cause_groups": root_cause_groups,
        "passed_checks": sum(1 for t in tests if t["status"] == "passed"),
        "failed_checks": sum(1 for t in tests if t["status"] == "failed"),
        "skipped_checks": sum(1 for t in tests if t["status"] == "skipped"),
        "total_checks": len(tests),
        "test_weights": TEST_WEIGHTS,
        "tests": tests,
        "by_name": {t["name"]: t for t in tests},
        "functional": {
            "passed": sum(1 for t in tests if t["name"].startswith("test_func_") and t["status"] == "passed"),
            "failed": sum(1 for t in tests if t["name"].startswith("test_func_") and t["status"] == "failed"),
            "skipped": sum(1 for t in tests if t["name"].startswith("test_func_") and t["status"] == "skipped"),
        },
        "security": {
            "passed": sum(1 for t in tests if t["name"].startswith("test_sec_") and t["status"] == "passed"),
            "failed": sum(1 for t in tests if t["name"].startswith("test_sec_") and t["status"] == "failed"),
            "skipped": sum(1 for t in tests if t["name"].startswith("test_sec_") and t["status"] == "skipped"),
        },
        "failed_tests": [
            {"name": t["name"], "message": t["message"], "weight": t["weight"], "score": t["score"]}
            for t in tests
            if t["status"] != "passed" or float(t["score"]) != 1.0
        ],
        "unknown_pytest_rows": unknown,
        "reason": reason,
        "exit_code": pytest_exit_code,
    }


def _write_outputs(summary: dict, *, junit_path: Path | None = None) -> None:
    out = _verifier_dir()
    _write_json(out / "deterministic_reward.json", summary)

    lines = ["Deterministic pytest prepass", ""]
    if junit_path is not None:
        lines.append(f"junit_xml: {junit_path}")
    lines.append(
        "summary: "
        f"{summary['passed_checks']} passed, "
        f"{summary['failed_checks']} failed, "
        f"{summary['skipped_checks']} skipped, "
        f"score={summary['deterministic_score']:.4f}"
    )
    lines.append("")
    for test in summary.get("tests", []):
        lines.append(
            f"{test['status'].upper():7} {test['name']} "
            f"[score={test['score']}, weight={test['weight']}]"
        )
        if test.get("message"):
            lines.append(f"  {test['message']}")
        for case in test.get("cases", []):
            lines.append(f"    {case['status'].upper():7} {case['name']}")
            if case.get("message"):
                lines.append(f"      {case['message']}")
    if summary.get("unknown_pytest_rows"):
        lines.append("")
        lines.append("Unknown pytest rows not present in TEST_WEIGHTS:")
        for row in summary["unknown_pytest_rows"]:
            lines.append(f"  {row['status'].upper():7} {row['name']}")
    text = "\n".join(lines) + "\n"
    (out / "test_output.log").write_text(text, encoding="utf-8")
    print(text)


def _preflight_failure(message: str, details: str = "") -> dict:
    tests = [
        {
            "name": name,
            "status": "failed",
            "score": 0.0,
            "weight": weight,
            "message": message,
            "details": details,
            "cases": [],
        }
        for name, weight in TEST_WEIGHTS.items()
    ]
    total_weight = sum(float(v) for v in TEST_WEIGHTS.values())
    return {
        "strict_pass": False,
        "strict_score": 0.0,
        "deterministic_score": 0.0,
        "earned_weight": 0.0,
        "total_weight": round(total_weight, 4),
        "passed_checks": 0,
        "failed_checks": len(tests),
        "skipped_checks": 0,
        "total_checks": len(tests),
        "test_weights": TEST_WEIGHTS,
        "tests": tests,
        "by_name": {t["name"]: t for t in tests},
        "functional": {
            "passed": 0,
            "failed": sum(1 for t in tests if t["name"].startswith("test_func_")),
            "skipped": 0,
        },
        "security": {
            "passed": 0,
            "failed": sum(1 for t in tests if t["name"].startswith("test_sec_")),
            "skipped": 0,
        },
        "failed_tests": [
            {"name": t["name"], "message": t["message"], "weight": t["weight"], "score": 0.0}
            for t in tests
        ],
        "unknown_pytest_rows": [],
        "reason": message,
        "exit_code": 1,
    }


def run_pytest_prepass() -> dict:
    out = _verifier_dir()
    junit_path = _internal_dir() / "deterministic_junit.xml"
    junit_path.unlink(missing_ok=True)
    targets = [str(p) for p in PYTEST_TARGETS]
    missing_targets = [p for p in PYTEST_TARGETS if not p.is_file()]

    if not targets or missing_targets:
        summary = _preflight_failure(
            f"missing deterministic pytest targets: {missing_targets or targets}",
            "Expected tests/deterministic/pytest_checks.py or DETERMINISTIC_PYTEST_TARGETS.",
        )
        _write_outputs(summary, junit_path=junit_path)
        return summary

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *targets,
        "--junit-xml",
        str(junit_path),
        "-q",
        "-p",
        "no:cacheprovider",
    ]
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(TESTS_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=int(os.environ.get("DETERMINISTIC_TIMEOUT_SEC", "900")),
    )
    duration_ms = int((time.perf_counter() - started) * 1000)
    raw_log = proc.stdout or ""
    (out / "pytest_output.log").write_text(raw_log, encoding="utf-8")

    try:
        cases = _parse_junit(junit_path)
        reason = "all checks passed" if proc.returncode == 0 else "pytest check failures"
        summary = _summarize_cases(cases, pytest_exit_code=proc.returncode, reason=reason)
        summary["pytest"] = {
            "command": cmd,
            "duration_ms": duration_ms,
            "junit_xml": str(junit_path),
            "raw_output": str(out / "pytest_output.log"),
        }
    except Exception as exc:  # noqa: BLE001
        summary = _preflight_failure(
            f"failed to parse deterministic pytest JUnit XML: {exc}",
            traceback.format_exc(),
        )
        summary["pytest"] = {
            "command": cmd,
            "duration_ms": duration_ms,
            "junit_xml": str(junit_path),
            "raw_output": str(out / "pytest_output.log"),
        }

    _write_outputs(summary, junit_path=junit_path)
    return summary


def _load_precomputed() -> dict:
    path = _verifier_dir() / "deterministic_reward.json"
    if not path.exists():
        return _preflight_failure(
            "deterministic prepass did not produce deterministic_reward.json"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("precomputed result must be an object")
        return value
    except Exception as exc:  # noqa: BLE001
        return _preflight_failure(
            f"deterministic_reward.json is invalid JSON: {exc}",
            traceback.format_exc(),
        )


@criterion(description="Precomputed deterministic pytest check {check_name}.")
def deterministic_check(workspace: Path, check_name: str) -> float:
    summary = _load_precomputed()
    row = (summary.get("by_name") or {}).get(check_name)
    if not isinstance(row, dict):
        return 0.0
    try:
        score = row.get("score", 0.0)
        if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
            return 0.0
        if summary.get("coverage_valid") is not True or summary.get("exit_code") not in (0, 1) or summary.get("unknown_pytest_rows"):
            return 0.0
        return float(score)
    except Exception:
        return 0.0


for _check_name, _weight in TEST_WEIGHTS.items():
    rk.deterministic_check(_check_name, weight=_weight, name=_check_name)


if __name__ == "__main__":
    if "--prepass" in sys.argv:
        try:
            run_pytest_prepass()
        except Exception as exc:
            _write_outputs(_preflight_failure(f"deterministic prepass failed: {exc}", traceback.format_exc()))


# ---------------------------------------------------------------------------
# Compact single-file variant — guard mechanism note
# ---------------------------------------------------------------------------
# The split-file layout above (pytest rows in pytest_checks.py, adapter in this
# file) is the preferred generated-task layout. A COMPACT SINGLE-FILE variant is
# also acceptable for analysis/triage tasks and small deterministic suites, where
# it is easier to keep the pytest rows and the RewardKit adapter together in one
# tests/deterministic/check.py. The full compact skeleton is not reproduced here;
# use check_compact.py as the starting point.
#
# The key compact-file guard mechanism is the REWARDKIT_RUNNING_PYTEST child
# process environment variable:
#
#   * test.sh still calls `python3 tests/deterministic/check.py --prepass`
#     before RewardKit, and that prepass sets REWARDKIT_RUNNING_PYTEST=1 only in
#     the pytest subprocess's environment.
#   * When pytest imports check.py as a test module during the prepass,
#     REWARDKIT_RUNNING_PYTEST is set, so the file's RewardKit import + criterion
#     registration branch is SKIPPED — pytest sees only pytest tests.
#   * During upload discovery and RewardKit scoring the variable is NOT set, so
#     the RewardKit imports/criteria register normally (and read precomputed rows
#     from deterministic_reward.json).
#
# The guarded import block looks like:
#
#     if os.environ.get("REWARDKIT_RUNNING_PYTEST") != "1":
#         import rewardkit as rk
#         from rewardkit import criterion
#     else:
#         rk = None
#         criterion = None
#
# Compact tasks that need pytest decorators/parameterization must still keep
# pytest out of the upload-discovery branch — guard the parameterized tests:
#
#     if os.environ.get("REWARDKIT_RUNNING_PYTEST") == "1":
#         import pytest
#         @pytest.mark.parametrize("case", [...], ids=lambda c: c["name"])
#         def test_sec_rejects_mutated_replay(case): ...
#
# Keep TEST_WEIGHTS OUTSIDE the pytest-only block so upload discovery can
# register RewardKit criteria without importing pytest. Prefer the split-file
# layout for heavily parameterized, fixture-heavy, or dependency-heavy suites.
