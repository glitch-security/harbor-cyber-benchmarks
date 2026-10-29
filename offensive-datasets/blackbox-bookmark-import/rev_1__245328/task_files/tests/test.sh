#!/usr/bin/env bash
# Maintained RewardKit v11.6.5 orchestration; task hooks are documented in README.md.
set -euo pipefail

VERIFIER_DIR="${RESULT_DIR:-/logs/verifier}"
TESTBED_DIR="${TESTBED_DIR:-/testbed}"
TESTS_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TASK_DIR="$(CDPATH= cd -- "$TESTS_DIR/.." && pwd)"
DETERMINISTIC_SUITE="$VERIFIER_DIR/deterministic_suite"
JUDGE_SUITE="$VERIFIER_DIR/judge_suite"
DETERMINISTIC_OUT="$VERIFIER_DIR/deterministic_reward"
JUDGE_OUT="$VERIFIER_DIR/judge_reward"


export RESULT_DIR="$VERIFIER_DIR"
export VERIFIER_DIR
export TESTS_DIR
export TESTBED_DIR
export OUTPUT_DIR="${OUTPUT_DIR:-/app/output}"
export PYTHONPATH="$TESTS_DIR"
unset PYTEST_ADDOPTS PYTEST_PLUGINS PYTHONSTARTUP PYTHONHOME REWARDKIT_RUNNING_PYTEST
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PYTHONNOUSERSITE=1

TRAJECTORY_SOURCE=""

copy_if_exists() {
  local src="$1"
  local dst="$2"
  # Only regular files at their declared paths are evidence; never dereference
  # agent-supplied symlinks as the privileged verifier.
  if [ -f "$src" ] && [ ! -L "$src" ]; then
    python3 -I - "$src" "$dst" <<'COPY_PY' || return 1
import os, stat, sys
from pathlib import Path
src, dst = map(Path, sys.argv[1:])
if not src.is_absolute() or ".." in src.parts:
    raise SystemExit("artifact path must be absolute without traversal")
# Traverse parents through directory descriptors, never pathname resolve()+open().
parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
try:
    for part in src.parts[1:-1]:
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.close(parent)
        parent = child
    fd = os.open(src.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
finally:
    os.close(parent)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > 8 * 1024 * 1024:
        raise SystemExit("artifact is not a bounded regular file")
    with os.fdopen(fd, "rb", closefd=False) as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise SystemExit("artifact grew beyond size limit")
        dst.write_bytes(data)
finally:
    os.close(fd)
COPY_PY
  fi
  return 0
}

find_trajectory() {
  TRAJECTORY_SOURCE=""
  for cand in \
    "${TRAJECTORY_PATH:-}" \
    /logs/agent/trajectory.json \
    /logs/artifacts/trajectory.json \
    /logs/trajectory.json \
    /logs/agent/terminus_2.pane \
    /logs/agent/claude-code.txt; do
    if [ -n "$cand" ] && [ -s "$cand" ] && [ ! -L "$cand" ]; then
      TRAJECTORY_SOURCE="$cand"
      return 0
    fi
  done
  return 1
}

extract_instruction_from_trajectory() {
  local trajectory="$1"
  local out_path="$2"
  python3 - "$trajectory" "$out_path" <<'PY'
import json, sys
from pathlib import Path

try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace"))
except Exception:
    raise SystemExit(0)

messages = []
if isinstance(data, dict):
    for key in ("steps", "events", "messages"):
        seq = data.get(key)
        if isinstance(seq, list):
            for step in seq:
                if not isinstance(step, dict):
                    continue
                msg = step.get("message") or step.get("content") or step.get("text")
                role = step.get("source") or step.get("role") or step.get("kind")
                if isinstance(msg, str) and (role in {"user", "prompt", "system"} or "Task Description:" in msg):
                    messages.append(msg)

for msg in messages:
    marker = "Task Description:"
    if marker not in msg:
        continue
    task = msg.split(marker, 1)[1]
    for end in ("\n\nCurrent terminal state:", "\nCurrent terminal state:"):
        if end in task:
            task = task.split(end, 1)[0]
            break
    task = task.strip()
    if task:
        Path(sys.argv[2]).write_text(task + "\n", encoding="utf-8")
        break
PY
}

copy_common_support_dirs() {
  local dst_root="$1"
  for name in fixtures fixture holdout data support corpus assets; do
    if [ -e "$TESTS_DIR/$name" ]; then
      cp -a "$TESTS_DIR/$name" "$dst_root/$name"
    fi
  done
}

build_deterministic_suite() {
  rm -rf "$DETERMINISTIC_SUITE" "$DETERMINISTIC_OUT"
  mkdir -p "$DETERMINISTIC_SUITE/deterministic" "$DETERMINISTIC_SUITE/process" "$DETERMINISTIC_OUT"

  cp "$TESTS_DIR/reward.toml" "$DETERMINISTIC_SUITE/reward.toml"
  cp "$TESTS_DIR/deterministic/check.py" "$DETERMINISTIC_SUITE/deterministic/check.py"
  cp "$TESTS_DIR/process/check.py" "$DETERMINISTIC_SUITE/process/check.py"

  # Copy task-specific pytest rows and deterministic helpers. Add task-specific
  # support names here only when trusted and needed; never copy them to judge evidence implicitly.
  find "$TESTS_DIR/deterministic" -maxdepth 1 -type f \
    \( -name 'pytest_checks.py' -o -name 'test_*.py' -o -name '*_helper.py' -o -name '*_helpers.py' \) \
    -exec cp {} "$DETERMINISTIC_SUITE/deterministic/" \;
  if [ -d "$TESTS_DIR/deterministic/support" ]; then
    cp -a "$TESTS_DIR/deterministic/support" "$DETERMINISTIC_SUITE/deterministic/support"
  fi
  # Optional trusted sidecar support; never stage its key as judge evidence.
  # Explicit private mode also handles archives that normalize ordinary files to 0644.
  for support_file in sidecar_control.py control-auth.key; do
    if [ -f "$TESTS_DIR/$support_file" ] && [ ! -L "$TESTS_DIR/$support_file" ]; then
      install -m 0600 "$TESTS_DIR/$support_file" "$DETERMINISTIC_SUITE/$support_file"
    fi
  done
  copy_common_support_dirs "$DETERMINISTIC_SUITE"
}

run_deterministic_pytest_prepass() {
  echo "=== Deterministic pytest prepass ===" >>"$VERIFIER_DIR/rewardkit.log"
  if ! TESTS_DIR="$DETERMINISTIC_SUITE" \
       PYTHONPATH="$DETERMINISTIC_SUITE" \
       python3 "$DETERMINISTIC_SUITE/deterministic/check.py" --prepass >>"$VERIFIER_DIR/rewardkit.log" 2>&1; then
    echo "WARN: deterministic pytest prepass returned non-zero; continuing so final reward files are written" >>"$VERIFIER_DIR/rewardkit.log"
  fi
}

build_judge_suite() {
  rm -rf "$JUDGE_SUITE" "$JUDGE_OUT"
  mkdir -p "$JUDGE_SUITE" "$JUDGE_OUT" || return 1
  cp "$TESTS_DIR/judge_prompt.md" "$JUDGE_SUITE/judge_prompt.md" || return 1
  for dim in process output_quality validity task_quality; do
    mkdir -p "$JUDGE_SUITE/$dim" || return 1
    cp "$TESTS_DIR/$dim/judge.toml" "$JUDGE_SUITE/$dim/judge.toml" || return 1
  done
}

stage_task_artifacts() {
  local dst="$VERIFIER_DIR/judge_inputs"
  rm -rf "$dst"
  mkdir -p "$dst"

  copy_if_exists "$VERIFIER_DIR/test_output.log" "$dst/test_output.log" || return 1
  copy_if_exists "$VERIFIER_DIR/deterministic_reward.json" "$dst/deterministic_reward.json" || return 1
  copy_if_exists "$VERIFIER_DIR/process_artifacts.json" "$dst/process_artifacts.json" || return 1
  copy_if_exists "$TESTS_DIR/deterministic/check.py" "$dst/deterministic_check.txt" || return 1

  if [ -f "$TASK_DIR/instruction.md" ]; then
    cp "$TASK_DIR/instruction.md" "$dst/instruction.md"
  elif [ -n "$TRAJECTORY_SOURCE" ]; then
    extract_instruction_from_trajectory "$TRAJECTORY_SOURCE" "$dst/instruction.md" || true
  fi
  if [ -n "$TRAJECTORY_SOURCE" ] && [ -f "$TRAJECTORY_SOURCE" ]; then
    cp "$TRAJECTORY_SOURCE" "$dst/trajectory.json" 2>/dev/null || cp "$TRAJECTORY_SOURCE" "$dst/trajectory.txt" || true
  fi

  # Customize this allow-list for the task. Examples:
  copy_if_exists /app/output/plan.md "$dst/plan.md" || return 1
  copy_if_exists /app/output/findings.json "$dst/findings.json" || return 1
  copy_if_exists /testbed/proof.json "$dst/proof.json" || return 1
}

sync_numeric_outputs() {
  python3 - "$VERIFIER_DIR" "$DETERMINISTIC_OUT/reward.json" "$JUDGE_OUT/reward.json" <<'PY'
import copy
import math
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
det_path = Path(sys.argv[2])
judge_path = Path(sys.argv[3])

def load(path):
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}

det = load(det_path)
judge = load(judge_path)
det_details = load(det_path.parent / "reward-details.json")
judge_details = load(judge_path.parent / "reward-details.json")
pre = load(out / "deterministic_reward.json")
proc = load(out / "process_artifacts.json")

def score(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"invalid score type/range: {type(value).__name__}")
    return float(value)

det_score = score(pre.get("deterministic_score", 0.0))
plan_score = score((proc.get("plan_md") or {}).get("score", 0.0))
# A failed/partial semantic pass contributes no semantic dimensions. The shell
# removes its incomplete files; also validate complete numeric coverage here.
if judge and not all(k in judge for k in ("output_quality", "process", "task_quality", "validity")):
    judge, judge_details = {}, {}
try:
    for key in ("output_quality", "process", "task_quality", "validity"):
        if key in judge:
            judge[key] = score(judge[key])
    if judge and not all(isinstance(judge_details.get(k), dict)
                         and isinstance(judge_details[k].get("criteria"), list)
                         and judge_details[k]["criteria"]
                         for k in ("output_quality", "process", "task_quality", "validity")):
        raise ValueError("incomplete semantic criteria details")
except (TypeError, ValueError):
    judge, judge_details = {}, {}
    with (out / "rewardkit.log").open("a") as log:
        log.write("WARN: invalid/incomplete semantic output discarded; deterministic result retained\n")

output_quality = judge.get("output_quality")
process_judge = judge.get("process")
task_quality = judge.get("task_quality")
validity = judge.get("validity")

process = plan_score if process_judge is None else min(plan_score, float(process_judge or 0.0))

weighted = {"deterministic": (det_score, 55.0), "process": (process, 20.0)}
if output_quality is not None:
    weighted["output_quality"] = (float(output_quality or 0.0), 25.0)

den = sum(w for _, w in weighted.values())
continuous = sum(v * w for v, w in weighted.values()) / den if den else 0.0

rows = pre.get("tests", [])
weights = pre.get("test_weights", {})
row_names = [row.get("name") for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
counts_valid = all(type(pre.get(key)) is int for key in
                   ("exit_code", "total_checks", "passed_checks", "failed_checks", "skipped_checks"))
strict = (pre.get("strict_pass") is True and pre.get("coverage_valid") is True
          and counts_valid and pre["exit_code"] == 0
          and isinstance(rows, list) and bool(rows) and isinstance(weights, dict) and bool(weights)
          and all(isinstance(name, str) for name in row_names)
          and len(row_names) == len(rows) == len(set(row_names))
          and set(row_names) == set(weights)
          and pre["total_checks"] == pre["passed_checks"] == len(rows)
          and pre["failed_checks"] == pre["skipped_checks"] == 0
          and not pre.get("unknown_pytest_rows")
          and all(isinstance(row, dict) and row.get("status") == "passed"
                  and type(row.get("score")) in (int, float) and row["score"] == 1.0
                  for row in rows)
          and det_score == 1.0 and plan_score == 1.0)

reward = {
    "reward": 1.0 if strict else 0.0,
    "binary_reward": 1.0 if strict else 0.0,
    "continuous_reward": round(continuous, 4),
    "deterministic": round(det_score, 4),
    "process": round(process, 4),
}
if output_quality is not None:
    reward["output_quality"] = round(float(output_quality or 0.0), 4)
if task_quality is not None:
    reward["task_quality"] = round(float(task_quality or 0.0), 4)
if validity is not None:
    reward["validity"] = round(float(validity or 0.0), 4)

merge_details = {
    "reward": reward,
    "deterministic": pre,
    "process_artifacts": proc,
    "judge": judge,
    "weights": {"deterministic": 55, "output_quality": 25, "process": 20},
}
# Deep-merge both passes. `det_details or judge_details` discards ALL judge
# detail (the deterministic block is essentially always present); a shallow
# `details[key] = block` overwrite loses the other half, because both passes
# emit a "process" block — deterministic carries plan_md_present, judge carries
# the semantic criteria. Concatenate criteria for any dimension both produced.
rewardkit_details = {}
if isinstance(det_details, dict):
    rewardkit_details.update(copy.deepcopy(det_details))
if isinstance(judge_details, dict):
    for _key, _block in judge_details.items():
        _existing = rewardkit_details.get(_key)
        if (
            not isinstance(_existing, dict)
            or not isinstance(_block, dict)
            or not isinstance(_existing.get("criteria"), list)
            or not isinstance(_block.get("criteria"), list)
        ):
            rewardkit_details[_key] = copy.deepcopy(_block)
            continue
        _combined = copy.deepcopy(_block)
        _combined["criteria"] = copy.deepcopy(_existing["criteria"]) + copy.deepcopy(_block["criteria"])
        rewardkit_details[_key] = _combined
if isinstance(rewardkit_details.get("deterministic"), dict):
    rewardkit_details["deterministic"]["score"] = round(det_score, 4)
if isinstance(rewardkit_details.get("process"), dict):
    rewardkit_details["process"]["score"] = round(process, 4)
(out / "reward.json").write_text(json.dumps(reward, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
if rewardkit_details:
    (out / "reward-details.json").write_text(json.dumps(rewardkit_details, indent=2, sort_keys=True) + "\n", encoding="utf-8")
else:
    (out / "reward-details.json").write_text(json.dumps(merge_details, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(out / "final-reward-details.json").write_text(json.dumps(merge_details, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(out / "reward.txt").write_text(f"{reward['reward']:.4f}\n", encoding="utf-8")
PY
}

write_numeric_fallback_reward() {
  python3 - "$VERIFIER_DIR" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
pre = {
    "strict_pass": False,
    "strict_score": 0.0,
    "deterministic_score": 0.0,
    "passed_checks": 0,
    "failed_checks": 1,
    "skipped_checks": 0,
    "total_checks": 1,
    "failed_tests": [{"name": "test_sec_verifier_preflight", "message": "deterministic RewardKit pass failed"}],
    "reason": "deterministic RewardKit pass failed",
}
pre_path = out / "deterministic_reward.json"
if pre_path.exists():
    try:
        old = json.loads(pre_path.read_text())
        (out / "prepass-before-failure.json").write_text(json.dumps(old, indent=2) + "\n")
    except (OSError, ValueError):
        pass
pre_path.write_text(json.dumps(pre, indent=2, sort_keys=True) + "\n", encoding="utf-8")
reward = {"reward": 0.0, "binary_reward": 0.0, "continuous_reward": 0.0, "deterministic": 0.0, "process": 0.0}
(out / "reward.json").write_text(json.dumps(reward, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
details = out / "reward-details.json"
if not details.exists():
    details.write_text(json.dumps({"reward": reward, "deterministic": pre}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(out / "process_artifacts.json").write_text(json.dumps({"plan_md": {"score": 0.0, "error": "verifier finalization failed"}}) + "\n")
(out / "judge_inputs").mkdir(exist_ok=True)
(out / "rewardkit.log").touch(exist_ok=True)
(out / "reward.txt").write_text("0.0000\n", encoding="utf-8")
with (out / "test_output.log").open("a", encoding="utf-8") as log:
    log.write("\nverifier orchestration failed; see rewardkit.log and prepass-before-failure.json\n")
PY
}

# Install finalization before suite creation, copying, scoring or staging.
# SIGKILL, host loss, or an unwritable result volume cannot be recovered in-process.
FINALIZED=0
finish_verifier() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [ "$FINALIZED" != "1" ] || [ "$status" -ne 0 ]; then
    write_numeric_fallback_reward
    stage_task_artifacts
  fi
  rm -rf "$DETERMINISTIC_SUITE" "$JUDGE_SUITE" "$DETERMINISTIC_OUT" "$JUDGE_OUT"
  exit 0
}
trap finish_verifier EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
mkdir -p "$VERIFIER_DIR" "$VERIFIER_DIR/internal" /app/output "$TESTBED_DIR" /logs/artifacts/app/output
rm -f "$VERIFIER_DIR"/{reward.json,reward-details.json,reward.txt,deterministic_reward.json,process_artifacts.json,rewardkit.log,test_output.log,pytest_output.log,final-reward-details.json,prepass-before-failure.json} \
      "$VERIFIER_DIR/internal/deterministic_junit.xml"
: > "$VERIFIER_DIR/rewardkit.log"

rm -f "$VERIFIER_DIR"/continuous_reward.txt "$VERIFIER_DIR"/continuous-reward-details.json \
      "$VERIFIER_DIR"/result.json "$VERIFIER_DIR"/test_output.txt \
      "$VERIFIER_DIR"/ctrf.json "$VERIFIER_DIR"/deterministic-test-details.json
rm -rf "$DETERMINISTIC_SUITE" "$JUDGE_SUITE" "$DETERMINISTIC_OUT" "$JUDGE_OUT" "$VERIFIER_DIR"/judge_inputs
mkdir -p "$VERIFIER_DIR/internal"

find_trajectory || true

DETERMINISTIC_OK=0
build_deterministic_suite
run_deterministic_pytest_prepass

echo "=== RewardKit deterministic pass ===" >>"$VERIFIER_DIR/rewardkit.log"
if timeout 120 rewardkit "$DETERMINISTIC_SUITE" --workspace /app --output "$DETERMINISTIC_OUT/reward.json" >>"$VERIFIER_DIR/rewardkit.log" 2>&1; then
  DETERMINISTIC_OK=1
  sync_numeric_outputs
else
  echo "WARN: RewardKit deterministic run failed; see $VERIFIER_DIR/rewardkit.log" >&2
  write_numeric_fallback_reward
fi

STAGING_OK=0
if stage_task_artifacts; then
  STAGING_OK=1
else
  echo "WARN: judge evidence staging failed; deterministic result retained" >>"$VERIFIER_DIR/rewardkit.log"
fi

# v11.6.5 dual-provider: derive the semantic-judge provider from the four packaged
# judge TOMLs and reject mixed/invalid stacks. Both Anthropic Sonnet 4.6 and OpenAI
# GPT-5.6 Terra are canonical; this template ships the Sonnet profile and a task may
# swap all four judge headers to Terra (see rewardkit-templates/README.md).
SELECTED_JUDGE_PROVIDER="$(python3 -S - "$TESTS_DIR" <<'PY'
import sys, tomllib
from pathlib import Path
root = Path(sys.argv[1])
paths = [root/'process/judge.toml', root/'output_quality/judge.toml', root/'task_quality/judge.toml', root/'validity/judge.toml']
profiles = []
for path in paths:
    cfg = tomllib.loads(path.read_text(encoding='utf-8'))
    judge = cfg.get('judge', {})
    provider = judge.get('judge', '')
    if provider == 'openai/gpt-5.6-terra' and judge.get('reasoning_effort') != 'high':
        raise SystemExit(2)
    if provider not in {'anthropic/claude-sonnet-4-6', 'openai/gpt-5.6-terra'}:
        raise SystemExit(2)
    profiles.append(provider)
if len(set(profiles)) != 1:
    raise SystemExit(2)
print(profiles[0])
PY
)" || SELECTED_JUDGE_PROVIDER=""

JUDGE_API_READY=0
case "${SELECTED_JUDGE_PROVIDER:-}" in
  anthropic/claude-sonnet-4-6) [ -n "${ANTHROPIC_API_KEY:-}" ] && JUDGE_API_READY=1 ;;
  openai/gpt-5.6-terra)        [ -n "${OPENAI_API_KEY:-}" ] && JUDGE_API_READY=1 ;;
  *) echo "WARN: semantic judge provider profile is missing, mixed, or unsupported" >>"$VERIFIER_DIR/rewardkit.log" ;;
esac

if [ "$DETERMINISTIC_OK" = "1" ] && [ "$STAGING_OK" = "1" ] && [ "$JUDGE_API_READY" = "1" ] && [ -n "${TRAJECTORY_SOURCE:-}" ] && [ -f "$TRAJECTORY_SOURCE" ]; then
  if build_judge_suite; then
    echo "=== RewardKit judge pass ===" >>"$VERIFIER_DIR/rewardkit.log"
    if ! timeout 120 rewardkit "$JUDGE_SUITE" --workspace /app --output "$JUDGE_OUT/reward.json" >>"$VERIFIER_DIR/rewardkit.log" 2>&1; then
      echo "WARN: RewardKit judge run failed; deterministic result retained" >>"$VERIFIER_DIR/rewardkit.log"
      rm -f "$JUDGE_OUT/reward.json" "$JUDGE_OUT/reward-details.json"
    fi
    sync_numeric_outputs
  else
    echo "WARN: judge suite preparation failed; deterministic result retained" >>"$VERIFIER_DIR/rewardkit.log"
    rm -f "$JUDGE_OUT/reward.json" "$JUDGE_OUT/reward-details.json"
  fi
else
  echo "INFO: semantic judge skipped; requires deterministic pass + coherent provider/API key + real agent/model trajectory" >>"$VERIFIER_DIR/rewardkit.log"
fi

rm -rf "$DETERMINISTIC_SUITE" "$JUDGE_SUITE" "$DETERMINISTIC_OUT" "$JUDGE_OUT"

mkdir -p /logs/artifacts/app/output 2>/dev/null || true
# Archive only declared regular outputs via the same staging allow-list; never copy an arbitrary output tree.
for artifact in plan.md findings.json; do
  copy_if_exists "/app/output/$artifact" "/logs/artifacts/app/output/$artifact" || \
    echo "WARN: artifact archival failed for $artifact" >>"$VERIFIER_DIR/rewardkit.log"
done

python3 -S - "$VERIFIER_DIR" <<'PY'
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
required = ["reward.json", "reward-details.json", "reward.txt", "deterministic_reward.json", "process_artifacts.json", "rewardkit.log", "test_output.log", "judge_inputs"]
missing = [name for name in required if not (out / name).exists()]
if missing:
    raise SystemExit(f"missing verifier artifacts: {missing}")
for name in ["reward.json", "reward-details.json", "deterministic_reward.json"]:
    path = out / name
    if path.exists():
        json.loads(path.read_text(encoding="utf-8"))
PY

FINALIZED=1
exit 0
