# ── MAIN image (agent phase + later the shared verifier). ───────────────────────
# HARBOR builds this as the `main` service. It contains ONLY agent-facing tooling,
# writable task outputs, and the build-time verifier dependencies. It MUST NOT
# contain the target runtime, target-private state, trusted receipt/effect, the
# warden, or any target launch script.
#
# ⛔ NO `USER` INSTRUCTION ANYWHERE (not even `USER root`). The unprivileged agent
#    identity is selected through `[agent].user = "auditor"` in task.toml. A USER
#    line can be rejected by upload validation and moves startup into the wrong
#    identity before the platform applies the task user.
FROM python:3.13-slim-bookworm@sha256:ec13883b084419a87507657f50589d3e4aab1aa3233e686ec50a2c22e2cfef73

ENV DEBIAN_FRONTEND=noninteractive PYTHONNOUSERSITE=1 TASK_AGENT_USER=auditor

# Agent-facing tools + build-time verifier deps (installed at build time
# so the shared verifier never installs anything at score time).
# The `[all]` extra + `botocore` are LOAD-BEARING: they ship the LLM-judge backend
# (litellm/provider SDKs). Plain `harbor-rewardkit` builds and passes `command -v`, but the
# judge pass then silently no-ops and output_quality/process/validity/task_quality never
# populate; validate the semantic pass with a real judge run when available.
COPY python-constraints.txt /opt/task/python-constraints.txt
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl jq procps psmisc tmux util-linux python3-pip python3-venv \
    && python3 -m pip install --no-cache-dir -c /opt/task/python-constraints.txt \
         pytest==8.3.3 'harbor-rewardkit[all]==0.2.3' botocore==1.43.114 \
    && command -v rewardkit >/dev/null \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged agent account + writable/verifier dirs. Agent owns /testbed +
# /app/output; verifier-only staging dirs are root-owned.
# ⚠️ /solution MUST be 0711 (root:root, traversable-not-listable), NOT 0700.
# The platform runs the ORACLE by executing `/solution/solve.sh` DIRECTLY as
# `[agent].user` (agent.name=oracle → the non-root agent account). A 0700-root
# /solution makes the oracle fail with `solve.sh: Permission denied` (exit 126) →
# no proof.json → every replay row fails. 0711
# lets the oracle traverse+exec solve.sh by path while keeping the dir non-listable;
# it is empty during a real agent phase, so the solution stays agent-unavailable
# temporally (staged only at oracle/verify time). /tests stays 0700 because the
# VERIFIER runs as root.
RUN useradd --create-home --uid 10001 --shell /bin/bash auditor \
    && mkdir -p /app/output /testbed /logs/verifier /logs/artifacts /agent /tests /solution /scripts \
    && chown -R auditor:auditor /app/output /testbed /logs/artifacts /agent \
    && chown -R root:root /logs/verifier /tests /solution /scripts \
    && chmod 0700 /logs/verifier /tests /scripts \
    && chmod 0711 /solution

COPY main-entrypoint.sh /usr/local/bin/main-entrypoint.sh
RUN chmod 0555 /usr/local/bin/main-entrypoint.sh

# Agent exploration helper: `taskctl reset` clears the preview relay to clean
# state (loopback control on the shared netns). Never reveals a private export
# value or creates the protected effect.
COPY taskctl /usr/local/bin/taskctl
RUN chmod 0555 /usr/local/bin/taskctl

WORKDIR /testbed
ENTRYPOINT ["/usr/local/bin/main-entrypoint.sh"]
CMD ["sleep", "infinity"]
