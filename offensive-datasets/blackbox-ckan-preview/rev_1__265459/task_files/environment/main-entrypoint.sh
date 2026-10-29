#!/bin/sh
# MAIN entrypoint. Prepares the agent environment only — it MUST NOT launch or
# embed the protected target (that lives in the sidecar). No `USER`; the platform
# applies `[agent].user` after this runs.
set -eu

: "${TASK_AGENT_USER:=auditor}"
mkdir -p /testbed /app/output /logs/verifier /logs/artifacts /agent
chown -R "$TASK_AGENT_USER:$TASK_AGENT_USER" /testbed /app/output /logs/artifacts /agent
chown -R root:root /logs/verifier
chmod 0755 /testbed /app/output /logs/artifacts /agent
chmod 0700 /logs/verifier
exec "$@"
