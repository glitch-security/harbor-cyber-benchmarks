#!/bin/sh
# MAIN entrypoint. Prepares the agent environment only. It must not launch or
# embed the target appliance, which lives in the isolated target service.
set -eu

: "${TASK_AGENT_USER:=auditor}"
mkdir -p /testbed /app/output /logs/verifier /logs/artifacts /agent
# The proof-format document stays root-owned and read-only. The /testbed
# directory is handed to the agent so it can create /testbed/proof.json.
chown "$TASK_AGENT_USER:$TASK_AGENT_USER" /testbed
chown -R "$TASK_AGENT_USER:$TASK_AGENT_USER" /app/output /logs/artifacts /agent
chown -R root:root /logs/verifier
chmod 0755 /testbed /app/output /logs/artifacts /agent
chmod 0700 /logs/verifier
exec "$@"
