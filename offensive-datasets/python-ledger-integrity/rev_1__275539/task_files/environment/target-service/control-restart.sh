#!/bin/sh
# Restart the authentic application while preserving private state.
set -eu
exec env RESTART_ONLY=1 "${SVC_START_SCRIPT:-/usr/local/bin/start-app.sh}"
