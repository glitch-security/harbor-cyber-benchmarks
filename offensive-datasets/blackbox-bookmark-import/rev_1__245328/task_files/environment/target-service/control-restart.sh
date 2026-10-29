#!/bin/sh
# Restart the authentic process, preserving private state and the protected effect.
set -eu
exec env RESTART_ONLY=1 /usr/local/bin/start-app.sh
