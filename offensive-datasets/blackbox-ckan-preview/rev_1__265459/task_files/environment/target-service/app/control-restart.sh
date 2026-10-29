#!/bin/bash
# Restart app processes, preserving export state and the CKAN database.
exec env RESTART_ONLY=1 /usr/local/bin/start-app.sh
