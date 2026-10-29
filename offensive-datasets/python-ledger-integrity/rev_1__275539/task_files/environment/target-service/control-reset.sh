#!/bin/sh
# Reset lifecycle: wipe service-private state, rebuild the deterministic fixture
# and relaunch the authentic application. Invoked only by the controller.
# It must never create a posted transition itself.
set -eu
exec env FORCE_RESTART=1 "${SVC_START_SCRIPT:-/usr/local/bin/start-app.sh}"
