#!/bin/sh
# Reset lifecycle: wipe the protected effect + service-private state and relaunch
# the AUTHENTIC service from clean state. Invoked only by the warden on
# POST /control/reset. It must NOT itself create the protected effect or a passing
# receipt — only the authentic service, driven by a real replay, may do that
# (contract §6 security rule).
set -eu

exec env FORCE_RESTART=1 /usr/local/bin/start-app.sh
