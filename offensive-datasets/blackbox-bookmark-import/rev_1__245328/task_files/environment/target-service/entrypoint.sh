#!/bin/sh
# Boot helper for the target-service image (defense-in-depth identity drop).
# The warden is the container ENTRYPOINT and calls start-app.sh itself; this
# script exists so that any interactive/default command still lands as the
# unprivileged service identity, with an explicit root-maintenance opt-out.
set -eu
: "${TASK_AGENT_USER:=auditor}"
[ "$#" -gt 0 ] || set -- /bin/sh
/usr/local/bin/start-app.sh
if [ "$(id -u)" = "0" ] && [ "${SVC_KEEP_ROOT:-0}" != "1" ]; then
  case "${1:-}" in
    ""|bash|/bin/bash|sh|/bin/sh|zsh|/bin/zsh|sleep)
      cd /testbed
      exec /usr/sbin/runuser -u "$TASK_AGENT_USER" -- "$@"
      ;;
  esac
fi
exec "$@"
