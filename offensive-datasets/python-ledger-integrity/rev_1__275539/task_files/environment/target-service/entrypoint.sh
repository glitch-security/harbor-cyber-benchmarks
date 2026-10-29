#!/bin/sh
# Boot helper for the target appliance (defense-in-depth identity drop).
set -eu
: "${TASK_AGENT_USER:=auditor}"
[ "$#" -gt 0 ] || set -- /bin/sh
if [ "$(id -u)" = "0" ] && [ "${SVC_KEEP_ROOT:-0}" != "1" ]; then
  case "${1:-}" in
    ""|bash|/bin/bash|sh|/bin/sh|zsh|/bin/zsh|sleep)
      cd /testbed
      exec /usr/sbin/runuser -u "$TASK_AGENT_USER" -- "$@"
      ;;
  esac
fi
exec "$@"
