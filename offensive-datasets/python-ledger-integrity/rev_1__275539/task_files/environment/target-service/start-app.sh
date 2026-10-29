#!/bin/sh
# Idempotent (re)start of the authentic hosted ledger service.
#
#   default call:               no-op when already healthy, otherwise launch.
#   FORCE_RESTART=1 (reset):    stop, wipe private state, rebuild the fixture,
#                               then launch the same authentic application.
#   RESTART_ONLY=1:             stop and relaunch, preserving state.
#
# This script never posts a journal entry and never writes the audit table; the
# fixture creates only an unposted review entry, and only a real application
# write can produce a posted transition.
set -eu
umask 077
PORT="${SVC_PORT:-9090}"
STATE="${SVC_STATE_DIR:-/var/lib/ledger}"
PIDFILE="${SVC_PIDFILE:-/var/run/ledger.pid}"
LOG="${SVC_LOG:-/var/log/ledger/app.log}"
APP="${SVC_APP:-/opt/ledger/appliance}"
PYTHON="${SVC_PYTHON:-/opt/ledger-venv/bin/python}"
export LEDGER_STATE_DIR="$STATE"
export LEDGER_STATIC_ROOT="${LEDGER_STATIC_ROOT:-/opt/ledger-static}"
export LEDGER_EVENT_LOG="${LEDGER_EVENT_LOG:-$STATE/events.jsonl}"
export PYTHONPATH="${SVC_ROOT:-/opt/ledger}:/opt/ledger/vendor/django-ledger:/opt/ledger/vendor/waitress:${PYTHONPATH:-}"
SVC_USER="${SVC_USER:-ledger}"

mkdir -p "$STATE" /var/run "$(dirname "$LOG")"
chown "$SVC_USER:$SVC_USER" "$STATE" 2>/dev/null || true
chmod 0700 "$STATE" 2>/dev/null || true

as_service() {
  if [ "$(id -u)" = "0" ]; then
    runuser -u "$SVC_USER" -- "$@"
  else
    "$@"
  fi
}

health_ok() {
  "$PYTHON" - "$PORT" <<'PY' >/dev/null 2>&1
import http.client, sys
conn = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=2)
conn.request("GET", "/auth/login/")
resp = conn.getresponse()
resp.read(64)
sys.exit(0 if resp.status == 200 else 1)
PY
}

port_open() {
  "$PYTHON" - "$PORT" <<'PY' >/dev/null 2>&1
import socket, sys
sock = socket.socket()
sock.settimeout(0.3)
sys.exit(0 if sock.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
}

wait_port_free() {
  i=0
  while [ "$i" -lt 100 ]; do
    port_open || return 0
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

wait_pid_gone() {
  pid="$1"
  [ -n "$pid" ] || return 0
  i=0
  while [ "$i" -lt 100 ]; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

stop_runner() {
  oldpid=""
  [ -f "$PIDFILE" ] && oldpid="$(cat "$PIDFILE" 2>/dev/null || true)"
  [ -n "$oldpid" ] && kill "$oldpid" 2>/dev/null || true
  pkill -f "deployment.run_service" 2>/dev/null || true
  [ -n "$oldpid" ] && wait_pid_gone "$oldpid" || true
  if port_open; then
    [ -n "$oldpid" ] && kill -KILL "$oldpid" 2>/dev/null || true
    pkill -KILL -f "deployment.run_service" 2>/dev/null || true
    wait_port_free || true
  fi
  rm -f "$PIDFILE" 2>/dev/null || true
}

launch_once() {
  : > "$LOG" 2>/dev/null || true
  cd "${SVC_ROOT:-/opt/ledger}"
  as_service setsid "$PYTHON" -m deployment.run_service </dev/null >>"$LOG" 2>&1 &
  CHILD=$!
  echo "$CHILD" > "$PIDFILE"
  sleep 0.2
  kill -0 "$CHILD" 2>/dev/null || return 1
  i=0
  while [ "$i" -lt 200 ]; do
    health_ok && return 0
    kill -0 "$CHILD" 2>/dev/null || return 1
    sleep 0.25
    i=$((i + 1))
  done
  return 1
}

if [ "${FORCE_RESTART:-0}" = "1" ]; then
  stop_runner
  wait_port_free || { echo "port ${PORT} did not release before reset" >&2; exit 1; }
  rm -f "$STATE"/state.sqlite3 "$STATE"/state.sqlite3-wal "$STATE"/state.sqlite3-shm "$STATE"/fixture.json "$STATE"/events.jsonl
  rm -f "$STATE"/secret_key
  as_service "$PYTHON" "$APP" reset >/dev/null
elif [ "${RESTART_ONLY:-0}" = "1" ]; then
  stop_runner
  wait_port_free || { echo "port ${PORT} did not release before restart" >&2; exit 1; }
else
  health_ok && exit 0
  stop_runner
  as_service "$PYTHON" "$APP" start >/dev/null || {
    rm -f "$STATE"/state.sqlite3 "$STATE"/state.sqlite3-wal "$STATE"/state.sqlite3-shm
    as_service "$PYTHON" "$APP" reset >/dev/null
  }
fi

for _ in 1 2; do
  launch_once && exit 0
  if grep -qi "address already in use\|bind" "$LOG" 2>/dev/null; then
    stop_runner
    wait_port_free || true
    sleep 0.2
    continue
  fi
  break
done

echo "service did not become healthy" >&2
tail -80 "$LOG" >&2 2>/dev/null || true
exit 1
