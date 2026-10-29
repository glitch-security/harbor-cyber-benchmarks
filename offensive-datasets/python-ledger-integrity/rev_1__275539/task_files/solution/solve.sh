#!/bin/sh
# Author reference solution. Runs as the unprivileged agent account.
set -eu
exec python3 /solution/build_proof.py
