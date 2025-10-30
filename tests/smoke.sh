#!/usr/bin/env bash
set -euo pipefail
exe="${1:-target/debug/proclet}"

echo "== OUTSIDE =="
echo "PIDNS OUT: $(readlink -f /proc/self/ns/pid)"
echo "MNTNS OUT: $(readlink -f /proc/self/ns/mnt)"

echo
echo "== INSIDE =="
sudo "$exe" -- /bin/sh -c '
  echo "pid=$$"
  echo "PIDNS IN: $(readlink -f /proc/self/ns/pid)"
  echo "MNTNS IN: $(readlink -f /proc/self/ns/mnt)"
  mount | grep " on /proc " | head -n1
  ps -o pid,ppid,comm --forest
'

echo
echo "== MOUNT ISOLATION =="
sudo "$exe" -- /bin/sh -euxc '
  mkdir -p /mnt/proclet-test
  mount -t tmpfs none /mnt/proclet-test
  touch /mnt/proclet-test/hello
  test -f /mnt/proclet-test/hello
'

echo
echo "== EXIT CODE =="
set +e
sudo "$exe" -- /bin/sh -c "exit 7"; code=$?
set -e
echo "exit=$code (expect 7)"
test "$code" -eq 7

echo "OK ✅"
