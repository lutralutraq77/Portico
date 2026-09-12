#!/usr/bin/bash
set -euo pipefail
# PID 1 of the NIC-less disposable QEMU guest only.
test "$$" -eq 1
chmod 0755 /
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755 tmpfs /run
mount -t tmpfs -o mode=1777 tmpfs /tmp
mkdir -p /dev/pts /dev/shm
mount -t devpts -o mode=0620,ptmxmode=0666 devpts /dev/pts
ln -sfn pts/ptmx /dev/ptmx
mount -t tmpfs -o mode=1777 tmpfs /dev/shm
exec /usr/lib/systemd/systemd --system --unit=portico-fixture.target
