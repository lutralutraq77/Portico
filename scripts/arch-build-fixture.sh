#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -ne 0
mkdir /tmp/portico-package
cd /tmp/portico-package
cp /input/PKGBUILD /input/portico /input/portico.1 /input/DEVELOPMENT.txt /input/portico-agent.service .
chmod u+x portico
stat -c 'build input mode=%a uid=%u gid=%g' portico
awk '$2 == "/tmp" { print "build mount: " $0 }' /proc/mounts
cp portico /tmp/portico-original
printf '\0' >> portico
if makepkg --verifysource --noconfirm > /tmp/checksum-negative.log 2>&1; then
    echo 'Modified application passed source verification' >&2
    exit 1
fi
grep -q 'validity check' /tmp/checksum-negative.log
echo PORTICO_ARCH_MODIFIED_SOURCE_REJECTED
cp /tmp/portico-original portico
makepkg --log --noconfirm
packages=(portico-cli-development-*.pkg.tar.zst)
test "${#packages[@]}" -eq 1
test -f "${packages[0]}"
cp "${packages[0]}" /output/
# makepkg executes check() in srcdir, not in the recipe's parent directory.
cp src/version.json /output/
pacman -Q > /output/build-packages.txt
printf '%s\n' "$SOURCE_DATE_EPOCH" > /output/source-date-epoch.txt
echo PORTICO_ARCH_PACKAGE_BUILT
