#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -ne 0
mkdir /tmp/portico-admin-package
cd /tmp/portico-admin-package
cp /input/PKGBUILD /input/portico-admin-tree.tar.gz /input/DEVELOPMENT.txt .
# Only the build-only dependency check is omitted in this offline image. The
# package declares its actual runtime dependencies; this fixture does not run it.
makepkg --nodeps --noconfirm --log
packages=(portico-admin-development-*.pkg.tar.zst)
test "${#packages[@]}" -eq 1
test -f "${packages[0]}"
cp "${packages[0]}" /output/
pacman -Q > /output/build-packages.txt
echo PORTICO_ARCH_ADMIN_PACKAGE_BUILT
