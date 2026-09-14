#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -eq 0
test ! -e /usr/lib/portico-admin
mkdir -m 700 /root/portico-administrator-fixture
printf '%s\n' 'isolated owner state marker' > /root/portico-administrator-fixture/preserved
before=$(sha256sum /root/portico-administrator-fixture/preserved)
packages=(/input/portico-admin-development-*.pkg.tar.zst)
test "${#packages[@]}" -eq 1
# The NIC-less package fixture validates ownership/install/remove without
# executing the browser. Actual dependency-complete window testing is separate.
pacman -U --nodeps --nodeps --noconfirm "${packages[0]}"
test "$(stat -c '%u:%g:%a' /usr/lib/portico-admin/electron/chrome-sandbox)" = '0:0:4755'
test "$(stat -c '%u:%g:%a' /usr/lib/portico-admin/electron/electron)" = '0:0:755'
test -f /usr/lib/portico-admin/electron/LICENSE
test -f /usr/lib/portico-admin/electron/LICENSES.chromium.html
test -f /usr/lib/portico-admin/app/main.cjs
test "$(find /usr/lib/portico-admin -type l | wc -l)" -eq 0
test "$(find /usr/lib/portico-admin -perm /0022 | wc -l)" -eq 0
test "$(find /usr/lib/portico-admin -type f -perm /7000 | wc -l)" -eq 1
pacman -Qkk portico-admin-development
pacman -R --noconfirm portico-admin-development
test ! -e /usr/lib/portico-admin
test "$before" = "$(sha256sum /root/portico-administrator-fixture/preserved)"
echo PORTICO_ARCH_ADMIN_INSTALL_REMOVE_PASS
