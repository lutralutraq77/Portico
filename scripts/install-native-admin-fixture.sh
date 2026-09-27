#!/usr/bin/env bash
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(id -u)" -ne 0
test "$#" -eq 3
tree=$1
binary=$2
digest=$3
test "$tree" = "$GITHUB_WORKSPACE/work/admin-package/$(git rev-parse HEAD)/portico-admin-tree.tar.gz"
test "$binary" = "$GITHUB_WORKSPACE/work/installed-admin/portico"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]]
test "$(sha256sum "$tree" | cut -d ' ' -f 1)" = "$digest"
test ! -e /usr/lib/portico-admin
test ! -e /usr/bin/portico
# The source-bound builder supplies only fixed usr/lib/portico-admin members.
# This script is restricted to the ephemeral CI runner, never the developer host.
sudo tar --extract --gzip --file "$tree" --directory / --same-owner --same-permissions
sudo install -o root -g root -m 0755 "$binary" /usr/bin/portico
test "$(stat -c '%u:%g:%a' /usr/lib/portico-admin/electron/chrome-sandbox)" = '0:0:4755'
test "$(sha256sum /usr/bin/portico | cut -d ' ' -f 1)" = "$(sha256sum "$binary" | cut -d ' ' -f 1)"
echo PORTICO_NATIVE_INSTALL_FIXTURE_READY
