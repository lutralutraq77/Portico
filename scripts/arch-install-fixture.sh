#!/usr/bin/env bash
set -euo pipefail
trap 'printf "ARCH_INSTALL_FAILED line=%s status=%s\n" "$LINENO" "$?" >&2' ERR
test "$(id -u)" -eq 0
packages=(/input/portico-cli-development-*.pkg.tar.zst)
test "${#packages[@]}" -eq 1
test -f "${packages[0]}"
# The official minimal image deliberately omits manuals and documentation.
# Admit only this package's two documentation files so this fixture can check
# their real installation. Keep every signature and other extraction rule.
pacman-conf NoExtract
printf '\n[options]\nNoExtract = !usr/share/man/man1/portico.1.gz !usr/share/doc/portico-cli-development/DEVELOPMENT.txt\n' >> /etc/pacman.conf
# This is a fresh networkless disposable container, with no host install roots.
# Use its unchanged local-package signature policy. No signature-policy override.
pacman -U --noconfirm "${packages[0]}"
stat -c 'installed binary mode=%a uid=%u gid=%g' /usr/bin/portico
test "$(stat -c '%u:%g:%a' /usr/bin/portico)" = '0:0:755'
test -f /usr/share/man/man1/portico.1.gz || test -f /usr/share/man/man1/portico.1
test -f /usr/share/doc/portico-cli-development/DEVELOPMENT.txt
printf '%s  /usr/bin/portico\n' "$PORTICO_BINARY_SHA256" | sha256sum --check --strict
test "$(stat -c '%u:%g:%a' /usr/lib/systemd/user/portico-agent.service)" = '0:0:644'
printf '%s  /usr/lib/systemd/user/portico-agent.service\n' "$PORTICO_UNIT_SHA256" | sha256sum --check --strict
mkdir -p /run/user/0
chmod 0700 /run/user/0
XDG_RUNTIME_DIR=/run/user/0 systemd-analyze --user verify /usr/lib/systemd/user/portico-agent.service
test ! -e /etc/systemd/user/default.target.wants/portico-agent.service
test ! -e /root/.config/systemd/user/default.target.wants/portico-agent.service
echo PORTICO_ARCH_USER_UNIT_VERIFIED_INACTIVE
portico version --json
portico help
pacman -Ql portico-cli-development
test ! -e /etc/portico
test ! -e /usr/lib/systemd/system/portico.service
mkdir -m 0700 /var/lib/portico-package-fixture
printf 'test-owned-state\n' > /var/lib/portico-package-fixture/state
chmod 0600 /var/lib/portico-package-fixture/state
cp /var/lib/portico-package-fixture/state /tmp/original-state
pacman -R --noconfirm portico-cli-development
test ! -e /usr/bin/portico
test ! -e /usr/lib/systemd/user/portico-agent.service
cmp /tmp/original-state /var/lib/portico-package-fixture/state
test "$(stat -c '%u:%g:%a' /var/lib/portico-package-fixture/state)" = '0:0:600'
echo PORTICO_ARCH_INSTALL_REMOVE_PASS
