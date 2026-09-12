#!/usr/bin/env bash
# Runs only in a fresh networkless build container. The output is a guest
# initramfs; no host installation root, cgroup tree or private state is mounted.
set -Eeuo pipefail
trap 'printf "PORTICO_ARCH_ROOTFS_FAILED line=%s status=%s\n" "$LINENO" "$?" >&2' ERR
test "$(id -u)" -eq 0
packages=(/input/portico-cli-development-*.pkg.tar.zst)
test "${#packages[@]}" -eq 1
pacman -U --noconfirm "${packages[0]}"
printf '%s  /usr/bin/portico\n' "$PORTICO_BINARY_SHA256" | sha256sum --check --strict
printf '%s  /usr/lib/systemd/user/portico-agent.service\n' "$PORTICO_UNIT_SHA256" | sha256sum --check --strict
test -x /usr/lib/systemd/systemd
test -x /usr/bin/bsdtar
test -x /usr/bin/curl
test -x /usr/bin/openssl
groupadd --gid 1000 porticofixture
groupadd --gid 1001 porticoother
useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash porticofixture
useradd --uid 1001 --gid 1001 --create-home --shell /bin/bash porticoother
chmod 0700 /home/porticofixture /home/porticoother
install -d -o 1000 -g 1000 -m 0700 /home/porticofixture/.config /home/porticofixture/.config/portico
printf '%s\n' '{"version":2,"enrollment_config_file":"/home/porticofixture/.config/portico/not-provisioned.json"}' > /home/porticofixture/.config/portico/client.json
chown 1000:1000 /home/porticofixture/.config/portico/client.json
chmod 0600 /home/porticofixture/.config/portico/client.json
sha256sum /home/porticofixture/.config/portico/client.json > /portico-fixture-state.sha256
printf '%s  /usr/bin/portico\n%s  /usr/lib/systemd/user/portico-agent.service\n' "$PORTICO_BINARY_SHA256" "$PORTICO_UNIT_SHA256" > /portico-fixture-package.sha256
printf '192.0.2.10\n' > /portico-systemd-isolated-fixture
printf '192.0.2.10\n' > /portico-isolated-fixture
printf '4cc2d26863f345c98b08dbb54b5cb3e6\n' > /etc/machine-id
printf 'portico-service-fixture\n' > /etc/hostname
printf '127.0.0.1 localhost\n::1 localhost\n' > /etc/hosts
: > /etc/resolv.conf
: > /etc/fstab
install -m 0755 /scripts/arch-systemd-guest.sh /portico-systemd-fixture.sh
install -m 0755 /scripts/arch-systemd-init.sh /portico-systemd-init
install -m 0755 /controller-input /controller
install -m 0755 /issuer-input /portico-issuer
ln -s usr/bin/portico /portico
cat > /etc/systemd/system/portico-fixture.target <<'UNIT'
[Unit]
Description=Disposable Portico service qualification
Requires=basic.target portico-fixture.service
After=basic.target portico-fixture.service
AllowIsolate=yes
UNIT
cat > /etc/systemd/system/portico-fixture.service <<'UNIT'
[Unit]
Description=Observe actual installed Portico user service
After=basic.target
[Service]
Type=oneshot
ExecStart=/usr/bin/bash /portico-systemd-fixture.sh
ExecStopPost=/usr/bin/systemctl --no-block poweroff
TimeoutStartSec=1300s
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
UNIT
# Only these fixture runtime paths and character devices enter the archive.
# Never archive the container's live /dev, /proc, /sys or /run mounts.
mkdir -p /tmp/portico-skeleton/{dev,proc,sys,tmp,run}
chmod 1777 /tmp/portico-skeleton/tmp
mknod -m 0600 /tmp/portico-skeleton/dev/console c 5 1
mknod -m 0666 /tmp/portico-skeleton/dev/null c 1 3
pacman -Q > /output/systemd-rootfs-packages.txt
/usr/lib/systemd/systemd --version > /output/systemd-version.txt
bsdtar --format=newc -cf - -C / bin etc home lib lib64 root sbin usr var portico controller portico-issuer portico-systemd-init portico-systemd-fixture.sh portico-systemd-isolated-fixture portico-isolated-fixture portico-fixture-state.sha256 portico-fixture-package.sha256 -C /tmp/portico-skeleton dev proc sys tmp run | gzip -1 > /output/systemd-initramfs.cpio.gz
echo PORTICO_ARCH_SYSTEMD_ROOTFS_BUILT
