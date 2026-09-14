#!/usr/bin/env bash
# Only called inside the disposable Arch build container, with no network.
set -Eeuo pipefail
test "$(id -u)" -eq 0
cd /ssh-input
sha256sum --check --strict packages.sha256
pacman -Q archlinux-keyring
sha256sum /usr/share/pacman/keyrings/archlinux.gpg /usr/share/pacman/keyrings/archlinux-revoked /usr/share/pacman/keyrings/archlinux-trusted
# Retain Arch's canonical master-key trust threshold. These are setup bounds.
timeout 300 pacman-key --init
timeout 300 pacman-key --populate archlinux
for package in openssh-10.5p1-1-x86_64.pkg.tar.zst libedit-20260512_3.1-1-x86_64.pkg.tar.zst; do
    timeout 30 gpg --batch --homedir /etc/pacman.d/gnupg --status-fd 1 --verify "$package.sig" "$package"
done
cp openssh-10.5p1-1-x86_64.pkg.tar.zst /tmp/portico-tampered-ssh.pkg.tar.zst
printf tampered >> /tmp/portico-tampered-ssh.pkg.tar.zst
if timeout 30 gpg --batch --homedir /etc/pacman.d/gnupg --status-fd 1 --verify openssh-10.5p1-1-x86_64.pkg.tar.zst.sig /tmp/portico-tampered-ssh.pkg.tar.zst > /tmp/portico-tampered-signature.log 2>&1; then
    echo 'Modified package signature accepted' >&2
    exit 1
fi
cat /tmp/portico-tampered-signature.log
grep -q '^\[GNUPG:\] BADSIG ' /tmp/portico-tampered-signature.log
echo PORTICO_SSH_TAMPERED_PACKAGE_REJECTED
cat > /tmp/portico-ssh-pacman.conf <<'CONF'
[options]
Architecture = x86_64
SigLevel = Required TrustedOnly
LocalFileSigLevel = Required TrustedOnly
CONF
timeout 90 pacman --config /tmp/portico-ssh-pacman.conf -U --noconfirm /ssh-input/libedit-20260512_3.1-1-x86_64.pkg.tar.zst /ssh-input/openssh-10.5p1-1-x86_64.pkg.tar.zst
test "$(pacman -Q openssh)" = 'openssh 10.5p1-1'
test "$(pacman -Q libedit)" = 'libedit 20260512_3.1-1'
timeout 10 /usr/bin/ssh -V
sha256sum /usr/bin/ssh "$(readlink -f /usr/lib/libedit.so.0)" > /output/ssh-binaries.sha256
cat /output/ssh-binaries.sha256
gpgconf --homedir /etc/pacman.d/gnupg --kill all
echo PORTICO_SSH_PACKAGE_PASS
