#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "PORTICO_ARCH_SYSTEMD_FAILED line=%s status=%s\n" "$LINENO" "$?" >&2; journalctl --no-pager -b -n 100 >&2' ERR
test "$(cat /proc/1/comm)" = systemd
test "$(cat /portico-systemd-isolated-fixture)" = 192.0.2.10
interfaces=(/sys/class/net/*)
test "${#interfaces[@]}" -eq 1
test "${interfaces[0]}" = /sys/class/net/lo
sha256sum --check --strict /portico-fixture-package.sha256
test "$(stat -c '%u:%g:%a' /usr/lib/systemd/user/portico-agent.service)" = 0:0:644
test ! -e /etc/systemd/user/default.target.wants/portico-agent.service
systemctl start systemd-user-sessions.service
test "$(systemctl show --property=ActiveState --value systemd-user-sessions.service)" = active
test ! -e /run/nologin
systemctl start systemd-logind.service user@1000.service
user_command() {
    runuser -u porticofixture -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "$@"
}
user_systemctl() { user_command systemctl --user "$@"; }
socket=/run/user/1000/portico-agent/agent.sock
test "$(user_systemctl is-enabled portico-agent.service || :)" = disabled
test "$(user_systemctl show --property=ActiveState --value portico-agent.service)" = inactive
test ! -e "$socket"
echo PORTICO_ARCH_SERVICE_INSTALLED_INACTIVE

wait_locked() {
    local state deadline=$((SECONDS+20))
    while (( SECONDS < deadline )); do
        state=$(user_command portico agent status --socket "$socket" 2>/dev/null) || state=''
        if [[ "$state" == '{"version":1,"state":"locked"}' ]]; then return 0; fi
        sleep 0.1
    done
    return 1
}
observe_service() {
    local agent_pid cgroup
    agent_pid=$(user_systemctl show --property=MainPID --value portico-agent.service)
    [[ "$agent_pid" =~ ^[1-9][0-9]*$ ]]
    test "$(readlink "/proc/$agent_pid/exe")" = /usr/bin/portico
    test "$(awk '/^Uid:/ {print $2 ":" $3 ":" $4 ":" $5}' "/proc/$agent_pid/status")" = 1000:1000:1000:1000
    test "$(awk '/^NoNewPrivs:/ {print $2}' "/proc/$agent_pid/status")" = 1
    test "$(awk '/^Seccomp:/ {print $2}' "/proc/$agent_pid/status")" = 2
    test "$(awk '/^CapEff:/ {print $2}' "/proc/$agent_pid/status")" = 0000000000000000
    test "$(awk '/^Umask:/ {print $2}' "/proc/$agent_pid/status")" = 0077
    test "$(awk '/^Max core file size/ {print $5 ":" $6}' "/proc/$agent_pid/limits")" = 0:0
    test "$(awk '/^Max open files/ {print $4 ":" $5}' "/proc/$agent_pid/limits")" = 256:256
    test "$(readlink "/proc/$agent_pid/fd/0")" = /dev/null
    cgroup=$(awk -F: '$1=="0" {print $3}' "/proc/$agent_pid/cgroup")
    [[ "$cgroup" == /user.slice/user-1000.slice/user@1000.service/*/portico-agent.service ]]
    test "$(cat "/sys/fs/cgroup$cgroup/memory.max")" = 1073741824
    test "$(cat "/sys/fs/cgroup$cgroup/pids.max")" = 128
    test "$(stat -c '%u:%g:%a' /run/user/1000/portico-agent)" = 1000:1000:700
    test "$(stat -c '%u:%g:%a' "$socket")" = 1000:1000:600
    test -S "$socket"
    printf 'PORTICO_ARCH_SERVICE_OBSERVED uid=1000 pid=%s cgroup=%s\n' "$agent_pid" "$cgroup"
}
user_systemctl start portico-agent.service
wait_locked
observe_service
if user_command portico agent catalog --socket "$socket" > /tmp/locked-catalog.out 2>/tmp/locked-catalog.err; then
    echo 'Locked service granted catalog access' >&2; exit 1
fi
test ! -s /tmp/locked-catalog.out
if runuser -u porticoother -- portico agent status --socket "$socket" > /tmp/other-status.out 2>/tmp/other-status.err; then
    echo 'Other UID accessed protected service' >&2; exit 1
fi
test ! -s /tmp/other-status.out
echo PORTICO_ARCH_SERVICE_LOCKED_AND_OTHER_UID_DENIED

old_pid=$(user_systemctl show --property=MainPID --value portico-agent.service)
user_systemctl kill --signal=SIGKILL --kill-whom=main portico-agent.service
deadline=$((SECONDS+20))
while (( SECONDS < deadline )); do
    new_pid=$(user_systemctl show --property=MainPID --value portico-agent.service)
    if [[ "$new_pid" != 0 && "$new_pid" != "$old_pid" ]]; then break; fi
    sleep 0.1
done
test "$new_pid" != 0
test "$new_pid" != "$old_pid"
wait_locked
observe_service
test "$(user_systemctl show --property=NRestarts --value portico-agent.service)" = 1
echo PORTICO_ARCH_SERVICE_CRASH_RESTART_LOCKED

user_systemctl stop portico-agent.service
test ! -e /run/user/1000/portico-agent
test ! -e "/proc/$new_pid"
sleep 6
test "$(user_systemctl show --property=ActiveState --value portico-agent.service)" = inactive
test "$(user_systemctl show --property=MainPID --value portico-agent.service)" = 0
test ! -e /run/user/1000/portico-agent
sha256sum --check --strict /portico-fixture-state.sha256
test "$(stat -c '%u:%g:%a' /home/porticofixture/.config/portico/client.json)" = 1000:1000:600
echo PORTICO_ARCH_SERVICE_STOP_CLEAN_AND_STATE_PRESERVED

systemctl stop user@1000.service
systemctl start user@1000.service
test "$(user_systemctl show --property=ActiveState --value portico-agent.service)" = inactive
test ! -e "$socket"
user_systemctl start portico-agent.service
wait_locked
observe_service
user_systemctl stop portico-agent.service
test ! -e /run/user/1000/portico-agent
sha256sum --check --strict /portico-fixture-state.sha256
sha256sum --check --strict /portico-fixture-package.sha256
echo PORTICO_ARCH_SERVICE_USER_MANAGER_RESTART
# Keep a real PAM login open while credential-switched enrollment commands run.
# Those commands do not create login sessions themselves; without this holder,
# logind normally tears down the user manager after the last runuser exits.
session_ready=/run/user/1000/portico-fixture-session-ready
test ! -e "$session_ready"
runuser -u porticofixture -- /usr/bin/bash -c 'umask 077; printf ready > /run/user/1000/portico-fixture-session-ready; exec /usr/bin/sleep 650' &
session_keeper=$!
cleanup_session() {
    kill "$session_keeper" 2>/dev/null || :
    wait "$session_keeper" 2>/dev/null || :
}
trap cleanup_session EXIT
deadline=$((SECONDS+20))
until test -f "$session_ready"; do
    kill -0 "$session_keeper"
    (( SECONDS < deadline ))
    sleep 0.1
done
test "$(stat -c '%u:%g:%a' "$session_ready")" = 1000:1000:600
test -n "$(loginctl show-user 1000 --property=Sessions --value)"
echo PORTICO_ARCH_SERVICE_LOGIN_SESSION_HELD
ip link set dev lo up
ip address add 192.0.2.10/32 dev lo
PORTICO_ISOLATED_VM=1 PORTICO_SYSTEMD_FIXTURE=1 /controller -test.v -test.timeout=600s '-test.run=^TestSystemdGuestAgentEnrollmentAndRevocation$'
kill -0 "$session_keeper"
sha256sum --check --strict /portico-fixture-package.sha256
echo PORTICO_ARCH_SERVICE_ENROLLED_IDENTITY_PASS
cleanup_session
trap - EXIT
# Real application integration runs separately as root in this disposable guest;
# it does not claim the preceding UID1000 installed-service qualification.
PORTICO_ISOLATED_VM=1 PORTICO_SYSTEMD_FIXTURE=1 /controller -test.v -test.timeout=600s '-test.run=^TestArchGuestApplicationHTTPS$'
echo PORTICO_ARCH_APPLICATION_HTTPS_PASS
echo PORTICO_ARCH_SYSTEMD_PASS
