#!/bin/bash
# HB-041 (FR-020): a script tries to persist itself. Every path below is either absent from the
# sandbox or outside the job's stage, so every attempt must fail.
#
# `F2C_T_HOST_ETC` is a directory the test created on the host to stand in for the host's /etc: it
# exists on the host and must not exist inside the sandbox. (The sandbox root is its own tmpfs, so
# a write to a literal /etc path only reaches that ephemeral root and proves nothing.)
try() {
  if eval "$2" >/dev/null 2>&1; then echo "RESULT $1 ALLOWED"; else echo "RESULT $1 BLOCKED"; fi
}
HOST_ETC="${F2C_T_HOST_ETC:-/nonexistent-host-etc}"
try cron "printf '* * * * * /bin/true\n' > /etc/cron.d/f2c-pwned"
try spool "printf '* * * * * /bin/true\n' > /var/spool/cron/f2c-pwned"
try systemd_unit "printf '[Service]\nExecStart=/bin/true\n' > \"$HOST_ETC/systemd/f2c-pwned.service\""
try rc_local "printf '/bin/true\n' >> \"$HOST_ETC/rc.local\""
try startup "printf '[Desktop Entry]\nExec=/bin/true\n' > \"$HOST_ETC/autostart/f2c-pwned.desktop\""
try ld_preload "printf '/tmp/evil.so\n' > \"$HOST_ETC/ld.so.preload\""
try user_unit "mkdir -p \"\$HOME/.config/systemd/user\" && printf '[Service]\nExecStart=/bin/true\n' > \"\$HOME/.config/systemd/user/f2c-pwned.service\""
echo "RESULT home ${HOME:-none}"
exit 0