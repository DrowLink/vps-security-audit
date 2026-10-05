#!/usr/bin/env bash
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/audit.sh
source "$PROJECT_ROOT/lib/audit.sh"

passed=0
failed=0

assert_eq() {
  local expected="$1" actual="$2" name="$3"
  if [[ "$actual" == "$expected" ]]; then
    printf 'ok - %s\n' "$name"
    passed=$((passed + 1))
  else
    printf 'not ok - %s (expected=%q actual=%q)\n' "$name" "$expected" "$actual"
    failed=$((failed + 1))
  fi
}

assert_eq "PASS" "$(classify_sshd_setting permitrootlogin no)" "root SSH login disabled passes"
assert_eq "WARN" "$(classify_sshd_setting permitrootlogin prohibit-password)" "restricted root SSH login warns"
assert_eq "FAIL" "$(classify_sshd_setting permitrootlogin yes)" "root SSH login enabled fails"
assert_eq "PASS" "$(classify_sshd_setting passwordauthentication no)" "SSH password authentication disabled passes"
assert_eq "FAIL" "$(classify_sshd_setting passwordauthentication yes)" "SSH password authentication enabled fails"
assert_eq "HIGH" "$(classify_port 23)" "Telnet is high risk"
assert_eq "EXPECTED" "$(classify_port 22)" "SSH is an expected administrative port"
assert_eq "REVIEW" "$(classify_port 8443)" "unknown listening port needs review"
assert_eq $'22\n23\n8080' "$(extract_listening_ports ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\ntcp LISTEN 0 128 [::]:23 [::]:*')" "ss parser extracts local listening ports"
assert_eq $'22\n3306' "$(extract_listening_ports netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\ntcp 0 0 0.0.0:22 0.0.0.0:* LISTEN 1/sshd\ntcp6 0 0 :::3306 :::* LISTEN 2/mysqld')" "netstat parser uses local-address field"
assert_eq "INVALID" "$(validate_listening_output ss 'warning: partial output')" "unrecognized successful listener output is invalid"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*')" "ss glued Process header variant is valid"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nwarning: partial output')" "listener header cannot hide partial output"
assert_eq "INVALID" "$(validate_listening_output ss 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port warning: partial output')" "ss header suffix cannot hide partial output"
assert_eq "INVALID" "$(validate_listening_output netstat 'Proto Recv-Q Send-Q Local Address Foreign Address State warning: partial output')" "netstat header suffix cannot hide partial output"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:22 192.0.2.1:50000 ESTABLISHED')" "netstat non-listening TCP row is invalid"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp UNCONN 0 0 0.0.0.0:22 0.0.0.0:*')" "ss rejects a TCP row with a UDP state"
assert_eq "PASS" "$(classify_ufw_status 'Status: active')" "active UFW passes"
assert_eq "FAIL" "$(classify_ufw_status 'Status: inactive')" "inactive UFW fails"
assert_eq "WARN" "$(classify_ufw_status 'Error: cached Status: active')" "embedded UFW status text cannot simulate an active firewall"
assert_eq "WARN" "$(classify_ufw_status '')" "unreadable UFW warns"
assert_eq "PASS" "$(classify_package_status apt 0 0)" "successful APT check with no updates passes"
assert_eq "WARN" "$(classify_package_status apt 0 4)" "APT pending updates warn"
assert_eq "ERROR" "$(classify_package_status apt 100 0)" "failed APT check is not a pass"
assert_eq "ERROR" "$(classify_apt_result 0 'unexpected successful output')" "unrecognized successful APT output is not a pass"
assert_eq "ERROR" "$(classify_apt_result 0 $'Listing...\nunexpected successful output')" "malformed APT entry after listing marker is not a pass"
assert_eq "PASS" "$(classify_package_status rpm 0 0)" "successful DNF/YUM check with no updates passes"
assert_eq "WARN" "$(classify_package_status rpm 100 0)" "DNF/YUM status 100 indicates updates"
assert_eq "ERROR" "$(classify_package_status rpm 1 0)" "failed DNF/YUM check reports error"
apt_fixture=$'\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\nListing...\nbase-files/stable 12.4 amd64 [upgradable from: 12.3]\ncurl/stable-security 8.0 amd64 [upgradable from: 7.9]'
assert_eq "2" "$(count_apt_upgrades "$apt_fixture")" "APT parser counts package entries only"
assert_eq "WARN" "$(classify_apt_result 0 "$apt_fixture")" "validated APT output with upgrades warns"
assert_eq "0" "$(count_apt_upgrades $'WARNING: apt warning\n\nListing...')" "APT parser ignores warnings headers and blanks"
assert_eq "ACTIVE" "$(classify_nft_ruleset $'table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}')" "nftables hooked base chain is active"
assert_eq "INERT" "$(classify_nft_ruleset $'table inet filter {\n}')" "empty nftables table is inert"
assert_eq "PASS" "$(classify_fail2ban_status $'Status\n`- Jail list: sshd')" "Fail2ban sshd jail passes"
assert_eq "WARN" "$(classify_fail2ban_status $'Status\n`- Jail list:')" "Fail2ban with zero jails warns"
assert_eq "WARN" "$(classify_fail2ban_status $'Status\n`- Jail list: nginx-http-auth')" "Fail2ban without sshd jail warns"
assert_eq "ERROR" "$(classify_fail2ban_status '')" "unreadable Fail2ban status errors"
assert_eq "ERROR" "$(classify_fail2ban_status 'Error: Jail list: sshd')" "malformed Fail2ban output cannot simulate an sshd jail"
assert_eq "ERROR" "$(classify_fail2ban_status $'Status\n`- Jail list: sshd unexpected-error')" "malformed Fail2ban jail separators cannot produce a pass"
awk() { printf '`- Jail list: sshd\n'; return 1; }
failed_awk_result="$(classify_fail2ban_status $'Status\n`- Jail list: sshd')"
unset -f awk
assert_eq "ERROR" "$failed_awk_result" "failed Fail2ban parser output cannot produce a pass"
assert_eq "YES" "$(probe_succeeded 0 'partial output')" "successful probe output may be parsed"
assert_eq "NO" "$(probe_succeeded 1 'Status: active')" "failed probe output is never trusted"
assert_eq "INERT" "$(classify_nft_ruleset $'table inet filter {\n # comment: hook input\n chain x { comment "hook input"; }\n}')" "nftables comments cannot simulate a base chain"
assert_eq "PASS" "$(classify_account_read 0 1 root)" "single root UID-zero account passes"
assert_eq "FAIL" "$(classify_account_read 0 2 root)" "multiple UID-zero accounts fail"
assert_eq "FAIL" "$(classify_account_read 0 1 backdoor)" "non-root UID-zero identity fails"
assert_eq "WARN" "$(classify_account_read 1 0 '')" "unreadable account database warns"
assert_eq "INFO" "$(firewall_finding_level PASS)" "active firewall frontend is informational, not proof of filtering"
assert_eq "INFO" "$(firewall_finding_level FAIL)" "inactive optional firewall frontend is informational"
assert_eq "WARN" "$(firewall_finding_level WARN)" "unknown firewall state warns"
assert_eq "ACTIVE" "$(classify_firewalld_state 0 running)" "running firewalld is active"
assert_eq "INACTIVE" "$(classify_firewalld_state 252 'not running')" "documented nonzero firewalld inactive state is recognized"
assert_eq "ERROR" "$(classify_firewalld_state 1 'Error: daemon not running due to D-Bus failure')" "unexpected not-running error is not treated as normal inactivity"
assert_eq "ERROR" "$(classify_firewalld_state 1 'connection failed')" "genuine firewalld probe failure errors"
assert_eq "OK" "$(classify_capture_status 0)" "successful informational capture is complete"
assert_eq "WARN" "$(classify_capture_status 1)" "failed informational capture warns"
assert_eq "OK" "$(classify_availability 1)" "available optional audit command is complete"
assert_eq "WARN" "$(classify_availability 0)" "missing optional audit command warns"
assert_eq "INFO" "$(ssh_finding_level passwordauthentication no)" "secure default SSH setting remains informational"
assert_eq "FAIL" "$(ssh_finding_level passwordauthentication yes)" "unsafe default SSH setting fails"
set +e
append_report /dev/full '%s\n' "data" 2>/dev/null
full_status=$?
set -e
assert_eq "1" "$full_status" "report append detects write failure"
unit_tmp="$(mktemp -d)"
printf 'report\n' > "$unit_tmp/source"
mkdir "$unit_tmp/destination-dir"
ln -s "$unit_tmp/destination-dir" "$unit_tmp/destination-link"
set +e
publish_exact "$unit_tmp/source" "$unit_tmp/destination-dir" 2>/dev/null
publish_dir_status=$?
publish_exact "$unit_tmp/source" "$unit_tmp/destination-link" 2>/dev/null
publish_link_status=$?
set -e
assert_eq "1" "$publish_dir_status" "exact publication refuses a directory destination"
assert_eq "1" "$publish_link_status" "exact publication refuses a symlink-to-directory destination"
assert_eq "0" "$(publish_exact "$unit_tmp/source" "$unit_tmp/final"; printf '%s' "$?")" "exact publication creates the requested file"
mkdir "$unit_tmp/fakebin"
cat > "$unit_tmp/fakebin/dirname" <<EOF
#!/usr/bin/env bash
printf 'hijacked\n' > "$unit_tmp/path-hijacked"
exec /usr/bin/dirname "\$@"
EOF
chmod +x "$unit_tmp/fakebin/dirname"
cat > "$unit_tmp/fakebin/bash" <<EOF
#!/bin/sh
printf 'hijacked\n' > "$unit_tmp/bash-hijacked"
exec /bin/bash "\$@"
EOF
chmod +x "$unit_tmp/fakebin/bash"
env PATH="$unit_tmp/fakebin:$PATH" "$PROJECT_ROOT/vps-audit.sh" --help >/dev/null
if [[ -e "$unit_tmp/path-hijacked" ]]; then
  assert_eq "safe" "hijacked" "script establishes a trusted PATH before external commands"
else
  assert_eq "safe" "safe" "script establishes a trusted PATH before external commands"
fi
if [[ -e "$unit_tmp/bash-hijacked" ]]; then
  assert_eq "safe" "hijacked" "script uses an absolute trusted Bash interpreter"
else
  assert_eq "safe" "safe" "script uses an absolute trusted Bash interpreter"
fi
printf 'printf "hijacked\\n" > %q\n' "$unit_tmp/bash-env-hijacked" > "$unit_tmp/bash-env"
env BASH_ENV="$unit_tmp/bash-env" "$PROJECT_ROOT/vps-audit.sh" --help >/dev/null
if [[ -e "$unit_tmp/bash-env-hijacked" ]]; then
  assert_eq "safe" "hijacked" "privileged mode ignores BASH_ENV"
else
  assert_eq "safe" "safe" "privileged mode ignores BASH_ENV"
fi
(
  FUNCTION_MARKER="$unit_tmp/function-hijacked"
  export FUNCTION_MARKER
  dirname() { printf 'hijacked\n' > "$FUNCTION_MARKER"; /usr/bin/dirname "$@"; }
  export -f dirname
  "$PROJECT_ROOT/vps-audit.sh" --help >/dev/null
)
if [[ -e "$unit_tmp/function-hijacked" ]]; then
  assert_eq "safe" "hijacked" "privileged mode ignores imported functions"
else
  assert_eq "safe" "safe" "privileged mode ignores imported functions"
fi
set +e
(
  cd "$PROJECT_ROOT/.." || exit 1
  CDPATH="$PROJECT_ROOT/.." vps-security-audit/vps-audit.sh --help >/dev/null 2>"$unit_tmp/cdpath-error"
)
cdpath_status=$?
set -e
assert_eq "0" "$cdpath_status" "relative invocation ignores inherited CDPATH"
assert_eq "" "$(cat "$unit_tmp/cdpath-error")" "relative invocation loads its required library cleanly"
set +e
env TMPDIR=/definitely/not/a/real/directory "$PROJECT_ROOT/vps-audit.sh" --no-color >/dev/null 2>&1
tmpdir_status=$?
set -e
assert_eq "0" "$tmpdir_status" "internal report ignores hostile TMPDIR"
cp "$PROJECT_ROOT/vps-audit.sh" "$unit_tmp/standalone-audit.sh"
chmod +x "$unit_tmp/standalone-audit.sh"
set +e
"$unit_tmp/standalone-audit.sh" --help >/dev/null 2>&1
missing_lib_status=$?
set -e
assert_eq "1" "$missing_lib_status" "missing required audit library fails closed"
rm -rf "$unit_tmp"

help_output="$($PROJECT_ROOT/vps-audit.sh --help 2>&1)"
assert_eq "0" "$?" "help exits successfully"
if [[ "$help_output" == *"Usage:"* ]] && [[ "$help_output" == *"--output"* ]]; then
  assert_eq "yes" "yes" "help documents usage and report output"
else
  assert_eq "yes" "no" "help documents usage and report output"
fi

set +e
"$PROJECT_ROOT/vps-audit.sh" --unknown >/dev/null 2>&1
invalid_status=$?
set -e
assert_eq "2" "$invalid_status" "unknown option exits with usage error"

tmp_dir="$(mktemp -d)"
tmp_report="$tmp_dir/report.txt"
trap 'rm -rf "$tmp_dir"' EXIT
report_output="$($PROJECT_ROOT/vps-audit.sh --no-color --output "$tmp_report")"
for section in "System information" "SSH configuration" "Listening ports" "Firewall" "Brute-force protection" "Updates" "Users and access" "Scheduled tasks" "Summary"; do
  if [[ "$report_output" == *"$section"* ]]; then
    assert_eq "present" "present" "report includes $section"
  else
    assert_eq "present" "missing" "report includes $section"
  fi
done
assert_eq "$report_output" "$(cat "$tmp_report")" "saved report matches stdout"
assert_eq "600" "$(stat -c '%a' "$tmp_report")" "saved report is private"

set +e
"$PROJECT_ROOT/vps-audit.sh" --no-color --output "$tmp_report" >/dev/null 2>&1
existing_status=$?
set -e
assert_eq "2" "$existing_status" "existing report is never overwritten"

symlink_target="$tmp_dir/target.txt"
symlink_path="$tmp_dir/link.txt"
printf 'keep\n' > "$symlink_target"
ln -s "$symlink_target" "$symlink_path"
set +e
"$PROJECT_ROOT/vps-audit.sh" --no-color --output "$symlink_path" >/dev/null 2>&1
symlink_status=$?
set -e
assert_eq "2" "$symlink_status" "symbolic-link report destination is refused"
assert_eq "keep" "$(cat "$symlink_target")" "symbolic-link target is unchanged"

fifo_path="$tmp_dir/report.fifo"
mkfifo "$fifo_path"
set +e
timeout 5 "$PROJECT_ROOT/vps-audit.sh" --no-color --output "$fifo_path" >/dev/null 2>&1
fifo_status=$?
set -e
assert_eq "2" "$fifo_status" "FIFO report destination is refused without blocking"

set +e
timeout 5 "$PROJECT_ROOT/vps-audit.sh" --no-color --output /dev/null >/dev/null 2>&1
device_status=$?
set -e
assert_eq "2" "$device_status" "device report destination is refused"

set +e
"$PROJECT_ROOT/vps-audit.sh" --no-color --output "/no-such-parent-$RANDOM/report.txt" >/dev/null 2>&1
write_status=$?
set -e
assert_eq "1" "$write_status" "unwritable report destination fails"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 ))
