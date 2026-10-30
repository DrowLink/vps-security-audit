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
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*')" "ss accepts a canonical interface-scoped IPv4 local endpoint"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%aud@test:53 0.0.0.0:*')" "ss accepts the exact canonical at-sign IPv4 interface scope"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%enp.100-t_1@vrf:53 0.0.0.0:*')" "ss accepts all permitted IPv4 interface-scope characters at length 15"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%a+b:53 0.0.0.0:*')" "ss accepts plus in an IPv4 interface scope"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%a%2:53 0.0.0.0:*')" "ss uses the first percent separator and accepts a later percent in an IPv4 interface scope"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%+=#@%]\\:53 0.0.0.0:*')" "ss accepts Linux interface-name punctuation in an IPv4 scope"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%scope12345678901:53 0.0.0.0:*')" "ss rejects an IPv4 interface scope longer than 15 characters"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%:53 0.0.0.0:*')" "ss rejects an empty IPv4 interface scope"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%.:53 0.0.0.0:*')" "ss rejects dot as an IPv4 interface scope"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%..:53 0.0.0.0:*')" "ss rejects dot-dot as an IPv4 interface scope"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 127.0.0.53%lo/0:53 0.0.0.0:*')" "ss rejects an invalid IPv4 interface scope"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nwarning: partial output')" "listener header cannot hide partial output"
assert_eq "INVALID" "$(validate_listening_output ss 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port warning: partial output')" "ss header suffix cannot hide partial output"
assert_eq "INVALID" "$(validate_listening_output netstat 'Proto Recv-Q Send-Q Local Address Foreign Address State warning: partial output')" "netstat header suffix cannot hide partial output"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:22 192.0.2.1:50000 ESTABLISHED')" "netstat non-listening TCP row is invalid"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:22 garbage:123 LISTEN')" "netstat rejects a malformed foreign address with a valid port"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 garbage:22 0.0.0.0:* LISTEN')" "netstat rejects a malformed local address with a valid port"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 :::22 :::* LISTEN')" "netstat rejects an IPv6 local address for tcp"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp6 0 0 0.0.0.0:22 0.0.0.0:* LISTEN')" "netstat rejects an IPv4 local address for tcp6"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:22 :::* LISTEN')" "netstat rejects an IPv6 foreign wildcard for tcp"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp6 0 0 :::22 0.0.0.0:* LISTEN')" "netstat rejects an IPv4 foreign wildcard for tcp6"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp 0 0 0.0.0.0:53 :::*')" "netstat rejects an IPv6 foreign wildcard for udp"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 :::53 0.0.0.0:*')" "netstat rejects an IPv4 foreign wildcard for udp6"
assert_eq "VALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:22 *:* LISTEN\ntcp6 0 0 :::443 *:* LISTEN\nudp 0 0 0.0.0.0:53 *:*\nudp6 0 0 :::5353 *:*')" "netstat accepts the family-neutral foreign wildcard"
assert_eq "VALID" "$(validate_listening_output netstat $'Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1/sshd\ntcp6 0 0 :::443 :::* LISTEN 2/nginx\nudp 0 0 127.0.0.1:53 0.0.0.0:* 3/dns\nudp6 0 0 :::5353 :::* 4/mdns')" "netstat accepts canonical IPv4, IPv6, TCP, and UDP listener output"
assert_eq "VALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 fe80::1%scope1234567890:53 :::*')" "netstat accepts an unbracketed IPv6 scope at length 15"
assert_eq "VALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 fe80::1%a+b:53 :::*')" "netstat accepts plus in an unbracketed IPv6 scope"
assert_eq "VALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 fe80::1%a%2:53 :::*')" "netstat uses the first percent separator and accepts a later percent in an IPv6 scope"
assert_eq "VALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 fe80::1%+=#@%]\\:53 :::*')" "netstat accepts Linux interface-name punctuation in an IPv6 scope"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 fe80::1%scope12345678901:53 :::*')" "netstat rejects an unbracketed IPv6 scope longer than 15 characters"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 fe80::1%.:53 :::*')" "netstat rejects dot as an unbracketed IPv6 scope"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp6 0 0 fe80::1%..:53 :::*')" "netstat rejects dot-dot as an unbracketed IPv6 scope"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp6 0 0 2001:db8:::1:22 :::* LISTEN')" "netstat rejects a malformed local IPv6 endpoint"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:70000 0.0.0.0:* LISTEN')" "netstat rejects an out-of-range local port"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:http 0.0.0.0:* LISTEN')" "netstat rejects a nonnumeric local port"
assert_eq "INVALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:022 0.0.0.0:* LISTEN')" "netstat rejects a noncanonical leading-zero local port"
assert_eq "VALID" "$(validate_listening_output netstat $'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:0 0.0.0.0:* LISTEN\ntcp 0 0 0.0.0.0:65535 0.0.0.0:* LISTEN')" "netstat accepts canonical boundary ports"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp UNCONN 0 0 0.0.0.0:22 0.0.0.0:*')" "ss rejects a TCP row with a UDP state"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 TRUNCATED')" "ss rejects a row with a malformed peer endpoint"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 garbage:123')" "ss rejects a malformed peer address with a valid port"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 garbage:22 0.0.0.0:*')" "ss rejects a malformed local address with a valid port"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 999.999.999.999:22 0.0.0.0:*')" "ss rejects an out-of-range numeric IPv4 local address"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%audit@test:45678 [::]:*')" "ss accepts the exact canonical scoped IPv6 local endpoint form"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%audit_1.t-2@vrf:45678 [::]:*')" "ss accepts permitted scoped IPv6 interface characters at length 15"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%a+b:45678 [::]:*')" "ss accepts plus in a scoped IPv6 interface"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%a%2:45678 [::]:*')" "ss uses the first percent separator and accepts a later percent in a scoped IPv6 interface"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%+=#@%]\\:45678 [::]:*')" "ss accepts Linux interface-name punctuation in a scoped IPv6 interface"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%scope12345678901:45678 [::]:*')" "ss rejects a scoped IPv6 interface longer than 15 characters"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%:45678 [::]:*')" "ss rejects an empty scoped IPv6 interface"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%.:45678 [::]:*')" "ss rejects dot as a scoped IPv6 interface"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%..:45678 [::]:*')" "ss rejects dot-dot as a scoped IPv6 interface"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%audit/test:45678 [::]:*')" "ss rejects a slash in a scoped IPv6 interface"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%audit:test:45678 [::]:*')" "ss rejects a colon in a scoped IPv6 interface"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%audit%test:45678 [::]:*')" "ss accepts a percent in a scoped IPv6 interface"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%audit test:45678 [::]:*')" "ss rejects whitespace in a scoped IPv6 interface"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234]%audit@test:45678junk [::]:*')" "ss rejects trailing garbage after a scoped IPv6 port"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [fe80::1234%audit]:45678 [::]:*')" "ss rejects noncanonical inside-bracket IPv6 scopes"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [2001:db8:::1]:22 [::]:*')" "ss rejects a malformed local IPv6 endpoint"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:70000 0.0.0.0:*')" "ss rejects an out-of-range local port"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:http 0.0.0.0:*')" "ss rejects a nonnumeric local port"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:022 0.0.0.0:*')" "ss rejects a noncanonical leading-zero local port"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:0 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:65535 0.0.0.0:*')" "ss accepts canonical boundary ports"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 999.999.999.999:123')" "ss rejects an out-of-range numeric IPv4 peer"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [::]:22 [:::]:*')" "ss rejects an invalid numeric IPv6 wildcard peer"
assert_eq "INVALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 [::]:22 [deadbeef:]:1')" "ss rejects an invalid numeric IPv6 peer"
assert_eq "VALID" "$(validate_listening_output ss $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\nudp UNCONN 0 0 0.0.0.0:68 *:*')" "ss accepts canonical listener wildcard peers"
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
assert_eq "ERROR" "$(classify_rpm_result 0 'warning: partial output')" "unexpected DNF/YUM output cannot produce a pass"
apt_fixture=$'\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\nListing...\nbase-files/stable 12.4 amd64 [upgradable from: 12.3]\ncurl/stable-security 8.0 amd64 [upgradable from: 7.9]'
assert_eq "2" "$(count_apt_upgrades "$apt_fixture")" "APT parser counts package entries only"
assert_eq "WARN" "$(classify_apt_result 0 "$apt_fixture")" "validated APT output with upgrades warns"
assert_eq "0" "$(count_apt_upgrades $'WARNING: apt warning\n\nListing...')" "APT parser ignores warnings headers and blanks"
assert_eq "ACTIVE" "$(classify_nft_ruleset $'table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}')" "nftables hooked base chain is active"
assert_eq "INERT" "$(classify_nft_ruleset $'table inet filter {\n}')" "empty nftables table is inert"
assert_eq "INERT" "$(classify_nft_ruleset 'type filter hook input priority filter; policy drop;')" "nftables hook declaration outside a chain is inert"
assert_eq "PASS" "$(classify_fail2ban_status $'Status\n`- Jail list: sshd')" "Fail2ban sshd jail passes"
assert_eq "WARN" "$(classify_fail2ban_status $'Status\n`- Jail list:')" "Fail2ban with zero jails warns"
assert_eq "WARN" "$(classify_fail2ban_status $'Status\n`- Jail list: nginx-http-auth')" "Fail2ban without sshd jail warns"
assert_eq "ERROR" "$(classify_fail2ban_status '')" "unreadable Fail2ban status errors"
assert_eq "ERROR" "$(classify_fail2ban_status 'Error: Jail list: sshd')" "malformed Fail2ban output cannot simulate an sshd jail"
assert_eq "ERROR" "$(classify_fail2ban_status '`- Jail list: sshd')" "Fail2ban jail list without a status header cannot produce a pass"
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
assert_eq "FATAL" "$(classify_bounded_capture_status 2)" "bounded capture filter failure is fatal"
bounded_capture_fixture() {
  printf '%s\n' one two three
}
bounded_capture_failed_fixture() {
  printf '%s\n' plausible
  return 23
}
bounded_capture_no_newline_fixture() {
  printf '%s' final
}
bounded_capture="$(mktemp)"
set +e
capture_bounded_lines 2 "$bounded_capture" bounded_capture_fixture
bounded_capture_status=$?
set -e
assert_eq "3" "$bounded_capture_status" "bounded command capture reports truncation"
assert_eq $'one\ntwo' "$(< "$bounded_capture")" "bounded command capture enforces its line limit"
set +e
capture_bounded_lines 2 "$bounded_capture" bounded_capture_failed_fixture
bounded_capture_status=$?
set -e
assert_eq "1" "$bounded_capture_status" "failed bounded command capture cannot appear complete"
assert_eq "23" "$CAPTURE_PRODUCER_STATUS" "bounded command capture preserves producer failure status"
set +e
capture_bounded_lines 2 /dev/full bounded_capture_fixture 2>/dev/null
bounded_capture_status=$?
set -e
assert_eq "2" "$bounded_capture_status" "bounded command capture reports target write failure as fatal"
set +e
capture_bounded_lines 2 "$bounded_capture" bounded_capture_no_newline_fixture
bounded_capture_status=$?
set -e
printf '%s' final > "$bounded_capture.expected"
assert_eq "0" "$bounded_capture_status" "unterminated bounded command capture succeeds"
assert_eq "0" "$(cmp -s "$bounded_capture.expected" "$bounded_capture"; printf '%s' "$?")" "bounded command capture preserves an unterminated final line"
rm -f -- "$bounded_capture" "$bounded_capture.expected"
assert_eq "OK" "$(classify_availability 1)" "available optional audit command is complete"
assert_eq "WARN" "$(classify_availability 0)" "missing optional audit command warns"
assert_eq "INFO" "$(ssh_finding_level passwordauthentication no)" "secure default SSH setting remains informational"
assert_eq "FAIL" "$(ssh_finding_level passwordauthentication yes)" "unsafe default SSH setting fails"
assert_eq "MISSING" "$(validate_sshd_output $'permitrootlogin no\npasswordauthentication no\npubkeyauthentication yes')" "sshd output missing an audited key warns"
assert_eq "DUPLICATE" "$(validate_sshd_output $'permitrootlogin no\npermitrootlogin yes\npasswordauthentication no\npubkeyauthentication yes\nmaxauthtries 3')" "duplicate audited sshd keys warn instead of using the first value"
assert_eq "MALFORMED" "$(validate_sshd_output $'permitrootlogin\npasswordauthentication no\npubkeyauthentication yes\nmaxauthtries 3')" "audited sshd keys without one value warn"
assert_eq "VALID" "$(validate_sshd_output $'permitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\nmaxauthtries 3')" "complete unique audited sshd settings are valid"
set +e
append_report /dev/full '%s\n' "data" 2>/dev/null
full_status=$?
set -e
assert_eq "1" "$full_status" "report append detects write failure"
unit_tmp="$(mktemp -d)"
printf 'prefix\n' > "$unit_tmp/report-target"
printf 'one\n\n' > "$unit_tmp/capture-source"
printf 'prefix\none\n\n' > "$unit_tmp/report-expected"
set +e
append_capture_file "$unit_tmp/report-target" "$unit_tmp/capture-source"
append_capture_status=$?
set -e
assert_eq "0" "$append_capture_status" "bounded capture append succeeds"
assert_eq "0" "$(cmp -s "$unit_tmp/report-expected" "$unit_tmp/report-target"; printf '%s' "$?")" "bounded capture append preserves exact line bytes"
printf 'evidence\n' > "$unit_tmp/consume-source"
printf 'evidence\n' > "$unit_tmp/consume-expected"
set +e
consume_capture_file "$unit_tmp/consume-target" "$unit_tmp/consume-source"
consume_capture_status=$?
set -e
assert_eq "0" "$consume_capture_status" "successful capture consumption succeeds"
assert_eq "0" "$(cmp -s "$unit_tmp/consume-expected" "$unit_tmp/consume-target"; printf '%s' "$?")" "capture consumption appends exact bytes"
assert_eq "absent" "$([[ -e "$unit_tmp/consume-source" ]] && printf present || printf absent)" "capture consumption removes consumed evidence"
printf 'retain\n' > "$unit_tmp/retain-source"
set +e
consume_capture_file /dev/full "$unit_tmp/retain-source" 2>/dev/null
consume_capture_status=$?
set -e
assert_eq "1" "$consume_capture_status" "failed capture append fails consumption"
assert_eq "present" "$([[ -e "$unit_tmp/retain-source" ]] && printf present || printf absent)" "failed capture append retains evidence for cleanup"
printf '%s' final > "$unit_tmp/unterminated-source"
printf 'final\n' > "$unit_tmp/unterminated-expected"
set +e
consume_capture_file "$unit_tmp/unterminated-target" "$unit_tmp/unterminated-source"
consume_capture_status=$?
set -e
assert_eq "0" "$consume_capture_status" "unterminated capture consumption succeeds"
assert_eq "0" "$(cmp -s "$unit_tmp/unterminated-expected" "$unit_tmp/unterminated-target"; printf '%s' "$?")" "capture consumption adds a report-record boundary after unterminated evidence"
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

active_success_fixture() {
  printf '%s\n' \
    'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process' \
    'tcp ESTAB 0 0 192.0.2.10:22 198.51.100.20:50000 users:(("sshd",pid=12,fd=3))'
}
active_failed_fixture() {
  active_success_fixture
  return 23
}
active_empty_fixture() {
  return 0
}
active_long_fixture() {
  printf '%s\n' 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
  printf 'tcp ESTAB 0 0 192.0.2.10:22 198.51.100.%s:50000\n' 20 21 22
}
active_hostile_fixture() {
  printf '%s\n' \
    'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process' \
    $'tcp ESTAB 0 0 192.0.2.10:22 198.51.100.20:50000 users:(("bad\033[2J\033[H\n[FAIL] forged finding",pid=12,fd=3))'
}
active_glued_header_fixture() {
  printf '%s\n' \
    'Netid State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess' \
    'tcp ESTAB 0 0 192.0.2.10:22 198.51.100.20:50000'
}
active_endpoint_fixture() {
  printf '%s\n' \
    'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port' \
    "tcp ESTAB 0 0 $1 $2"
}
active_canonical_endpoints_fixture() {
  printf '%s\n' \
    'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port' \
    'tcp ESTAB 0 0 192.0.2.10:22 198.51.100.20:50000' \
    'tcp ESTAB 0 0 [2001:db8::1]:443 [fe80::2%eth0]:50000' \
    'udp UNCONN 0 0 0.0.0.0:* *:*' \
    'udp UNCONN 0 0 [::]:* [::]:*'
}
active_capture="$unit_tmp/active-connections"
set +e
capture_active_connections 60 "$active_capture" active_success_fixture
active_status=$?
set -e
assert_eq "0" "$active_status" "successful active-connection capture is complete"
assert_eq $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp ESTAB 0 0 192.0.2.10:22 198.51.100.20:50000' "$(cat "$active_capture")" "active-connection inventory retains numeric connection evidence"
set +e
capture_active_connections 60 "$active_capture" active_failed_fixture
active_status=$?
set -e
assert_eq "1" "$active_status" "failed active-connection probe with plausible partial stdout warns"
assert_eq "23" "$ACTIVE_CONNECTION_PRODUCER_STATUS" "active-connection capture preserves the producer status"
set +e
capture_active_connections 60 "$active_capture" active_empty_fixture
active_status=$?
set -e
assert_eq "2" "$active_status" "empty active-connection output warns"
set +e
capture_active_connections 3 "$active_capture" active_long_fixture
active_status=$?
set -e
assert_eq "3" "$active_status" "bounded active-connection capture reports truncation"
assert_eq "3" "$(wc -l < "$active_capture")" "active-connection capture enforces its line bound"
set +e
capture_active_connections 60 "$active_capture" active_hostile_fixture
active_status=$?
set -e
assert_eq "4" "$active_status" "malformed injected active-connection output warns"
assert_eq $'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp ESTAB 0 0 192.0.2.10:22 198.51.100.20:50000' "$(cat "$active_capture")" "hostile process metadata cannot reach the inventory"
set +e
capture_active_connections 60 "$active_capture" active_glued_header_fixture
active_glued_status=$?
capture_active_connections 60 "$active_capture" active_endpoint_fixture '999.999.999.999:22' '198.51.100.20:50000'
active_bad_ipv4_status=$?
capture_active_connections 60 "$active_capture" active_endpoint_fixture '192.0.2.10:22' '198.51.100.20:70000'
active_bad_port_status=$?
capture_active_connections 60 "$active_capture" active_endpoint_fixture '....:99999' '198.51.100.20:50000'
active_bad_dotted_status=$?
capture_active_connections 60 "$active_capture" active_endpoint_fixture '192.*.2.1:22' '198.51.100.20:50000'
active_bad_wildcard_status=$?
capture_active_connections 60 "$active_capture" active_endpoint_fixture '[2001:db8:::1]:22' '[2001:db8::2]:50000'
active_bad_ipv6_status=$?
capture_active_connections 60 "$active_capture" active_canonical_endpoints_fixture
active_canonical_status=$?
set -e
assert_eq "0" "$active_glued_status" "active-connection capture accepts the glued Process header variant"
assert_eq "4" "$active_bad_ipv4_status" "active-connection capture rejects an out-of-range IPv4 endpoint"
assert_eq "4" "$active_bad_port_status" "active-connection capture rejects a port above 65535"
assert_eq "4" "$active_bad_dotted_status" "active-connection capture rejects a malformed dotted endpoint"
assert_eq "4" "$active_bad_wildcard_status" "active-connection capture rejects malformed wildcard placement"
assert_eq "4" "$active_bad_ipv6_status" "active-connection capture rejects invalid numeric IPv6"
assert_eq "0" "$active_canonical_status" "active-connection capture accepts canonical IPv4, scoped IPv6, and wildcard endpoints"

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
if [[ "$report_output" == *"Active network connections (maximum 60):"* ]]; then
  assert_eq "present" "present" "report includes bounded active-connection inventory"
else
  assert_eq "present" "missing" "report includes bounded active-connection inventory"
fi
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
