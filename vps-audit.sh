#!/bin/bash -p
set -uo pipefail
export LC_ALL=C
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
unset BASH_ENV ENV CDPATH TMPDIR

if ! SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"; then
  printf 'Error: cannot resolve the audit script directory.\n' >&2
  exit 1
fi
# shellcheck source=lib/audit.sh
if ! source "$SCRIPT_DIR/lib/audit.sh"; then
  printf 'Error: required audit library could not be loaded.\n' >&2
  exit 1
fi

usage() {
  cat <<'USAGE'
Usage: sudo ./vps-audit.sh [--output FILE] [--no-color] [--help]

Read-only security audit for Linux VPS hosts. It never changes system state.
Root is optional, but enables complete SSH, log, and firewall checks.

Options:
  -o, --output FILE  Save the report to FILE as well as stdout
      --no-color     Disable ANSI colors
  -h, --help         Show this help
USAGE
}

output_file=""
while (( $# > 0 )); do
  case "$1" in
    -o|--output)
      if (( $# < 2 )); then printf 'Error: %s requires a file path.\n' "$1" >&2; usage >&2; exit 2; fi
      output_file="$2"
      shift 2
      ;;
    --no-color) shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Error: unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

umask 077
output_fd=""
output_stage=""
output_stage_dir=""
report=""
internal_report_dir=""
cleanup() {
  [[ -n "${report:-}" ]] && rm -f -- "$report" 2>/dev/null || true
  [[ -n "${internal_report_dir:-}" ]] && rmdir -- "$internal_report_dir" 2>/dev/null || true
  [[ -n "${output_stage:-}" ]] && rm -f -- "$output_stage" 2>/dev/null || true
  [[ -n "${output_stage_dir:-}" ]] && rmdir -- "$output_stage_dir" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -n "$output_file" ]]; then
  output_dir="$(dirname -- "$output_file")"
  output_name="$(basename -- "$output_file")"
  if [[ -e "$output_file" || -L "$output_file" ]]; then
    printf 'Error: refusing to overwrite existing output path: %s\n' "$output_file" >&2
    exit 2
  fi
  output_stage_dir="$(mktemp -d --tmpdir="$output_dir" ".${output_name}.stage.XXXXXX" 2>/dev/null)" || {
    printf 'Error: could not create a secure staging directory beside %s\n' "$output_file" >&2
    exit 1
  }
  output_stage="$output_stage_dir/report"
  if ! exec {output_fd}> "$output_stage"; then
    rmdir -- "$output_stage_dir" 2>/dev/null || true
    printf 'Error: could not create a secure staged report for %s\n' "$output_file" >&2
    exit 1
  fi
fi

internal_report_dir="$(mktemp -d --tmpdir=/tmp vps-security-audit.XXXXXX 2>/dev/null)" || {
  printf 'Error: cannot create secure internal report directory.\n' >&2
  exit 1
}
report="$internal_report_dir/report"
if ! : > "$report"; then
  printf 'Error: cannot create secure internal report.\n' >&2
  exit 1
fi

report_write() {
  if ! append_report "$report" "$@"; then
    printf 'Error: audit report write failed; refusing partial output.\n' >&2
    exit 1
  fi
}

section() {
  report_write '\n## %s\n' "$1"
}

finding() {
  report_write '[%s] %s\n' "$1" "$2"
}

capture_limited() {
  local lines="$1" captured capture_status
  shift
  captured="$("$@" 2>/dev/null)"
  capture_status=$?
  report_write '%s\n' "$(head -n "$lines" <<< "$captured")"
  [[ "$(classify_capture_status "$capture_status")" == "OK" ]]
}

report_write 'VPS Security Audit\n'
report_write 'Generated: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
report_write 'Host: %s\n' "$(hostname 2>/dev/null || printf 'unknown')"
report_write 'Mode: read-only\n'

section "System information"
if [[ -r /etc/os-release ]]; then
  os_name="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
else
  os_name="unknown"
fi
report_write 'Operating system: %s\n' "$os_name"
report_write 'Kernel: %s\n' "$(uname -srmo 2>/dev/null || printf 'unknown')"
report_write 'Uptime: %s\n' "$(uptime -p 2>/dev/null || printf 'unknown')"
if (( EUID == 0 )); then
  finding PASS "Running with root privileges; privileged checks are available."
else
  finding INFO "Running without root; some checks may be incomplete."
fi

section "SSH configuration"
sshd_config=""
sshd_probe_status=127
if command -v sshd >/dev/null 2>&1; then
  sshd_config="$(sshd -T 2>/dev/null)"
  sshd_probe_status=$?
fi
if [[ "$(probe_succeeded "$sshd_probe_status" "$sshd_config")" == "YES" ]]; then
  for key in permitrootlogin passwordauthentication pubkeyauthentication maxauthtries; do
    value="$(awk -v wanted="$key" '$1 == wanted {print $2; exit}' <<< "$sshd_config")"
    [[ -n "$value" ]] || value="unknown"
    report_write '%s: %s\n' "$key" "$value"
    case "$key" in
      permitrootlogin|passwordauthentication)
        result="$(ssh_finding_level "$key" "$value")"
        if [[ "$result" == "INFO" ]]; then
          finding INFO "$key defaults to $value; conditional Match contexts were not enumerated."
        else
          finding "$result" "$key defaults to $value."
        fi
        ;;
    esac
  done
else
  finding WARN "Could not read effective sshd configuration (sshd missing, inaccessible, or inactive)."
fi

section "Listening ports"
ports_output=""
ports_format=""
ports_status=127
if command -v ss >/dev/null 2>&1; then
  ports_output="$(ss -lntup 2>/dev/null)"
  ports_status=$?
  if (( ports_status != 0 )); then
    ports_output="$(ss -lntu 2>/dev/null)"
    ports_status=$?
  fi
  (( ports_status == 0 )) && ports_format="ss"
elif command -v netstat >/dev/null 2>&1; then
  ports_output="$(netstat -lntup 2>/dev/null)"
  ports_status=$?
  (( ports_status == 0 )) && ports_format="netstat"
fi
if [[ "$(probe_succeeded "$ports_status" "$ports_output")" == "YES" ]]; then
  report_write '%s\n' "$(head -n 60 <<< "$ports_output")"
  mapfile -t ports < <(extract_listening_ports "$ports_format" "$ports_output")
  high_ports=()
  review_ports=()
  for port in "${ports[@]}"; do
    case "$(classify_port "$port")" in
      HIGH) high_ports+=("$port") ;;
      REVIEW) review_ports+=("$port") ;;
    esac
  done
  if (( ${#high_ports[@]} > 0 )); then
    finding FAIL "High-risk legacy ports detected: ${high_ports[*]}."
  else
    finding PASS "No known high-risk legacy ports detected."
  fi
  if (( ${#review_ports[@]} > 0 )); then
    finding INFO "Review whether these non-standard ports are required: ${review_ports[*]}."
  fi
else
  finding WARN "Could not enumerate listening ports; install iproute2 (ss)."
fi

section "Firewall"
firewall_found=0
firewall_active=0
if command -v ufw >/dev/null 2>&1; then
  firewall_found=1
  ufw_status="$(ufw status 2>/dev/null)"
  ufw_probe_status=$?
  report_write 'UFW:\n%s\n' "${ufw_status:-status unavailable}"
  if [[ "$(probe_succeeded "$ufw_probe_status" "$ufw_status")" != "YES" ]]; then
    finding WARN "UFW is installed, but its status command failed."
  else
    case "$(classify_ufw_status "$ufw_status")" in
      PASS) finding "$(firewall_finding_level PASS)" "UFW reports active; rule policy effectiveness was not evaluated."; firewall_active=1 ;;
      FAIL) finding "$(firewall_finding_level FAIL)" "UFW is installed but inactive; another backend may be in use." ;;
      WARN) finding WARN "UFW returned an unrecognized status." ;;
    esac
  fi
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall_found=1
  fw_state="$(firewall-cmd --state 2>/dev/null)"
  fw_probe_status=$?
  report_write 'firewalld state: %s\n' "${fw_state:-unavailable}"
  case "$(classify_firewalld_state "$fw_probe_status" "$fw_state")" in
    ACTIVE)
      finding INFO "firewalld reports running; zone and policy effectiveness were not evaluated."
      firewall_active=1
      ;;
    INACTIVE)
      finding INFO "firewalld is installed but not running; another backend may be in use."
      ;;
    ERROR)
      finding WARN "firewalld is installed, but its state command failed."
      ;;
  esac
fi
if command -v nft >/dev/null 2>&1; then
  firewall_found=1
  nft_rules="$(nft list ruleset 2>/dev/null)"
  nft_status=$?
  if (( nft_status == 0 )); then
    rule_count="$(wc -l <<< "$nft_rules")"
    report_write 'nftables ruleset lines: %s\n' "$rule_count"
    if [[ "$(classify_nft_ruleset "$nft_rules")" == "ACTIVE" ]]; then
      finding INFO "nftables has at least one hooked base chain; review its rules and policies."
      firewall_active=1
    else
      finding WARN "nftables has no hooked input, forward, or output base chain."
    fi
  else
    finding WARN "nftables is installed, but its ruleset could not be read."
  fi
fi
if (( firewall_found == 0 )); then
  finding WARN "No supported host firewall tool was detected."
elif (( firewall_active == 0 )); then
  finding WARN "No active host firewall backend was confirmed."
else
  finding WARN "A firewall backend appears active, but protective policy effectiveness was not verified."
fi

section "Brute-force protection"
if command -v fail2ban-client >/dev/null 2>&1; then
  f2b_status="$(fail2ban-client status 2>/dev/null)"
  f2b_probe_status=$?
  report_write '%s\n' "$f2b_status"
  if [[ "$(probe_succeeded "$f2b_probe_status" "$f2b_status")" != "YES" ]]; then
    finding WARN "Fail2ban is installed, but its status command failed."
  else
    case "$(classify_fail2ban_status "$f2b_status")" in
      PASS) finding PASS "Fail2ban is running with an sshd jail." ;;
      WARN) finding WARN "Fail2ban is running, but an sshd jail was not confirmed." ;;
      ERROR) finding WARN "Fail2ban returned an unrecognized status." ;;
    esac
  fi
else
  finding WARN "Fail2ban is not installed or is not in PATH."
fi

section "Updates"
if command -v apt >/dev/null 2>&1; then
  apt_output="$(apt list --upgradable 2>&1)"
  apt_status=$?
  update_count="$(count_apt_upgrades "$apt_output")"
  report_write 'APT status: %s; upgradable packages in local metadata: %s\n' "$apt_status" "$update_count"
  case "$(classify_package_status apt "$apt_status" "$update_count")" in
    PASS) finding PASS "No upgrades are listed in current APT metadata." ;;
    WARN) finding WARN "$update_count package upgrade(s) are listed; review and patch promptly." ;;
    ERROR) finding WARN "APT update status could not be determined; the command exited with status $apt_status." ;;
  esac
elif command -v dnf >/dev/null 2>&1; then
  dnf_output="$(dnf -q --cacheonly check-update 2>&1)"
  dnf_status=$?
  report_write 'DNF cache-only check status: %s\n' "$dnf_status"
  report_write '%s\n' "$(head -n 30 <<< "$dnf_output")"
  case "$(classify_package_status rpm "$dnf_status" 0)" in
    PASS) finding PASS "DNF reports no pending updates in local metadata." ;;
    WARN) finding WARN "DNF reports pending updates; review and patch promptly." ;;
    ERROR) finding WARN "DNF update status could not be determined; the command exited with status $dnf_status." ;;
  esac
elif command -v yum >/dev/null 2>&1; then
  yum_output="$(yum -q --cacheonly check-update 2>&1)"
  yum_status=$?
  report_write 'YUM cache-only check status: %s\n' "$yum_status"
  report_write '%s\n' "$(head -n 30 <<< "$yum_output")"
  case "$(classify_package_status rpm "$yum_status" 0)" in
    PASS) finding PASS "YUM reports no pending updates in local metadata." ;;
    WARN) finding WARN "YUM reports pending updates; review and patch promptly." ;;
    ERROR) finding WARN "YUM update status could not be determined; the command exited with status $yum_status." ;;
  esac
else
  finding WARN "No supported package manager was detected."
fi

section "Users and access"
passwd_data="$(cat /etc/passwd 2>/dev/null)"
passwd_status=$?
report_write 'UID 0 accounts:\n'
if (( passwd_status == 0 )); then
  uid0_names="$(awk -F: '$3 == 0 {print $1}' <<< "$passwd_data")"
  report_write '%s\n' "$(awk '{print "  " $0}' <<< "$uid0_names")"
  uid0_count="$(awk -F: '$3 == 0 {count++} END {print count+0}' <<< "$passwd_data")"
  uid0_name="$(awk 'NR == 1 {print; exit}' <<< "$uid0_names")"
else
  uid0_count=0
  uid0_name=""
  report_write '  unavailable\n'
fi
case "$(classify_account_read "$passwd_status" "$uid0_count" "$uid0_name")" in
  PASS) finding PASS "The root account is the only UID 0 account." ;;
  FAIL) finding FAIL "UID 0 identity check failed (count=$uid0_count, first account=${uid0_name:-none})." ;;
  WARN) finding WARN "Could not read the account database; UID 0 status is unknown." ;;
esac
report_write 'Interactive-login accounts:\n'
if (( passwd_status == 0 )); then
  report_write '%s\n' "$(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print "  " $1 " -> " $7}' <<< "$passwd_data")"
else
  report_write '  unavailable\n'
fi
last_available=0
command -v last >/dev/null 2>&1 && last_available=1
if [[ "$(classify_availability "$last_available")" == "OK" ]]; then
  report_write 'Recent logins (maximum 10):\n'
  if ! capture_limited 10 last -a; then
    finding WARN "Recent login history could not be read completely."
  fi
else
  finding WARN "The 'last' command is unavailable; recent login history was not checked."
fi

section "Scheduled tasks"
if command -v systemctl >/dev/null 2>&1; then
  report_write 'Loaded timers (maximum 30):\n'
  if ! capture_limited 30 systemctl list-timers --all --no-pager; then
    finding WARN "systemd timer inventory could not be read completely."
  fi
else
  finding WARN "systemctl is unavailable; systemd timers were not checked."
fi
report_write 'System cron entries:\n'
for cron_file in /etc/crontab /etc/cron.d/*; do
  [[ -f "$cron_file" ]] || continue
  report_write '  %s\n' "$cron_file"
done
finding INFO "Review the listed timers and cron files; unfamiliar persistence should be investigated."

section "Summary"
pass_count="$(grep -c '^\[PASS\]' "$report" || true)"
warn_count="$(grep -c '^\[WARN\]' "$report" || true)"
fail_count="$(grep -c '^\[FAIL\]' "$report" || true)"
info_count="$(grep -c '^\[INFO\]' "$report" || true)"
report_write 'PASS=%s WARN=%s FAIL=%s INFO=%s\n' "$pass_count" "$warn_count" "$fail_count" "$info_count"
report_write 'Investigate every FAIL and WARN before changing production configuration.\n'

if ! cat "$report"; then
  printf 'Error: could not print the complete audit report.\n' >&2
  exit 1
fi
if [[ -n "$output_fd" ]]; then
  if ! cat "$report" >&"$output_fd"; then
    printf 'Error: could not write staged report for %s\n' "$output_file" >&2
    exit 1
  fi
  if command -v sync >/dev/null 2>&1 && ! sync -f "$output_stage"; then
    printf 'Error: staged report could not be flushed to storage.\n' >&2
    exit 1
  fi
  if ! exec {output_fd}>&-; then
    printf 'Error: staged report could not be closed cleanly.\n' >&2
    exit 1
  fi
  if ! publish_exact "$output_stage" "$output_file" 2>/dev/null; then
    if [[ -e "$output_file" || -L "$output_file" ]]; then
      printf 'Error: refusing to overwrite existing output path: %s\n' "$output_file" >&2
      exit 2
    fi
    printf 'Error: could not publish report to %s\n' "$output_file" >&2
    exit 1
  fi
fi
