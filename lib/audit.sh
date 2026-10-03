#!/usr/bin/env bash

classify_sshd_setting() {
  local key="${1,,}" value="${2,,}"

  case "$key:$value" in
    permitrootlogin:no|passwordauthentication:no) printf 'PASS\n' ;;
    permitrootlogin:prohibit-password|permitrootlogin:without-password) printf 'WARN\n' ;;
    permitrootlogin:*|passwordauthentication:yes) printf 'FAIL\n' ;;
    *) printf 'WARN\n' ;;
  esac
}

classify_port() {
  case "$1" in
    21|23|69|111|512|513|514) printf 'HIGH\n' ;;
    22|25|53|80|110|143|443|465|587|993|995) printf 'EXPECTED\n' ;;
    *) printf 'REVIEW\n' ;;
  esac
}

extract_listening_ports() {
  local format="$1" input="$2" field
  case "$format" in
    ss) field=5 ;;
    netstat) field=4 ;;
    *) return 2 ;;
  esac
  awk -v field="$field" 'NR > 1 {
    address=$field
    sub(/^.*:/, "", address)
    if (address ~ /^[0-9]+$/) print address
  }' <<< "$input" | sort -nu
}

validate_listening_output() {
  local format="$1" input="$2"
  case "$format" in
    ss)
      awk '
        BEGIN {valid=1; header=0}
        /^$/ {next}
        /^Netid[[:space:]]+State[[:space:]]+Recv-Q[[:space:]]+Send-Q[[:space:]]+Local Address:Port[[:space:]]+Peer Address:Port([[:space:]]*Process)?[[:space:]]*$/ {
          if (header) valid=0
          header=1
          next
        }
        !header {valid=0; next}
        {
          address=$5
          sub(/^.*:/, "", address)
          if (NF < 6 || $1 !~ /^(tcp|udp)$/ || address !~ /^[0-9]+$/) {
            valid=0
          } else if ($1 == "tcp" && $2 != "LISTEN") {
            valid=0
          } else if ($1 == "udp" && $2 != "UNCONN") {
            valid=0
          }
        }
        END {exit(header && valid ? 0 : 1)}
      ' <<< "$input" && printf 'VALID\n' || printf 'INVALID\n'
      ;;
    netstat)
      awk '
        BEGIN {valid=1; header=0}
        /^$/ {next}
        /^Active Internet connections \(only servers\)$/ && !header {next}
        /^Proto[[:space:]]+Recv-Q[[:space:]]+Send-Q[[:space:]]+Local Address[[:space:]]+Foreign Address[[:space:]]+State([[:space:]]+PID\/Program name)?[[:space:]]*$/ {
          if (header) valid=0
          header=1
          next
        }
        !header {valid=0; next}
        {
          address=$4
          sub(/^.*:/, "", address)
          if (NF < 5 || $1 !~ /^(tcp|tcp6|udp|udp6)$/ || address !~ /^[0-9]+$/) {
            valid=0
          } else if ($1 ~ /^tcp/ && (NF < 6 || $6 != "LISTEN")) {
            valid=0
          } else if ($1 ~ /^udp/ && NF > 6) {
            valid=0
          }
        }
        END {exit(header && valid ? 0 : 1)}
      ' <<< "$input" && printf 'VALID\n' || printf 'INVALID\n'
      ;;
    *) printf 'INVALID\n' ;;
  esac
}

classify_ufw_status() {
  local status="${1,,}"
  if [[ "$status" == *"status: active"* ]]; then
    printf 'PASS\n'
  elif [[ "$status" == *"status: inactive"* ]]; then
    printf 'FAIL\n'
  else
    printf 'WARN\n'
  fi
}

classify_package_status() {
  local family="$1" status="$2" count="$3"
  case "$family:$status" in
    apt:0)
      (( count == 0 )) && printf 'PASS\n' || printf 'WARN\n'
      ;;
    rpm:0) printf 'PASS\n' ;;
    rpm:100) printf 'WARN\n' ;;
    *) printf 'ERROR\n' ;;
  esac
}

count_apt_upgrades() {
  awk '/\[upgradable from:/ {count++} END {print count+0}' <<< "$1"
}

classify_apt_result() {
  local status="$1" output="$2" count
  if (( status != 0 )) || ! awk '
    BEGIN {valid=1}
    /^$/ {next}
    $0 == "WARNING: apt does not have a stable CLI interface. Use with caution in scripts." {next}
    $0 == "Listing..." {if (listing) valid=0; listing=1; next}
    listing && NF == 6 && $1 ~ /^[^[:space:]\/]+\/[^[:space:]]+$/ &&
      $4 == "[upgradable" && $5 == "from:" && $6 ~ /]$/ {next}
    {valid=0}
    END {exit(listing && valid != 0 ? 0 : 1)}
  ' <<< "$output"; then
    printf 'ERROR\n'
    return
  fi
  count="$(count_apt_upgrades "$output")"
  classify_package_status apt "$status" "$count"
}

classify_nft_ruleset() {
  if awk '
    /^[[:space:]]*#/ {next}
    /^[[:space:]]*type[[:space:]]+(filter|nat|route)[[:space:]]+hook[[:space:]]+(input|forward|output)([[:space:]]|;)/ {found=1}
    END {exit(found ? 0 : 1)}
  ' <<< "$1"; then
    printf 'ACTIVE\n'
  else
    printf 'INERT\n'
  fi
}

classify_fail2ban_status() {
  local status="$1" jail_list
  [[ -n "$status" ]] || { printf 'ERROR\n'; return; }
  jail_list="$(awk -F'Jail list:' '/Jail list:/ {print $2; exit}' <<< "$status")"
  [[ "$status" == *"Jail list:"* ]] || { printf 'ERROR\n'; return; }
  if [[ "$jail_list" =~ (^|[,	[:space:]])sshd([,	[:space:]]|$) ]]; then
    printf 'PASS\n'
  else
    printf 'WARN\n'
  fi
}

probe_succeeded() {
  local status="$1" output="$2"
  if (( status == 0 )) && [[ -n "$output" ]]; then
    printf 'YES\n'
  else
    printf 'NO\n'
  fi
}

classify_account_read() {
  local status="$1" uid0_count="$2" uid0_name="$3"
  if (( status != 0 )); then
    printf 'WARN\n'
  elif (( uid0_count == 1 )) && [[ "$uid0_name" == "root" ]]; then
    printf 'PASS\n'
  else
    printf 'FAIL\n'
  fi
}

firewall_finding_level() {
  [[ "$1" == "WARN" ]] && printf 'WARN\n' || printf 'INFO\n'
}

classify_firewalld_state() {
  local status="$1" state="${2,,}"
  if (( status == 0 )) && [[ "$state" == "running" ]]; then
    printf 'ACTIVE\n'
  elif (( status == 252 )) && [[ "$state" == "not running" ]]; then
    printf 'INACTIVE\n'
  else
    printf 'ERROR\n'
  fi
}

classify_capture_status() {
  (( $1 == 0 )) && printf 'OK\n' || printf 'WARN\n'
}

classify_availability() {
  (( $1 == 1 )) && printf 'OK\n' || printf 'WARN\n'
}

ssh_finding_level() {
  local result
  result="$(classify_sshd_setting "$1" "$2")"
  [[ "$result" == "PASS" ]] && printf 'INFO\n' || printf '%s\n' "$result"
}

append_report() {
  local target="$1" format="$2"
  shift 2
  printf "$format" "$@" >> "$target"
}

publish_exact() {
  ln -T -- "$1" "$2"
}
