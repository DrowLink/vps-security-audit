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
