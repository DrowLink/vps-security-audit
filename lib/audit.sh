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
          peer=$6
          has_address_separator=(address ~ /:/)
          sub(/^.*:/, "", address)
          if (NF < 6 || $1 !~ /^(tcp|udp)$/ || !has_address_separator ||
              address !~ /^[0-9]+$/ ||
              (peer != "0.0.0.0:*" && peer != "[::]:*" && peer != "*:*")) {
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
          peer=$5
          sub(/^.*:/, "", address)
          if (NF < 5 || $1 !~ /^(tcp|tcp6|udp|udp6)$/ || address !~ /^[0-9]+$/ ||
              (peer != "0.0.0.0:*" && peer != ":::*" && peer != "*:*")) {
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
  local status="${1,,}" first_line
  first_line="${status%%$'\n'*}"
  if [[ "$first_line" == "status: active" ]]; then
    printf 'PASS\n'
  elif [[ "$first_line" == "status: inactive" ]]; then
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

classify_rpm_result() {
  local status="$1" output="$2"
  if (( status == 0 )); then
    if [[ "$output" =~ ^[[:space:]]*$ ]]; then
      printf 'PASS\n'
    else
      printf 'ERROR\n'
    fi
  elif (( status == 100 )); then
    printf 'WARN\n'
  else
    printf 'ERROR\n'
  fi
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
    /^[[:space:]]*chain[[:space:]]+[^[:space:]{]+[[:space:]]*\{[[:space:]]*$/ {in_chain=1; next}
    in_chain && /^[[:space:]]*type[[:space:]]+(filter|nat|route)[[:space:]]+hook[[:space:]]+(input|forward|output)([[:space:]]|;)/ {found=1}
    in_chain && /^[[:space:]]*\}[[:space:]]*$/ {in_chain=0}
    END {exit(found ? 0 : 1)}
  ' <<< "$1"; then
    printf 'ACTIVE\n'
  else
    printf 'INERT\n'
  fi
}

classify_fail2ban_status() {
  local status="$1" first_line jail_line jail_list
  [[ -n "$status" ]] || { printf 'ERROR\n'; return; }
  first_line="${status%%$'\n'*}"
  [[ "$first_line" == "Status" ]] || { printf 'ERROR\n'; return; }
  if ! jail_line="$(awk '/^[[:space:]]*(`-|\|-)[[:space:]]+Jail list:[[:space:]]*/ {print}' <<< "$status")"; then
    printf 'ERROR\n'
    return
  fi
  if [[ -z "$jail_line" || "$jail_line" == *$'\n'* ]]; then
    printf 'ERROR\n'
    return
  fi
  jail_list="${jail_line#*Jail list:}"
  if [[ "$jail_list" =~ ^[[:space:]]*$ ]]; then
    printf 'WARN\n'
    return
  fi
  if [[ ! "$jail_list" =~ ^[[:space:]]*[[:alnum:]_.-]+([[:space:]]*,[[:space:]]*[[:alnum:]_.-]+)*[[:space:]]*$ ]]; then
    printf 'ERROR\n'
    return
  fi
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

capture_active_connections() {
  local limit="$1" target="$2" filter_status
  local -a pipeline_statuses
  shift 2

  ACTIVE_CONNECTION_PRODUCER_STATUS=127
  (( limit > 0 )) || return 2
  "$@" 2>/dev/null | awk -v limit="$limit" '
    function valid_port(port) {
      return port == "*" || (port ~ /^[0-9]+$/ && (port + 0) <= 65535)
    }
    function valid_ipv4(address,    octets, count, i) {
      count=split(address, octets, ".")
      if (count != 4) return 0
      for (i=1; i<=4; i++) {
        if (octets[i] !~ /^[0-9]+$/ || (octets[i] + 0) > 255 ||
            octets[i] != sprintf("%d", octets[i] + 0)) return 0
      }
      return 1
    }
    function ipv6_units(part,    fields, count, i, units) {
      if (part == "") return 0
      count=split(part, fields, ":")
      units=0
      for (i=1; i<=count; i++) {
        if (fields[i] ~ /\./) {
          if (i != count || !valid_ipv4(fields[i])) return -1
          units+=2
        } else {
          if (fields[i] !~ /^[[:xdigit:]]{1,4}$/) return -1
          units++
        }
      }
      return units
    }
    function valid_ipv6(address,    scoped, scope_count, compression, remainder, left, right, joined, units) {
      scope_count=split(address, scoped, "%")
      if (scope_count > 2 ||
          (scope_count == 2 && scoped[2] !~ /^[[:alnum:]_.-]+$/)) return 0
      address=scoped[1]
      compression=index(address, "::")
      if (compression) {
        remainder=substr(address, compression + 2)
        if (index(remainder, "::") ||
            (compression > 1 && substr(address, compression - 1, 1) == ":") ||
            substr(remainder, 1, 1) == ":") return 0
        left=substr(address, 1, compression - 1)
        right=remainder
        joined=left
        if (left != "" && right != "") joined=left ":" right
        else if (right != "") joined=right
        units=ipv6_units(joined)
        return units >= 0 && units < 8
      }
      if (substr(address, 1, 1) == ":" || substr(address, length(address), 1) == ":") return 0
      return ipv6_units(address) == 8
    }
    function valid_endpoint(endpoint,    separator, address, port) {
      if (substr(endpoint, 1, 1) == "[") {
        separator=index(endpoint, "]:")
        if (separator < 3) return 0
        address=substr(endpoint, 2, separator - 2)
        port=substr(endpoint, separator + 2)
        return valid_ipv6(address) && valid_port(port)
      }
      separator=index(endpoint, ":")
      if (!separator || index(substr(endpoint, separator + 1), ":")) return 0
      address=substr(endpoint, 1, separator - 1)
      port=substr(endpoint, separator + 1)
      return (address == "*" || valid_ipv4(address)) && valid_port(port)
    }
    BEGIN {header=0; emitted=0; malformed=0; truncated=0}
    NR > limit {truncated=1; exit}
    /^Netid[[:space:]]+State[[:space:]]+Recv-Q[[:space:]]+Send-Q[[:space:]]+Local Address:Port[[:space:]]+Peer Address:Port([[:space:]]*Process)?[[:space:]]*$/ {
      if (header || NR != 1) {
        malformed=1
        next
      }
      print "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port"
      header=1
      emitted++
      next
    }
    {
      if (!header || NF < 6 || $1 !~ /^(tcp|udp)$/ ||
          $2 !~ /^[A-Z][A-Z0-9-]*$/ || $3 !~ /^[0-9]+$/ ||
          $4 !~ /^[0-9]+$/ || !valid_endpoint($5) || !valid_endpoint($6)) {
        malformed=1
        next
      }
      print $1, $2, $3, $4, $5, $6
      emitted++
    }
    END {
      if (truncated) exit 3
      if (!header || emitted == 0) exit 2
      if (malformed) exit 4
    }
  ' > "$target"
  pipeline_statuses=("${PIPESTATUS[@]}")
  ACTIVE_CONNECTION_PRODUCER_STATUS="${pipeline_statuses[0]}"
  filter_status="${pipeline_statuses[1]}"

  (( filter_status == 3 )) && return 3
  (( ACTIVE_CONNECTION_PRODUCER_STATUS == 0 )) || return 1
  return "$filter_status"
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
