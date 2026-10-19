#!/usr/bin/env bash
# Bounded, parallel read-only diagnostics. No installs, credentials or uploads.
umask 077
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/layero-probes-XXXXXX") || exit 1
report="$work_dir/report"
printf 'Layero: проверяем подключение…\n'
sanitize() {
  sed -E 's/(Uses proxy env variable .* == ).*/\1[redacted]/; s/([Pp]roxy-[Aa]uthorization:|[Aa]uthorization:|[Ss]et-[Cc]ookie:).*/\1 [redacted]/'
}
bounded() {
  local seconds=$1 command_pid timer_pid result_code
  shift
  "$@" & command_pid=$!
  ( sleep "$seconds" >/dev/null 2>&1; printf '\nPROBE_TIME_LIMIT=%ss (partial result)\n' "$seconds"; kill -TERM "$command_pid" 2>/dev/null; sleep 1 >/dev/null 2>&1; kill -KILL "$command_pid" 2>/dev/null ) & timer_pid=$!
  wait "$command_pid" 2>/dev/null; result_code=$?
  kill "$timer_pid" 2>/dev/null
  wait "$timer_pid" 2>/dev/null
  return "$result_code"
}
check_target() {
  local target=$1 host=$2 dns_a_pid dns_aaaa_pid result curl_code destination family
  printf '\n===== %s =====\nUTC: ' "$host"; date -u '+%Y-%m-%dT%H:%M:%SZ'
  if command -v nslookup >/dev/null 2>&1; then
    bounded 3 nslookup -timeout=1 -retry=1 -type=A "$host" >"$work_dir/$host.a" 2>&1 & dns_a_pid=$!
    bounded 3 nslookup -timeout=1 -retry=1 -type=AAAA "$host" >"$work_dir/$host.aaaa" 2>&1 & dns_aaaa_pid=$!
  fi
  result=$(bounded 7 curl -q -v --connect-timeout 3 --max-time 6 --output /dev/null \
    --write-out '\nLAYERO_REMOTE_IP=%{remote_ip}\nHTTP=%{http_code} DNS=%{time_namelookup} CONNECT=%{time_connect} TLS=%{time_appconnect} FIRST_BYTE=%{time_starttransfer} TOTAL=%{time_total}\n' "$target" 2>&1)
  curl_code=$?
  if [ -n "$dns_a_pid" ]; then
    wait "$dns_a_pid"; wait "$dns_aaaa_pid"
    cat "$work_dir/$host.a" "$work_dir/$host.aaaa"
    rm -f "$work_dir/$host.a" "$work_dir/$host.aaaa"
  else printf 'DNS: nslookup unavailable; see curl resolution.\n'; fi
  printf '\nHTTPS GET:\n%s\ncurl_exit=%s\n' "$result" "$curl_code" | sanitize
  destination=$(printf '%s\n' "$result" | sed -n 's/^LAYERO_REMOTE_IP=//p' | tail -n 1)
  if printf '%s' "$result" | grep -Eiq 'proxy|CONNECT tunnel'; then
    printf 'Proxy detected: hostname trace is separate from the proxy/browser route.\n'
    destination="$host"
  fi
  [ -n "$destination" ] || destination="$host"
  case "$destination" in *:*) family=-6;; *) family=-4;; esac
  printf '\nRoute target: %s\nRoute budget: 4s; partial hops, NOT packet-loss statistics or the reverse path.\n' "$destination"
  if command -v mtr >/dev/null 2>&1; then
    printf 'TCP MTR443 raw events, 2 cycles:\n'
    bounded 4 mtr "$family" -T -P 443 -l -n -c 2 -m 16 "$destination" 2>&1
    printf 'mtr_exit=%s\n' "$?"
  elif [ "$family" = -4 ] && command -v traceroute >/dev/null 2>&1; then
    printf 'MTR unavailable. UDP traceroute (NOT TCP443); may stop before destination:\n'
    bounded 4 traceroute -n -m 16 -w 1 -q 1 "$destination" 2>&1
    printf 'traceroute_exit=%s\n' "$?"
  else printf 'Route not measured: no compatible tool.\n'; fi
}
{
  printf 'Layero network diagnostics 1.1\nUTC: '; date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf 'OS: '; uname -s
  printf 'Parallel quick snapshot. DNS/terminal proxy may differ from browser; routes are limited partial outbound probes. No uploads.\n'
} >"$report"
bounded 5 curl -q -sS --connect-timeout 3 --max-time 4 'https://network-check.layero.app/__layero/network-info' >"$work_dir/network" 2>&1 & network_pid=$!
pids=(); parts=()
for target in 'https://app.layero.ru/login' 'https://api.layero.ru/health' 'https://status.layero.app/' 'https://docs.layero.ru/' 'https://layero.ru/'; do
  host=${target#https://}; host=${host%%/*}
  check_target "$target" "$host" >"$work_dir/$host" 2>&1 & pids+=("$!")
  parts+=("$work_dir/$host")
done
for probe_pid in "${pids[@]}"; do wait "$probe_pid"; done
wait "$network_pid"
printf '\nObserved egress network:\n' >>"$report"
cat "$work_dir/network" >>"$report"; rm -f "$work_dir/network"
for part in "${parts[@]}"; do cat "$part" >>"$report"; rm -f "$part"; done
printf '\nFinished UTC: ' >>"$report"; date -u '+%Y-%m-%dT%H:%M:%SZ' >>"$report"
printf '\nГотово. Скопируйте текст между BEGIN и END и отправьте в поддержку.\n\n--- BEGIN LAYERO REPORT ---\n'
cat "$report"
printf '\n--- END LAYERO REPORT ---\n'
rm -f "$report"
rmdir "$work_dir"
