#!/usr/bin/env bash
# linux-baseline: read-only hardening checks for Linux hosts, in pure Bash.
# Every path is resolved under --root, so the same checks run against a live host (/) or a mounted image / test fixture.
set -u

ROOT="/"
FORMAT="text"
FAIL_ON="low"
declare -A SEV_RANK=([low]=1 [medium]=2 [high]=3 [critical]=4)
RESULTS=()
FAILS=0
WORST=0

usage() {
  cat <<'U'
usage: linux-baseline.sh [--root DIR] [--format text|json] [--fail-on low|medium|high|critical]
Read-only checks (no changes are made). Exit code 2 when a failed check reaches --fail-on.
U
}

while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="${2:-}"; shift 2 ;;
    --format) FORMAT="${2:-}"; shift 2 ;;
    --fail-on) FAIL_ON="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[ -d "$ROOT" ] || { echo "root directory not found: $ROOT" >&2; exit 2; }
[ -n "${SEV_RANK[$FAIL_ON]:-}" ] || { echo "invalid --fail-on" >&2; exit 2; }
case "$FORMAT" in text|json) ;; *) echo "invalid --format" >&2; exit 2 ;; esac
ROOT="${ROOT%/}"

p() { printf '%s%s' "$ROOT" "$1"; }

json_escape() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }

# record <id> <PASS|FAIL|SKIP> <severity> <message>
record() {
  local id=$1 status=$2 sev=$3 msg=$4
  RESULTS+=("$id|$status|$sev|$msg")
  if [ "$status" = FAIL ]; then
    FAILS=$((FAILS + 1))
    local r=${SEV_RANK[$sev]}
    [ "$r" -gt "$WORST" ] && WORST=$r
  fi
}

mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# First effective (uncommented) value of an sshd directive; sshd honours the first occurrence.
sshd_val() {
  local f; f=$(p /etc/ssh/sshd_config)
  [ -r "$f" ] || return 1
  awk -v k="$1" 'BEGIN{IGNORECASE=1} $0 !~ /^[[:space:]]*#/ && tolower($1)==tolower(k) {print tolower($2); exit}' "$f"
}

check_sshd() {
  local f; f=$(p /etc/ssh/sshd_config)
  if [ ! -r "$f" ]; then
    for id in L001 L002 L003 L004 L014; do record "$id" SKIP low "sshd_config not found"; done
    return
  fi
  local v
  v=$(sshd_val permitrootlogin)
  case "${v:-prohibit-password}" in
    no|prohibit-password|without-password|forced-commands-only) record L001 PASS high "root SSH login restricted (${v:-default})" ;;
    *) record L001 FAIL high "PermitRootLogin is '$v'" ;;
  esac
  v=$(sshd_val passwordauthentication)
  if [ "${v:-yes}" = no ]; then record L002 PASS medium "SSH password authentication disabled"
  else record L002 FAIL medium "SSH password authentication enabled (${v:-default yes}); prefer keys"; fi
  v=$(sshd_val permitemptypasswords)
  if [ "${v:-no}" = yes ]; then record L003 FAIL critical "PermitEmptyPasswords yes"; else record L003 PASS critical "empty SSH passwords refused"; fi
  v=$(sshd_val x11forwarding)
  if [ "${v:-no}" = yes ]; then record L004 FAIL low "X11Forwarding enabled"; else record L004 PASS low "X11 forwarding off"; fi
  local m; m=$(mode_of "$f")
  if [ -n "$m" ] && [ $(( 8#$m & 8#022 )) -ne 0 ]; then record L014 FAIL high "sshd_config writable by group/others (mode $m)"; else record L014 PASS high "sshd_config permissions ok (${m:-?})"; fi
}

check_accounts() {
  local pw; pw=$(p /etc/passwd)
  if [ -r "$pw" ]; then
    local extra; extra=$(awk -F: '$3==0 && $1!="root" {printf "%s ", $1}' "$pw")
    if [ -n "$extra" ]; then record L005 FAIL critical "extra UID 0 accounts: ${extra% }"; else record L005 PASS critical "only root has UID 0"; fi
    local m; m=$(mode_of "$pw")
    if [ -n "$m" ] && [ $(( 8#$m & 8#002 )) -ne 0 ]; then record L008 FAIL high "/etc/passwd is world-writable (mode $m)"; else record L008 PASS high "/etc/passwd not world-writable"; fi
  else
    record L005 SKIP critical "/etc/passwd not readable"; record L008 SKIP high "/etc/passwd not readable"
  fi
  local sh; sh=$(p /etc/shadow)
  if [ -r "$sh" ]; then
    local empty; empty=$(awk -F: '$2=="" {printf "%s ", $1}' "$sh")
    if [ -n "$empty" ]; then record L006 FAIL critical "accounts with empty password: ${empty% }"; else record L006 PASS critical "no empty password fields"; fi
  else
    record L006 SKIP critical "/etc/shadow not readable (run as root)"
  fi
  if [ -e "$sh" ]; then
    local m; m=$(mode_of "$sh")
    if [ -n "$m" ] && [ $(( 8#$m & 8#027 )) -ne 0 ]; then record L007 FAIL high "/etc/shadow too permissive (mode $m)"; else record L007 PASS high "/etc/shadow permissions ok (${m:-?})"; fi
  else
    record L007 SKIP high "/etc/shadow not found"
  fi
  local ld; ld=$(p /etc/login.defs)
  if [ -r "$ld" ]; then
    local d; d=$(awk '$1=="PASS_MAX_DAYS" {print $2; exit}' "$ld")
    if [ -n "$d" ] && [ "$d" -le 365 ] 2>/dev/null; then record L009 PASS medium "PASS_MAX_DAYS=$d"; else record L009 FAIL medium "PASS_MAX_DAYS is '${d:-unset}' (want <= 365)"; fi
  else
    record L009 SKIP medium "/etc/login.defs not found"
  fi
}

check_sudo() {
  local files=() f
  [ -r "$(p /etc/sudoers)" ] && files+=("$(p /etc/sudoers)")
  for f in "$(p /etc/sudoers.d)"/*; do [ -f "$f" ] && [ -r "$f" ] && files+=("$f"); done
  if [ ${#files[@]} -eq 0 ]; then record L010 SKIP medium "no readable sudoers files"; return; fi
  local hits; hits=$(grep -hEi '^[^#]*NOPASSWD' "${files[@]}" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$hits" -gt 0 ]; then record L010 FAIL medium "$hits sudoers rule(s) use NOPASSWD"; else record L010 PASS medium "no NOPASSWD sudo rules"; fi
}

check_kernel() {
  local f v
  f=$(p /proc/sys/kernel/randomize_va_space)
  if [ -r "$f" ]; then v=$(tr -d '[:space:]' < "$f"); if [ "$v" = 2 ]; then record L011 PASS medium "ASLR fully enabled"; else record L011 FAIL medium "randomize_va_space=$v (want 2)"; fi
  else record L011 SKIP medium "kernel setting unavailable"; fi
  f=$(p /proc/sys/net/ipv4/tcp_syncookies)
  if [ -r "$f" ]; then v=$(tr -d '[:space:]' < "$f"); if [ "$v" = 1 ]; then record L012 PASS low "TCP SYN cookies on"; else record L012 FAIL low "tcp_syncookies=$v (want 1)"; fi
  else record L012 SKIP low "kernel setting unavailable"; fi
  f=$(p /proc/sys/net/ipv4/conf/all/accept_redirects)
  if [ -r "$f" ]; then v=$(tr -d '[:space:]' < "$f"); if [ "$v" = 0 ]; then record L013 PASS low "ICMP redirects ignored"; else record L013 FAIL low "accept_redirects=$v (want 0)"; fi
  else record L013 SKIP low "kernel setting unavailable"; fi
}

check_sshd; check_accounts; check_sudo; check_kernel

if [ "$FORMAT" = json ]; then
  printf '[\n'
  n=${#RESULTS[@]}; i=0
  for r in "${RESULTS[@]}"; do
    i=$((i + 1)); IFS='|' read -r id status sev msg <<< "$r"
    printf '  {"id":"%s","status":"%s","severity":"%s","message":"%s"}%s\n' "$id" "$status" "$sev" "$(json_escape "$msg")" "$([ "$i" -lt "$n" ] && echo ,)"
  done
  printf ']\n'
else
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id status sev msg <<< "$r"
    printf '[%-4s] %s %-8s %s\n' "$status" "$id" "$sev" "$msg"
  done
  printf '\n%d check(s), %d failed\n' "${#RESULTS[@]}" "$FAILS"
fi

[ "$WORST" -ge "${SEV_RANK[$FAIL_ON]}" ] && exit 2
exit 0
