#!/usr/bin/env bash
# Dependency-free tests: build fixture root directories and assert on the output.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
TOOL="$HERE/linux-baseline.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

ok()   { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }
assert_contains() { grep -qF -- "$2" <<< "$1" && ok || fail "$3 (missing '$2')"; }
assert_absent()   { grep -qF -- "$2" <<< "$1" && fail "$3 (unexpected '$2')" || ok; }
assert_eq()       { [ "$1" = "$2" ] && ok || fail "$3 (got '$1', want '$2')"; }

good_root() {
  local r=$1
  mkdir -p "$r/etc/ssh" "$r/etc/sudoers.d" "$r/proc/sys/kernel" "$r/proc/sys/net/ipv4/conf/all"
  printf 'PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nX11Forwarding no\n' > "$r/etc/ssh/sshd_config"
  chmod 600 "$r/etc/ssh/sshd_config"
  printf 'root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n' > "$r/etc/passwd"; chmod 644 "$r/etc/passwd"
  printf 'root:!:19000:0:90:7:::\ndaemon:*:19000:0:99999:7:::\n' > "$r/etc/shadow"; chmod 640 "$r/etc/shadow"
  printf 'PASS_MAX_DAYS 90\n' > "$r/etc/login.defs"
  printf 'root ALL=(ALL) ALL\n' > "$r/etc/sudoers"
  echo 2 > "$r/proc/sys/kernel/randomize_va_space"
  echo 1 > "$r/proc/sys/net/ipv4/tcp_syncookies"
  echo 0 > "$r/proc/sys/net/ipv4/conf/all/accept_redirects"
}

# 1. hardened host: no failures, exit 0
good_root "$TMP/good"
out=$("$TOOL" --root "$TMP/good"); code=$?
assert_eq "$code" 0 "hardened host exits 0"
assert_contains "$out" "0 failed" "hardened host reports zero failures"

# 2. weak host: every class of finding detected
bad="$TMP/bad"; good_root "$bad"
printf 'PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\nX11Forwarding yes\n' > "$bad/etc/ssh/sshd_config"; chmod 666 "$bad/etc/ssh/sshd_config"
printf 'root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n' > "$bad/etc/passwd"; chmod 666 "$bad/etc/passwd"
printf 'root:!:1:::::\nghost::1:::::\n' > "$bad/etc/shadow"; chmod 644 "$bad/etc/shadow"
printf 'PASS_MAX_DAYS 99999\n' > "$bad/etc/login.defs"
printf 'deploy ALL=(ALL) NOPASSWD: ALL\n' > "$bad/etc/sudoers.d/deploy"
echo 0 > "$bad/proc/sys/kernel/randomize_va_space"; echo 0 > "$bad/proc/sys/net/ipv4/tcp_syncookies"; echo 1 > "$bad/proc/sys/net/ipv4/conf/all/accept_redirects"
out=$("$TOOL" --root "$bad"); code=$?
assert_eq "$code" 2 "weak host exits 2"
for id in L001 L002 L003 L004 L005 L006 L007 L008 L009 L010 L011 L012 L013 L014; do
  assert_contains "$out" "[FAIL] $id" "weak host fails $id"
done
assert_contains "$out" "toor" "extra UID 0 account is named"
assert_contains "$out" "ghost" "empty-password account is named"

# 3. sshd honours the FIRST occurrence and ignores comments
first="$TMP/first"; good_root "$first"
printf '# PermitRootLogin yes\nPermitRootLogin no\nPermitRootLogin yes\n' > "$first/etc/ssh/sshd_config"; chmod 600 "$first/etc/ssh/sshd_config"
out=$("$TOOL" --root "$first")
assert_contains "$out" "[PASS] L001" "first occurrence wins"

# 4. missing files are skipped, not failed
mkdir -p "$TMP/empty"
out=$("$TOOL" --root "$TMP/empty"); code=$?
assert_eq "$code" 0 "empty root exits 0"
assert_contains "$out" "[SKIP] L001" "missing sshd_config skipped"

# 5. --fail-on threshold
low="$TMP/low"; good_root "$low"; echo 0 > "$low/proc/sys/net/ipv4/tcp_syncookies"
"$TOOL" --root "$low" >/dev/null; assert_eq "$?" 2 "low finding fails at default threshold"
"$TOOL" --root "$low" --fail-on high >/dev/null; assert_eq "$?" 0 "low finding passes with --fail-on high"

# 6. JSON output
out=$("$TOOL" --root "$bad" --format json)
assert_contains "$out" '"id":"L005","status":"FAIL","severity":"critical"' "JSON carries id, status and severity"
assert_contains "$out" "[" "JSON is a list"

# 7. argument validation
"$TOOL" --bogus >/dev/null 2>&1; assert_eq "$?" 2 "unknown flag rejected"
"$TOOL" --root /does/not/exist >/dev/null 2>&1; assert_eq "$?" 2 "missing root rejected"
"$TOOL" --fail-on nope >/dev/null 2>&1; assert_eq "$?" 2 "bad severity rejected"

# 8. the tool is read-only
before=$(find "$TMP/good" -type f -exec cksum {} + 2>/dev/null | sort | cksum)
"$TOOL" --root "$TMP/good" >/dev/null
after=$(find "$TMP/good" -type f -exec cksum {} + 2>/dev/null | sort | cksum)
assert_eq "$after" "$before" "scan does not modify files"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
