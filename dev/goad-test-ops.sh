#!/usr/bin/env bash
#
# Tests msldap-ops against a GOAD lab: runs queries with query logging enabled and imports the
# resulting log with bofhound. Meant to be run on a host that can reach the lab.
#
# Usage:
#   dev/goad-test-ops.sh
#
# Uses the same configuration as goad-test-msldap.sh (dev/goad.env, see dev/goad.env.example):
# NORTH_DC, ROOT_DC, LOWPRIV_USER, LOWPRIV_PASS. msldap is taken from the checkout configured in
# [tool.uv.sources] of pyproject.toml (../msldap), bofhound is run via uvx.
#
# Results end up in dev/results/ops-<timestamp>/ (git-ignored).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$HERE/goad.env" ]] && source "$HERE/goad.env"

NORTH_DC="${NORTH_DC:-192.168.56.11}"
LOWPRIV_USER="${LOWPRIV_USER:-samwell.tarly}"
LOWPRIV_PASS="${LOWPRIV_PASS:-Heartsbane}"

RESULTS="$HERE/results/ops-$(date +%Y%m%d-%H%M%S)"
LOGS="$RESULTS/msldap-ops-logs"
mkdir -p "$RESULTS"
exec > >(tee "$RESULTS/run.log") 2>&1

command -v uv >/dev/null || {
  echo "uv not found (pacman -S uv)"
  exit 1
}

echo "== msldap-ops GOAD test run $(date -Is)"
echo "   results:  $RESULTS"

uv sync -q --project "$REPO_ROOT"
OPS="$REPO_ROOT/.venv/bin/msldap-ops"
PY="$REPO_ROOT/.venv/bin/python"
URL="$("$PY" -c 'import sys; from urllib.parse import quote; d,u,p,h=sys.argv[1:]; print("ldap+ntlm-password://%s\\%s:%s@%s" % (d, quote(u, safe=""), quote(p, safe=""), h))' NORTH "$LOWPRIV_USER" "$LOWPRIV_PASS" "$NORTH_DC")"

ops() { # ops <outfile> <commands...>
  local out="$1"
  shift
  "$OPS" --log-dir "$LOGS" "$URL" "$@" >"$RESULTS/$out" 2>&1 || true
}

PASS=0
FAIL=0
check() { # check <description> <pattern> <file>
  if grep -qE "$2" "$3"; then
    echo "   PASS  $1"
    PASS=$((PASS + 1))
  else
    echo "   FAIL  $1 (see $(basename "$3"))"
    FAIL=$((FAIL + 1))
  fi
}

check_cmd() { # check_cmd <description> <command...>
  local desc="$1"
  shift
  if "$@"; then
    echo "   PASS  $desc"
    PASS=$((PASS + 1))
  else
    echo "   FAIL  $desc"
    FAIL=$((FAIL + 1))
  fi
}

DOMAIN_DN="DC=north,DC=sevenkingdoms,DC=local"
CONFIG_DN="CN=Configuration,DC=sevenkingdoms,DC=local"
ATTRS='*,nTSecurityDescriptor'

echo
echo "== query logging"
ops collect.txt login \
  "query (objectClass=domain) $ATTRS" \
  "query (sAMAccountType=805306368) $ATTRS" \
  "query (objectCategory=group) $ATTRS" \
  "query (objectCategory=computer) $ATTRS" \
  "query (objectClass=pKICertificateTemplate) $ATTRS $CONFIG_DN" \
  "query (objectClass=pKIEnrollmentService) $ATTRS $CONFIG_DN" \
  log
LOG="$(ls "$LOGS"/msldap-ops_*.log 2>/dev/null | head -n 1 || true)"
QLOG="$(ls "$LOGS"/msldap-ops-queries_*.jsonl 2>/dev/null | head -n 1 || true)"
check_cmd "log file written to --log-dir" test -s "${LOG:-/nonexistent}"
check_cmd "query journal written" test -s "${QLOG:-/nonexistent}"
check "log command shows the log location" "results: $LOGS/msldap-ops_" "$RESULTS/collect.txt"
check "records contain base64 security descriptors" '^nTSecurityDescriptor: AQAE' "${LOG:-/dev/null}"
check "records contain SIDs in string form" '^objectSid: S-1-5-21-' "${LOG:-/dev/null}"
check "queries are terminated for bofhound" '^Retrieved [0-9]+ results total$' "${LOG:-/dev/null}"
check "query journal has the filter" '"filter": "\(objectCategory=computer\)"' "${QLOG:-/dev/null}"

BEFORE="$(wc -l <"${LOG:-/dev/null}")"
ops logoff.txt login "log off" "query (objectClass=domain) $ATTRS"
AFTER="$(wc -l <"${LOG:-/dev/null}")"
check_cmd "log off stops logging" test "$BEFORE" -eq "$AFTER"

echo
echo "== bofhound import"
(cd "$RESULTS" && uvx bofhound -i "$LOGS" -o "$RESULTS/bofhound" >"$RESULTS/bofhound.txt" 2>&1) || true
parsed() { grep -oE "Parsed [0-9]+ $1" "$RESULTS/bofhound.txt" | grep -oE '[0-9]+' | head -n 1; }
for kind in Users Groups Computers Domains "Cert Templates" "Enterprise CAs"; do
  n="$(parsed "$kind" || true)"
  check_cmd "bofhound parsed ${n:-0} $kind" test "${n:-0}" -gt 0
done
check_cmd "bofhound knows $LOWPRIV_USER with ACEs" "$PY" - "$RESULTS/bofhound" "$LOWPRIV_USER" <<'EOF'
import glob, json, sys
out, user = sys.argv[1:]
for f in glob.glob(out + '/users_*.json'):
  for o in json.load(open(f))['data']:
    if o['Properties'].get('samaccountname', '').lower() == user.lower():
      sys.exit(0 if o.get('Aces') else 1)
sys.exit(1)
EOF

echo
echo "== summary"
echo "   checks: $PASS passed, $FAIL failed"
echo "   full output: $RESULTS"
