#!/usr/bin/env bash
#
# Tests msldap-ops against a GOAD lab: runs queries with query logging enabled and imports the
# resulting log with bofhound. Meant to be run on a host that can reach the lab.
#
# Usage:
#   dev/goad-test-ops.sh
#
# Uses the same configuration as goad-test-msldap.sh (dev/goad.env, see dev/goad.env.example):
# NORTH_DC, ROOT_DC, LOWPRIV_USER, LOWPRIV_PASS, ROOT_USER, ROOT_PASS. msldap is taken from the checkout configured in
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
ROOT_DC="${ROOT_DC:-192.168.56.10}"
ROOT_USER="${ROOT_USER:-cersei.lannister}"
ROOT_PASS="${ROOT_PASS:-il0vejaime}"

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
mkurl() { # mkurl <domain> <user> <pass> <host>
  "$PY" -c 'import sys; from urllib.parse import quote; d,u,p,h=sys.argv[1:]; print("ldap+ntlm-password://%s\\%s:%s@%s" % (d, quote(u, safe=""), quote(p, safe=""), h))' "$@"
}
URL="$(mkurl NORTH "$LOWPRIV_USER" "$LOWPRIV_PASS" "$NORTH_DC")"
ROOT_URL="$(mkurl SEVENKINGDOMS "$ROOT_USER" "$ROOT_PASS" "$ROOT_DC")"

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

ATTRS='*,nTSecurityDescriptor'

echo
echo "== bofhound_collect presets"
ops collect.txt login "bofhound_collect all" "bofhound_collect dns" "query (sAMAccountName=$LOWPRIV_USER) $ATTRS" log
check "bofhound_collect all runs without failed queries" '^[0-9]+ objects from [0-9]+ queries, 0 failed$' "$RESULTS/collect.txt"
check "bofhound_collect dns returns DNS nodes" '^  dns/DNS nodes \(domain zones\) +[1-9]' "$RESULTS/collect.txt"

echo
echo "== query logging"
LOG="$(ls "$LOGS"/msldap-ops_*.log 2>/dev/null | head -n 1 || true)"
QLOG="$(ls "$LOGS"/msldap-ops-queries_*.jsonl 2>/dev/null | head -n 1 || true)"
check_cmd "log file written to --log-dir" test -s "${LOG:-/nonexistent}"
check_cmd "query journal written" test -s "${QLOG:-/nonexistent}"
check "log command shows the log location" "results: $LOGS/msldap-ops_" "$RESULTS/collect.txt"
check "records contain base64 security descriptors" '^nTSecurityDescriptor: AQAE' "${LOG:-/dev/null}"
check "records contain SIDs in string form" '^objectSid: S-1-5-21-' "${LOG:-/dev/null}"
check "records contain schema GUIDs" '^schemaIDGUID: [0-9a-f]{8}-' "${LOG:-/dev/null}"
check "queries are terminated for bofhound" '^Retrieved [0-9]+ results total$' "${LOG:-/dev/null}"
check "query journal has the filter" "\"filter\": \"\\(sAMAccountName=$LOWPRIV_USER\\)\"" "${QLOG:-/dev/null}"

BEFORE="$(wc -l <"${LOG:-/dev/null}")"
# 'log off' before login, the login itself runs queries as well
ops logoff.txt "log off" login "query (objectClass=domain) $ATTRS"
AFTER="$(wc -l <"${LOG:-/dev/null}")"
check_cmd "log off stops logging" test "$BEFORE" -eq "$AFTER"

echo
echo "== privileged accounts (find_admins)"
"$OPS" --no-log "$URL" login find_admins >"$RESULTS/admins-north.txt" 2>&1 || true
check "Domain Admins found by SID" '^  [^ ].* \(S-1-5-21-[0-9-]+-512\): [1-9][0-9]* accounts?$' "$RESULTS/admins-north.txt"
check "eddard.stark is a privileged account" '^  eddard\.stark +user ' "$RESULTS/admins-north.txt"
check "Enterprise Admins explained on the child domain" 'Enterprise Admins \(S-1-5-21-[0-9-]+-519\): lives in the forest root' "$RESULTS/admins-north.txt"
check "Administrators lists the forest root group as other-domain member" '\(other domain\) +direct CN=Enterprise Admins,' "$RESULTS/admins-north.txt"
check "report completes" '^adminCount=1 users outside the privileged groups: [0-9]+$' "$RESULTS/admins-north.txt"
check_cmd "no error section" bash -c "! grep -q '^Errors:' '$RESULTS/admins-north.txt'"

"$OPS" --no-log "$ROOT_URL" login find_admins >"$RESULTS/admins-root.txt" 2>&1 || true
check "Enterprise Admins listed on the forest root" '^  [^ ].* \(S-1-5-21-[0-9-]+-519\): [1-9][0-9]* accounts?$' "$RESULTS/admins-root.txt"
check "Schema Admins listed on the forest root" '^  [^ ].* \(S-1-5-21-[0-9-]+-518\): [0-9]+ accounts?$' "$RESULTS/admins-root.txt"
check "name search runs" "^Name or description contains 'adm', outside the privileged groups: [0-9]+$" "$RESULTS/admins-north.txt"
echo "   INFO  $(grep -E "^Name or description contains" "$RESULTS/admins-north.txt" || true)"
echo "   INFO  findings on north: $(grep -oE '(kerberoastable|asrep-roastable|password-never-expires|unconstrained-delegation|delegable|password-not-required)' "$RESULTS/admins-north.txt" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"

echo
echo "== bofhound import"
# dnsNode parsing needs bofhound >= 0.4.21; without a version uvx may reuse an older cached one
BOFHOUND=(uvx --from 'bofhound>=0.4.21' bofhound)
echo "   bofhound $("${BOFHOUND[@]:0:3}" python -c 'import importlib.metadata as m; print(m.version("bofhound"))' 2>/dev/null || echo '?')"
(cd "$RESULTS" && "${BOFHOUND[@]}" -i "$LOGS" -o "$RESULTS/bofhound" >"$RESULTS/bofhound.txt" 2>&1) || true
parsed() { grep -oE "Parsed [0-9]+ $1" "$RESULTS/bofhound.txt" | grep -oE '[0-9]+' | head -n 1; }
for kind in Users Groups Computers Domains "Trust Accounts" OUs Containers GPOs "Enterprise CAs" \
  "AIA CAs" "Root CAs" "NTAuth Stores" "Cert Templates" Schemas Referrals "DNS nodes"; do
  n="$(parsed "$kind" || true)"
  check_cmd "bofhound parsed ${n:-0} $kind" test "${n:-0}" -gt 0
done
echo "   INFO  bofhound parsed $(parsed "Issuance Policies" || echo 0) Issuance Policies (only those with flags=2 count)"
echo "   INFO  bofhound unknown objects: $(parsed "Unknown Objects" || echo 0)"
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
