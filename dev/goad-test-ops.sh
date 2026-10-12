#!/usr/bin/env bash
#
# Tests msldap-ops against a GOAD lab: runs queries with query logging enabled and imports the
# resulting log with bofhound. Meant to be run on a host that can reach the lab.
#
# Usage:
#   dev/goad-test-ops.sh
#
# Uses the same configuration as goad-test-msldap.sh (dev/goad.env, see dev/goad.env.example):
# MSLDAP_DIR (msldap checkout to test, default ../msldap; MSLDAP_DIR=git uses the locked git version),
# NORTH_DC, ROOT_DC, ESSOS_DC, LOWPRIV_USER, LOWPRIV_PASS, ROOT_USER, ROOT_PASS,
# ESSOS_LOWPRIV_USER, ESSOS_LOWPRIV_PASS. msldap is taken from the checkout configured in
# MSLDAP_DIR, bofhound is run via uvx.
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
ESSOS_DC="${ESSOS_DC:-192.168.56.12}"
ESSOS_LOWPRIV_USER="${ESSOS_LOWPRIV_USER:-khal.drogo}"
ESSOS_LOWPRIV_PASS="${ESSOS_LOWPRIV_PASS:-horse}"
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
MSLDAP_DIR="${MSLDAP_DIR:-$REPO_ROOT/../msldap}"
if [[ "$MSLDAP_DIR" != "git" && -d "$MSLDAP_DIR" ]]; then
  # the local checkout replaces the git dependency in the venv until the next 'uv sync' / 'uv run'
  uv pip install -q --python "$REPO_ROOT/.venv/bin/python" -e "$MSLDAP_DIR"
  echo "   msldap:   $MSLDAP_DIR ($(git -C "$MSLDAP_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null) $(git -C "$MSLDAP_DIR" rev-parse --short HEAD 2>/dev/null))"
else
  echo "   msldap:   git dependency from uv.lock"
fi
OPS="$REPO_ROOT/.venv/bin/msldap-ops"
PY="$REPO_ROOT/.venv/bin/python"
mkurl() { # mkurl <domain> <user> <pass> <host>
  "$PY" -c 'import sys; from urllib.parse import quote; d,u,p,h=sys.argv[1:]; print("ldap+ntlm-password://%s\\%s:%s@%s" % (d, quote(u, safe=""), quote(p, safe=""), h))' "$@"
}
URL="$(mkurl NORTH "$LOWPRIV_USER" "$LOWPRIV_PASS" "$NORTH_DC")"
ROOT_URL="$(mkurl SEVENKINGDOMS "$ROOT_USER" "$ROOT_PASS" "$ROOT_DC")"
ESSOS_URL="$(mkurl ESSOS "$ESSOS_LOWPRIV_USER" "$ESSOS_LOWPRIV_PASS" "$ESSOS_DC")"

ops() { # ops <outfile> <commands...>
  local out="$1"
  shift
  "$OPS" --no-cache --log-dir "$LOGS" "$URL" "$@" >"$RESULTS/$out" 2>&1 || true
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
"$OPS" --no-cache --no-log "$URL" login find_admins >"$RESULTS/admins-north.txt" 2>&1 || true
check "Domain Admins found by SID" '^  [^ ].* \(S-1-5-21-[0-9-]+-512\): [1-9][0-9]* accounts?$' "$RESULTS/admins-north.txt"
check "eddard.stark is a privileged account" '^  eddard\.stark +user ' "$RESULTS/admins-north.txt"
check "Enterprise Admins explained on the child domain" 'Enterprise Admins \(S-1-5-21-[0-9-]+-519\): lives in the forest root' "$RESULTS/admins-north.txt"
check "Administrators lists the forest root group as other-domain member" '\(other domain\) +direct +CN=Enterprise Admins,' "$RESULTS/admins-north.txt"
check "report completes" '^adminCount=1 users outside the privileged groups: [0-9]+$' "$RESULTS/admins-north.txt"
check_cmd "no error section" bash -c "! grep -q '^Errors:' '$RESULTS/admins-north.txt'"

"$OPS" --no-cache --no-log "$ROOT_URL" login find_admins >"$RESULTS/admins-root.txt" 2>&1 || true
check "Enterprise Admins listed on the forest root" '^  [^ ].* \(S-1-5-21-[0-9-]+-519\): [1-9][0-9]* accounts?$' "$RESULTS/admins-root.txt"
check "Schema Admins listed on the forest root" '^  [^ ].* \(S-1-5-21-[0-9-]+-518\): [0-9]+ accounts?$' "$RESULTS/admins-root.txt"
check "name search runs" "^Name or description contains 'adm', outside the privileged groups: [0-9]+$" "$RESULTS/admins-north.txt"
echo "   INFO  $(grep -E "^Name or description contains" "$RESULTS/admins-north.txt" || true)"
echo "   INFO  findings on north: $(grep -oE '(kerberoastable|asrep-roastable|password-never-expires|unconstrained-delegation|delegable|password-not-required)' "$RESULTS/admins-north.txt" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"

echo
echo "== certificate templates"
"$OPS" --no-cache --no-log --opsec show "$URL" login templates "templates User" >"$RESULTS/templates-north.txt" 2>&1 || true
check "table of templates" '^  Name +CAs +Client Auth +Enrollee Subject +Approval +Vulnerabilities$' "$RESULTS/templates-north.txt"
check "checked for the bound user" "^Vulnerabilities checked for NORTH\\\\$LOWPRIV_USER\\." "$RESULTS/templates-north.txt"
check "User template flags decoded one per line" '^  Certificate Name Flag +: SUBJECT_ALT_REQUIRE_UPN$' "$RESULTS/templates-north.txt"
check "template table needs 4 searches" '^\[opsec\] templates: 4 LDAP queries sent$' "$RESULTS/templates-north.txt"
"$OPS" --no-cache --no-log "$ESSOS_URL" login "templates vulnerable" >"$RESULTS/templates-essos.txt" 2>&1 || true
check "essos: ESC1 template marked" '^  Enrollee Supplies Subject +: True \[!\]$' "$RESULTS/templates-essos.txt"
check "essos: ESC1 reported for $ESSOS_LOWPRIV_USER" "^  \\[!\\] Vulnerabilities for ESSOS\\\\$ESSOS_LOWPRIV_USER" "$RESULTS/templates-essos.txt"
check "essos: ESC1 finding" '^    ESC1 +: ' "$RESULTS/templates-essos.txt"
echo "   INFO  essos vulnerable templates: $(grep -E '^Template ' "$RESULTS/templates-essos.txt" | cut -d' ' -f2 | tr '\n' ' ')"
echo "   INFO  essos findings: $(grep -oE '^    ESC[0-9]+' "$RESULTS/templates-essos.txt" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"

echo
echo "== opsec"
"$OPS" --no-cache --no-log --opsec show "$URL" login find_admins >"$RESULTS/opsec-show.txt" 2>&1 || true
check "show prints the queries before they are sent" '^\[ldap #1\] DC=' "$RESULTS/opsec-show.txt"
check "show reports the number of queries per command" '^\[opsec\] find_admins: [0-9]+ LDAP quer(y|ies) sent$' "$RESULTS/opsec-show.txt"
echo "   INFO  $(grep -E '^\[opsec\] (login|find_admins):' "$RESULTS/opsec-show.txt" | tr '\n' ';')"
"$OPS" --no-cache --no-log --opsec show "$URL" login "cd CN=Computers" >"$RESULTS/opsec-cd.txt" 2>&1 || true
check "cd shows its query" '^\[ldap #1\] CN=Computers,DC=' "$RESULTS/opsec-cd.txt"
check_cmd "cd sends a single query (msldap get_tree_plot fix)" bash -c "! grep -qE '^\[ldap #2\] CN=[^,]+,CN=Computers,' '$RESULTS/opsec-cd.txt'"
"$OPS" --no-cache --no-log "$URL" login "opsec dryrun" "bofhound_collect all" >"$RESULTS/opsec-dryrun.txt" 2>&1 || true
check "dryrun shows the queries" '^\[dryrun #1\] ' "$RESULTS/opsec-dryrun.txt"
check "dryrun sends nothing" '^0 objects from [0-9]+ queries, 0 failed$' "$RESULTS/opsec-dryrun.txt"
check "dryrun summary" '^\[opsec\] bofhound_collect: [0-9]+ LDAP queries shown, none sent$' "$RESULTS/opsec-dryrun.txt"

echo
echo "== query cache"
CACHE_ARGS=(--no-log --cache-dir "$RESULTS/cache" --opsec show)
"$OPS" "${CACHE_ARGS[@]}" "$URL" login find_admins find_admins cache >"$RESULTS/cache-1.txt" 2>&1 || true
check "second find_admins is answered from the cache" '^\[cache\] ' "$RESULTS/cache-1.txt"
check "the second find_admins sends nothing" '^\[opsec\] find_admins: no LDAP queries sent, [1-9][0-9]* answered from the cache$' "$RESULTS/cache-1.txt"
check "cache command shows hits" '^  [0-9]+ queries \([0-9]+ results\), [0-9]+ DNs known, [1-9][0-9]* hits' "$RESULTS/cache-1.txt"
check_cmd "cache file written" bash -c "ls '$RESULTS/cache/'*.json >/dev/null 2>&1"
"$OPS" "${CACHE_ARGS[@]}" "$URL" login find_admins >"$RESULTS/cache-2.txt" 2>&1 || true
check "a new session reuses the persisted cache" '^\[opsec\] find_admins: no LDAP queries sent, [1-9][0-9]* answered from the cache$' "$RESULTS/cache-2.txt"
"$OPS" "${CACHE_ARGS[@]}" "$URL" login "cache flush" find_admins >"$RESULTS/cache-3.txt" 2>&1 || true
check "flush empties the cache" '^Dropped [0-9]+ cached quer(y|ies) and the DN index$' "$RESULTS/cache-3.txt"
check "after a flush the queries are sent again" '^\[opsec\] find_admins: [0-9]+ LDAP quer(y|ies) sent$' "$RESULTS/cache-3.txt"
"$OPS" "${CACHE_ARGS[@]}" "$URL" login "cache flush" "bofhound_collect adcs" templates >"$RESULTS/cache-4.txt" 2>&1 || true
check "templates reuses the ADCS data of bofhound_collect" '^\[opsec\] templates: 2 LDAP queries sent, 2 answered from the cache$' "$RESULTS/cache-4.txt"

echo
echo "== delegation"
"$OPS" --no-cache --no-log "$URL" login delegations >"$RESULTS/deleg.txt" 2>&1 || true
check "delegation overview has all three sections" 'Resource-based constrained delegation' "$RESULTS/deleg.txt"
INFO_DELEG=$(grep -E '^(Unconstrained|Constrained|Resource-based)' "$RESULTS/deleg.txt" | tr '\n' ';')
echo "   INFO  $INFO_DELEG"

echo
echo "== navigation"
"$OPS" --no-log --cache-dir "$RESULTS/cache-nav" "$URL" login "cd .." "cd CN=Users" "cd .." "map . 2" \
  "cd CN=Configuration,DC=sevenkingdoms,DC=local" map "cd ../.." >"$RESULTS/navigation.txt" 2>&1 || true
check "cd .. at the domain root is explained" 'is the top of its naming context on this DC\. Naming contexts of this DC: ' "$RESULTS/navigation.txt"
check "map shows what cd has seen" '^(\||`)-- CN=Users$' "$RESULTS/navigation.txt"
check "map shows children of CN=Users" '^(\| |  )  (\||`)-- CN=' "$RESULTS/navigation.txt"
check "cd into another naming context (Configuration)" '^(\||`)-- CN=Schema$' "$RESULTS/navigation.txt"
check "cd ../.. above the Configuration NC is refused" 'CN=Configuration,DC=sevenkingdoms,DC=local is the top of its naming context' "$RESULTS/navigation.txt"
check_cmd "no raw referral errors" bash -c "! grep -q 'referral' '$RESULTS/navigation.txt'"
"$OPS" --no-log --no-cache "$URL" login "cat . name" "cat * name" "cd CN=Users" "cat CN=Domain* cn" \
  "cat ../CN=Builtin name" "cat CN=nosuchobject" "ls ../CN=Builtin" "ls Domain*" >"$RESULTS/cat.txt" 2>&1 || true
check "cat . shows the current object" '^DN: DC=north,DC=sevenkingdoms,DC=local$' "$RESULTS/cat.txt"
check "cat * shows every child" '^DN: CN=Users,DC=north,DC=sevenkingdoms,DC=local$' "$RESULTS/cat.txt"
check "cat with a pattern" '^DN: CN=Domain Admins,CN=Users,DC=north,DC=sevenkingdoms,DC=local$' "$RESULTS/cat.txt"
check "cat with a relative path" '^DN: CN=Builtin,DC=north,DC=sevenkingdoms,DC=local$' "$RESULTS/cat.txt"
check "cat of a missing object is explained" '^No such object: CN=nosuchobject,CN=Users,DC=north' "$RESULTS/cat.txt"
check "ls with a path" '^CN=Administrators$' "$RESULTS/cat.txt"
check "ls with a pattern" '^CN=Domain Controllers$' "$RESULTS/cat.txt"
"$OPS" --no-log --no-cache "$URL" login "find jon.sn*" "find 'Domain Admins'" "acl" "acl CN=Users explicit" "getsd ." "acl CN=Domain Admins,CN=Users risky" >"$RESULTS/acl.txt" 2>&1 || true
check "find by account name pattern" '^user +jon\.snow +CN=jon\.snow,' "$RESULTS/acl.txt"
check "find by name" '^group +Domain Admins +CN=Domain Admins,CN=Users,DC=north' "$RESULTS/acl.txt"
check "acl of the domain object" '^ACL of DC=north,DC=sevenkingdoms,DC=local$' "$RESULTS/acl.txt"
check "acl decodes the DCSync rights" 'ExtendedRight +Replicating Directory Changes All ' "$RESULTS/acl.txt"
check "acl resolves principals" '^  allow .*\\Domain Admins ' "$RESULTS/acl.txt"
check "getsd accepts paths" '^O:[A-Z0-9-]+G:' "$RESULTS/acl.txt"
"$OPS" --no-log --opsec show --cache-dir "$RESULTS/cache-acl" "$URL" login "cache flush" "bofhound_collect domain,users,groups" acl >"$RESULTS/acl-cache.txt" 2>&1 || true
check "acl takes the security descriptor from bofhound_collect" '^ACL of DC=north,DC=sevenkingdoms,DC=local  \(from the cache, ' "$RESULTS/acl-cache.txt"
echo "   INFO  $(grep -E '^\[opsec\] acl:' "$RESULTS/acl-cache.txt" || echo 'acl: no LDAP queries')"
check_cmd "no tracebacks in acl/getsd" bash -c "! grep -q 'Traceback' '$RESULTS/acl.txt'"

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
