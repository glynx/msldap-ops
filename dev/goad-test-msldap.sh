#!/usr/bin/env bash
#
# Runs the msldap fork's live test suite and some CLI smoke tests against a
# GOAD lab. Meant to be run on a host that can reach the lab.
#
# Usage:
#   dev/goad-test-msldap.sh             # test the fix branch
#   dev/goad-test-msldap.sh --compare   # additionally run the suite on upstream main as a baseline
#
# Configuration (environment variables, defaults match a stock GOAD install):
#   MSLDAP_DIR      msldap checkout              (default: ../msldap next to this repo)
#   BRANCH          branch to test               (default: fix/query-improvements)
#   BASE_BRANCH     baseline for --compare       (default: main)
#   NORTH_DC        child domain DC              (default: 192.168.56.11, north.sevenkingdoms.local)
#   ROOT_DC         forest root DC               (default: 192.168.56.10, sevenkingdoms.local)
#   ESSOS_DC        second forest DC             (default: 192.168.56.12, essos.local)
#   LAB_USER / LAB_PASS                privileged account, valid on all three DCs (default: vagrant / vagrant)
#   LOWPRIV_USER / LOWPRIV_PASS        unprivileged NORTH account (default: samwell.tarly / Heartsbane)
#
# Results end up in dev/results/<timestamp>/ (git-ignored).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
MSLDAP_DIR="${MSLDAP_DIR:-$(cd "$REPO_ROOT/../msldap" && pwd)}"
BRANCH="${BRANCH:-fix/query-improvements}"
BASE_BRANCH="${BASE_BRANCH:-main}"
NORTH_DC="${NORTH_DC:-192.168.56.11}"
ROOT_DC="${ROOT_DC:-192.168.56.10}"
ESSOS_DC="${ESSOS_DC:-192.168.56.12}"
LAB_USER="${LAB_USER:-vagrant}"
LAB_PASS="${LAB_PASS:-vagrant}"
LOWPRIV_USER="${LOWPRIV_USER:-samwell.tarly}"
LOWPRIV_PASS="${LOWPRIV_PASS:-Heartsbane}"

COMPARE=0
[[ "${1:-}" == "--compare" ]] && COMPARE=1

RESULTS="$HERE/results/$(date +%Y%m%d-%H%M%S)"
WORK="$HERE/.work"
mkdir -p "$RESULTS" "$WORK"
exec > >(tee "$RESULTS/run.log") 2>&1

command -v uv >/dev/null || { echo "uv not found (pacman -S uv)"; exit 1; }

echo "== msldap GOAD test run $(date -Is)"
echo "   msldap:   $MSLDAP_DIR ($BRANCH)"
echo "   results:  $RESULTS"

# --- reachability ------------------------------------------------------------
for dc in "$NORTH_DC" "$ROOT_DC" "$ESSOS_DC"; do
	if timeout 3 bash -c "</dev/tcp/$dc/389" 2>/dev/null; then
		echo "   $dc:389 reachable"
	else
		echo "   $dc:389 NOT reachable (tests needing it will be skipped)"
	fi
done

# --- profile (temporary, contains lab credentials) ---------------------------
PROFILE="$(mktemp --suffix=.yml)"
trap 'rm -f "$PROFILE"' EXIT
cat >"$PROFILE" <<EOF
target:
  host: $NORTH_DC
  protocol: ldap
  port: null
  dc_ip: $NORTH_DC
tree: null
authentication:
  method: ntlm-password
  domain: NORTH
  username: $LAB_USER
  password: $LAB_PASS
params: {}
extra_targets:
  root:
    host: $ROOT_DC
    domain: SEVENKINGDOMS
  essos:
    host: $ESSOS_DC
    domain: ESSOS
safety:
  disposable: true
  allow_destructive: false
EOF
export MSLDAP_TEST_PROFILE="$PROFILE"

# --- helpers -----------------------------------------------------------------
# prepare_checkout <name> <branch>: worktree + venv, prints the worktree path
prepare_checkout() {
	local name="$1" branch="$2" wt="$WORK/msldap-$1"
	if [[ -d "$wt" ]]; then
		git -C "$wt" checkout -q --detach "$branch"
	else
		git -C "$MSLDAP_DIR" worktree add -q --detach "$wt" "$branch"
	fi
	uv venv -q --allow-existing "$wt/.venv"
	uv pip install -q --python "$wt/.venv/bin/python" -e "$wt" -r "$wt/requirements-test.txt"
	echo "$wt"
}

run_live_suite() {
	local name="$1" wt="$2"
	echo
	echo "== live suite: $name ($(git -C "$wt" log -1 --format='%h %s'))"
	(cd "$wt" && .venv/bin/python -m pytest tests/interop/live --run-live -ra -q \
		-p no:cacheprovider --junitxml="$RESULTS/live-$name.xml") \
		| tee "$RESULTS/live-$name.txt" || true
}

PASS=0
FAIL=0
check() { # check <description> <pattern> <file>
	if grep -qE "$2" "$3"; then
		echo "   PASS  $1"; PASS=$((PASS+1))
	else
		echo "   FAIL  $1 (see $(basename "$3"))"; FAIL=$((FAIL+1))
	fi
}

# --- fix branch ----------------------------------------------------------------
WT="$(prepare_checkout fix "$BRANCH")"
run_live_suite fix "$WT"

echo
echo "== CLI smoke tests (query command)"
PY="$WT/.venv/bin/python"
mkurl() { # mkurl <domain> <user> <pass> <host>
	"$PY" -c 'import sys; from urllib.parse import quote; d,u,p,h=sys.argv[1:]; print("ldap+ntlm-password://%s\\%s:%s@%s" % (d, quote(u, safe=""), quote(p, safe=""), h))' "$@"
}
msldap_cli() { # msldap_cli <outfile> <url> <commands...>
	local out="$1"; shift
	"$PY" -m msldap.examples.msldapclient -n "$@" >"$RESULTS/$out" 2>&1 || true
}
LOW_URL="$(mkurl NORTH "$LOWPRIV_USER" "$LOWPRIV_PASS" "$NORTH_DC")"

msldap_cli cli-query-default.txt "$LOW_URL" login "query (sAMAccountName=$LOWPRIV_USER)"
check "query without attribute list returns all attributes" '^  (sAMAccountName|objectSid):' "$RESULTS/cli-query-default.txt"

msldap_cli cli-query-scope.txt "$LOW_URL" login "query (objectClass=*) cn CN=Users,DC=north,DC=sevenkingdoms,DC=local base"
check "query with base DN + scope=base returns exactly that object" '^DN: CN=Users,DC=north' "$RESULTS/cli-query-scope.txt"

msldap_cli cli-query-sd.txt "$LOW_URL" login "query (sAMAccountName=$LOWPRIV_USER) nTSecurityDescriptor"
check "nTSecurityDescriptor readable as low-priv user (SD flags control)" '^  nTSecurityDescriptor: O:' "$RESULTS/cli-query-sd.txt"

msldap_cli cli-query-badscope.txt "$LOW_URL" login "query (cn=x) cn - bogus"
check "invalid scope is rejected" 'Unknown scope' "$RESULTS/cli-query-badscope.txt"

# --- optional baseline -----------------------------------------------------------
if [[ $COMPARE -eq 1 ]]; then
	BWT="$(prepare_checkout base "$BASE_BRANCH")"
	run_live_suite base "$BWT"
fi

# --- summary ---------------------------------------------------------------------
echo
echo "== summary"
for f in "$RESULTS"/live-*.txt; do
	echo "   $(basename "$f" .txt): $(tail -n 1 "$f")"
done
echo "   CLI smoke tests: $PASS passed, $FAIL failed"
echo "   full output: $RESULTS"
