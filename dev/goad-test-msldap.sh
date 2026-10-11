#!/usr/bin/env bash
#
# Runs the msldap fork's live test suite and some CLI smoke tests against a
# GOAD lab. Meant to be run on a host that can reach the lab.
#
# Usage:
#   dev/goad-test-msldap.sh             # test the fix branch
#   dev/goad-test-msldap.sh --compare   # additionally run everything on upstream main as a baseline
#
# Configuration: environment variables, or put them into dev/goad.env (git-ignored,
# see dev/goad.env.example). Defaults match a stock GOAD install.
#   MSLDAP_DIR      msldap checkout              (default: ../msldap next to this repo)
#   BRANCH          branch to test               (default: fork-main = upstream main + all our branches)
#   BASE_BRANCH     baseline for --compare       (default: main)
#   NORTH_DC / ROOT_DC / ESSOS_DC                DC addresses of north.sevenkingdoms.local,
#                                                sevenkingdoms.local and essos.local
#   NORTH_USER / NORTH_PASS                      privileged accounts per domain, used by the
#   ROOT_USER / ROOT_PASS                        live suite (defaults: GOAD domain admins that may use NTLM;
#   ESSOS_USER / ESSOS_PASS                      robert.baratheon is in Protected Users)
#   LOWPRIV_USER / LOWPRIV_PASS                  unprivileged NORTH account for the CLI tests
#   ESSOS_LOWPRIV_USER / ESSOS_LOWPRIV_PASS      unprivileged ESSOS account (ADCS checks against ESSOS-CA)
#
# Results end up in dev/results/<timestamp>/ (git-ignored).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$HERE/goad.env" ]] && source "$HERE/goad.env"

MSLDAP_DIR="${MSLDAP_DIR:-$(cd "$REPO_ROOT/../msldap" && pwd)}"
BRANCH="${BRANCH:-fork-main}"
BASE_BRANCH="${BASE_BRANCH:-main}"
NORTH_DC="${NORTH_DC:-192.168.56.11}"
ROOT_DC="${ROOT_DC:-192.168.56.10}"
ESSOS_DC="${ESSOS_DC:-192.168.56.12}"
NORTH_USER="${NORTH_USER:-eddard.stark}"
NORTH_PASS="${NORTH_PASS:-FightP3aceAndHonor!}"
ROOT_USER="${ROOT_USER:-cersei.lannister}"
ROOT_PASS="${ROOT_PASS:-il0vejaime}"
ESSOS_USER="${ESSOS_USER:-daenerys.targaryen}"
ESSOS_PASS="${ESSOS_PASS:-BurnThemAll!}"
LOWPRIV_USER="${LOWPRIV_USER:-samwell.tarly}"
LOWPRIV_PASS="${LOWPRIV_PASS:-Heartsbane}"
ESSOS_LOWPRIV_USER="${ESSOS_LOWPRIV_USER:-khal.drogo}"
ESSOS_LOWPRIV_PASS="${ESSOS_LOWPRIV_PASS:-horse}"

COMPARE=0
[[ "${1:-}" == "--compare" ]] && COMPARE=1

RESULTS="$HERE/results/$(date +%Y%m%d-%H%M%S)"
WORK="$HERE/.work"
mkdir -p "$RESULTS" "$WORK"
exec > >(tee "$RESULTS/run.log") 2>&1

command -v uv >/dev/null || {
  echo "uv not found (pacman -S uv)"
  exit 1
}

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
# YAML single-quoted scalar, embedded quotes doubled
yaml_str() { printf "'%s'" "${1//\'/\'\'}"; }
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
  username: $(yaml_str "$NORTH_USER")
  password: $(yaml_str "$NORTH_PASS")
params: {}
extra_targets:
  root:
    host: $ROOT_DC
    domain: SEVENKINGDOMS
    username: $(yaml_str "$ROOT_USER")
    password: $(yaml_str "$ROOT_PASS")
  essos:
    host: $ESSOS_DC
    domain: ESSOS
    username: $(yaml_str "$ESSOS_USER")
    password: $(yaml_str "$ESSOS_PASS")
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
    -p no:cacheprovider --junitxml="$RESULTS/live-$name.xml") |
    tee "$RESULTS/live-$name.txt" || true
}

mkurl() { # mkurl <python> <domain> <user> <pass> <host>
  local py="$1"
  shift
  "$py" -c 'import sys; from urllib.parse import quote; d,u,p,h=sys.argv[1:]; print("ldap+ntlm-password://%s\\%s:%s@%s" % (d, quote(u, safe=""), quote(p, safe=""), h))' "$@"
}

msldap_cli() { # msldap_cli <python> <outfile> <url> <commands...>
  local py="$1" out="$2"
  shift 2
  "$py" -m msldap.examples.msldapclient -n "$@" >"$RESULTS/$out" 2>&1 || true
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

check_absent() { # check_absent <description> <pattern> <file>
  if [[ -s "$3" ]] && ! grep -qE "$2" "$3"; then
    echo "   PASS  $1"
    PASS=$((PASS + 1))
  else
    echo "   FAIL  $1 (see $(basename "$3"))"
    FAIL=$((FAIL + 1))
  fi
}

USERS_DN="CN=Users,DC=north,DC=sevenkingdoms,DC=local"

# --- fix branch ----------------------------------------------------------------
WT="$(prepare_checkout fix "$BRANCH")"
run_live_suite fix "$WT"

echo
echo "== CLI smoke tests (query command)"
PY="$WT/.venv/bin/python"
LOW_URL="$(mkurl "$PY" NORTH "$LOWPRIV_USER" "$LOWPRIV_PASS" "$NORTH_DC")"

msldap_cli "$PY" cli-query-default.txt "$LOW_URL" login "query (sAMAccountName=$LOWPRIV_USER)"
check "query without attribute list returns all attributes" '^  (sAMAccountName|objectSid):' "$RESULTS/cli-query-default.txt"

msldap_cli "$PY" cli-query-scope.txt "$LOW_URL" login "query (objectClass=*) cn $USERS_DN base"
check "query with base DN + scope=base returns exactly that object" "^DN: $USERS_DN" "$RESULTS/cli-query-scope.txt"

msldap_cli "$PY" cli-query-sd.txt "$LOW_URL" login "query (sAMAccountName=$LOWPRIV_USER) nTSecurityDescriptor"
check "nTSecurityDescriptor readable as low-priv user (SD flags control)" '^  nTSecurityDescriptor: O:' "$RESULTS/cli-query-sd.txt"

msldap_cli "$PY" cli-query-badscope.txt "$LOW_URL" login "query (cn=x) cn - bogus"
check "invalid scope is rejected" 'Unknown scope' "$RESULTS/cli-query-badscope.txt"

echo
echo "== CLI smoke tests (SID resolution)"
msldap_cli "$PY" cli-certtemplates.txt "$LOW_URL" login certtemplates
check "certtemplates resolves forest root principals" 'SEVENKINGDOMS\\Enterprise Admins' "$RESULTS/cli-certtemplates.txt"
check_absent "certtemplates has no unresolved SIDs" '\?\?\?\\\?\?\?' "$RESULTS/cli-certtemplates.txt"

msldap_cli "$PY" cli-whoami.txt "$LOW_URL" login whoami
check "whoami resolves builtin aliases" 'S-1-5-32-555 \(BUILTIN\\Remote Desktop Users\)' "$RESULTS/cli-whoami.txt"
check_absent "whoami has no unresolved SIDs" '\?\?\?\\\?\?\?' "$RESULTS/cli-whoami.txt"

echo
echo "== CLI smoke tests (help)"
msldap_cli "$PY" cli-help.txt "$LOW_URL" "help whoami" "certtemplates -h"
check "help <command> shows usage" '^Usage: whoami' "$RESULTS/cli-help.txt"
check "<command> -h shows usage without internal params" '^Usage: certtemplates \[name\]$' "$RESULTS/cli-help.txt"

echo
echo "== CLI smoke tests (certify2)"
msldap_cli "$PY" cli-certify2-north.txt "$LOW_URL" login certify2
check "certify2 reports a result on north (vulns or explicit none)" '^(Template Name:|No vulnerable templates found)' "$RESULTS/cli-certify2-north.txt"

ESSOS_LOW_URL="$(mkurl "$PY" ESSOS "$ESSOS_LOWPRIV_USER" "$ESSOS_LOWPRIV_PASS" "$ESSOS_DC")"
msldap_cli "$PY" cli-certify2-essos.txt "$ESSOS_LOW_URL" login certify2
check "certify2 finds ESC1 on essos" 'ESC1 - ' "$RESULTS/cli-certify2-essos.txt"

# --- optional baseline -----------------------------------------------------------
if [[ $COMPARE -eq 1 ]]; then
  BWT="$(prepare_checkout base "$BASE_BRANCH")"
  run_live_suite base "$BWT"

  echo
  echo "== CLI baseline ($BASE_BRANCH, informational)"
  BPY="$BWT/.venv/bin/python"
  msldap_cli "$BPY" cli-base-query-sd.txt "$LOW_URL" login "query (sAMAccountName=$LOWPRIV_USER) nTSecurityDescriptor"
  if grep -q '^  nTSecurityDescriptor' "$RESULTS/cli-base-query-sd.txt"; then
    echo "   INFO  baseline returns nTSecurityDescriptor to the low-priv user as well"
  else
    echo "   INFO  baseline returns no nTSecurityDescriptor to the low-priv user"
  fi
  msldap_cli "$BPY" cli-base-certify2-essos.txt "$ESSOS_LOW_URL" login certify2
  echo "   INFO  baseline certify2 on essos finds: $(grep -oE '^\s+ESC[0-9]+' "$RESULTS/cli-base-certify2-essos.txt" | sort -u | tr -d '\t ' | tr '\n' ' ')"
  echo "   INFO  fix branch certify2 on essos finds: $(grep -oE '^\s+ESC[0-9]+' "$RESULTS/cli-certify2-essos.txt" | sort -u | tr -d '\t ' | tr '\n' ' ')"
fi

# --- summary ---------------------------------------------------------------------
echo
echo "== summary"
for f in "$RESULTS"/live-*.txt; do
  echo "   $(basename "$f" .txt): $(tail -n 1 "$f")"
done
echo "   CLI smoke tests: $PASS passed, $FAIL failed"
echo "   full output: $RESULTS"
