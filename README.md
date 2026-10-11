# msldap-ops

Operator toolkit on top of [msldap](https://github.com/skelsec/msldap), a pure-Python LDAP client
for Active Directory that does not depend on impacket.

Features:

- **Query logging** in a [pyldapsearch](https://github.com/Tw1sm/pyldapsearch)-compatible format, so
  that collected data can be imported into BloodHound with
  [bofhound](https://github.com/coffeegist/bofhound). Logs are written to the current working directory.

- **Collection presets** for bofhound, split per object type (users, computers, groups, OUs, GPOs,
  schema, ADCS, ...), so that no single query returns the whole directory.

- **Query cache** (`cache`): repeated searches are answered from earlier results, persisted per
  server and account.
- **Navigation**: `cd` with relative paths, `..` and completion from everything seen so far, `map`
  as a tree of the known structure.
- **Opsec modes** (`opsec`): show, confirm or suppress every LDAP search before it is sent, for all
  commands including the msldap built-ins.
- **Certificate templates** (`templates`) in a certipy-like layout with decoded flags.
- **Privileged accounts** (`find_admins`): recursive members of the protected groups, found by SID, with
  their risky settings.

- **Extended shell**: all msldap shell commands plus the msldap-ops commands.

msldap-ops currently depends on the [glynx/msldap](https://github.com/glynx/msldap) fork, which carries
fixes that are not (yet) upstream.

## Installation

```bash
uv tool install git+https://github.com/glynx/msldap-ops.git
```

Updates: `uv tool upgrade msldap-ops` (msldap is pulled from the `main` branch of the fork).

## Usage

The connection URL is the same as for msldap:

```bash
msldap-ops 'ldap+ntlm-password://NORTH\user:password@192.168.56.11'
```

Commands can be passed as additional arguments; `i` drops into the interactive shell:

```bash
msldap-ops 'ldap+ntlm-password://NORTH\user:password@192.168.56.11' login 'query (adminCount=1) sAMAccountName'
```

## Query logging

Every search result msldap receives is logged, whether it comes from `query` or from any other
command (`certify2`, `whoami`, ...). The logs go to `./msldap-ops-logs/` in the current directory:

- `msldap-ops_<date>.log`: the results in the pyldapsearch / ldapsearch BOF format
- `msldap-ops-queries_<date>.jsonl`: one line per query with server, base, scope, filter,
  attributes, result count and error

Import them with bofhound:

```bash
bofhound -i msldap-ops-logs/
```

bofhound needs `nTSecurityDescriptor` to build ACL edges, so request it explicitly, for example
`query (sAMAccountType=805306368) *,nTSecurityDescriptor`. The `query` command sends the SD flags
control, so unprivileged users get the owner, group and DACL as well.

## Collecting data for bofhound

`bofhound_collect` runs one query per object type, with `*,nTSecurityDescriptor` and the SD flags control.
The results are not printed, they go to the query log.

```text
bofhound_collect                 list the presets and their queries
bofhound_collect all             everything except DNS
bofhound_collect users,groups    selected presets
bofhound_collect all 5           wait 5 seconds between queries
bofhound_collect dns             DNS nodes (computer IP addresses), not part of 'all'
```

bofhound evaluates DNS nodes since version 0.4.21; older versions list them as unknown objects.

Presets: `domain`, `users`, `computers` (including gMSAs and trust accounts), `groups`, `ous`,
`containers`, `gpos`, `trusts`, `fsps`, `schema`, `adcs` (enterprise CAs, root/AIA CAs, NTAuth store,
templates, issuance policies), `partitions` (NetBIOS names) and `dns`. Base DNs are taken from the
RootDSE, so Configuration and Schema are found on child domain DCs as well.

The presets cover the domain the DC belongs to. For other domains of the forest or trusted forests,
connect to one of their DCs and run `bofhound_collect` again.

## Privileged accounts

`find_admins` lists the recursive members of Domain Admins, Enterprise/Schema/Enterprise Key Admins,
Administrators, Account/Server/Print/Backup Operators, Key Admins, Group Policy Creator Owners,
Domain Controllers and DnsAdmins. Groups are found by SID, so localized names work. Per account:

- `kerberoastable` (user with SPN), `asrep-roastable`, `password-not-required`,
  `password-never-expires`, `unconstrained-delegation` (not reported for DCs)
- `delegable`: neither "sensitive and cannot be delegated" nor in Protected Users
- `disabled`, pwdLastSet and lastLogonTimestamp

It also lists `adminCount=1` users that are no longer in any of these groups, and users, computers
and groups outside the privileged groups whose sAMAccountName, displayName or description contains
`adm` (catches `admin`, `Administrator`, `adm_` accounts, admin workstations, "SQL Admins", ...).
`find_admins <pattern>` uses another pattern, `find_admins -` skips the name search. Direct members from
other domains (foreign security principals, forest root groups) are shown with their DN. The forest
root groups can only be listed on a DC of the forest root.

In the shell, `log` shows the log files, `log off` / `log on` pause and resume logging.
`--log-dir` changes the directory, `--no-log` disables logging completely.

## Certificate templates

```text
templates                 table: CAs, client authentication, enrollee supplies subject,
                          manager approval, vulnerabilities
templates <name>          details of one template
templates vulnerable      details of the published templates with vulnerabilities
templates enabled         details of all published templates
```

The details follow certipy: msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag and
msPKI-Private-Key-Flag decoded one flag per line with the security relevant bits marked `[!]`,
EKUs, manager approval, authorized signatures, validity and renewal period, minimum key size and the
principals of the enrollment and object control permissions. Vulnerabilities (ESC1-4, ESC9) are
checked for the token of the bound user; an account bound through a trust is checked as a low
privileged user of the connected domain. The table needs 4 LDAP searches, the details additionally
resolve the SIDs of the permissions.

## Navigation

```text
cd ..                    parent DN (refused above the naming context of the DC, with a hint)
cd ../..                 two levels up
cd CN=Computers          relative to the current DN, also deeper: OU=Servers,OU=Tier0
cd <DN>                  absolute, any naming context of the DC (e.g. CN=Configuration,...)
ls [path|pattern] [full] children of the current DN (no query) or of a path, e.g. ls CN=Users,
                         ls Domain*, ls ../OU=*; full prints DNs
cat [path] [attributes]  attributes of the current object (cat, cat .), of every child (cat *),
                         of matching children (cat CN=Domain*, cat ../OU=*) or of a DN/path
query <filter> [attributes] [base|path] [base|one|sub]
acl [path] [all|explicit|risky]  readable ACL of an object (owner, rights, object types, scope)
getsd [path] [p|g]       msldap's raw security descriptor, with paths as for cd
map [DN|path] [depth]    tree of the DNs seen so far below a DN (default: current, 3 levels)
tree [DN] [level]        msldap's tree: queried live from the DC
```

`cd` completes the children of the current DN, every DN below it that any command has seen so far
and the naming contexts of the DC. Escaped commas (`CN=Doe\, John`) are handled; completions are
quoted so that aiocmd's argument parsing keeps them intact. `cat` takes attributes as a comma separated
list (`cat * cn,description`); msldap's order `cat [attributes] [path]` works as well. `map` sends no query, it draws the DN
index of the query cache and may therefore be incomplete. `tree` asks the DC (one search per
container down to the level) and fills the cache, so its results show up in `map` as well.

## ACLs

`acl` shows the security descriptor of an object decoded: owner, group and one line per DACL entry
with allow/deny, the principal (resolved by name), the rights (FullControl, GenericWrite, WriteDacl,
WriteProperty, ExtendedRight, ...), the object type the entry is limited to (an attribute like
`member`, an extended right like `Reset Password`, a validated write like `Self-Membership`) and
where it applies (this object, descendants, `user objects`).

```text
ACL of CN=Domain Admins,CN=Users,DC=north,DC=sevenkingdoms,DC=local
  Owner: NORTH\Domain Admins
  Group: NORTH\Domain Admins
  DACL: 24 entries, 9 inherited

  Access        Principal                    Rights         Object           Applies to
  allow         NORTH\jon.snow               WriteProperty  member           this object   [!] Write member
  allow         NORTH\helpdesk               ExtendedRight  Reset Password   user objects  [!] Reset Password
  ...
```

`[!]` marks entries that let a principal outside the privileged groups take over the object: full
control, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, Reset Password, the DCSync rights,
writing `member`, `servicePrincipalName`, `msDS-KeyCredentialLink`,
`msDS-AllowedToActOnBehalfOfOtherIdentity` and similar attributes, adding oneself to a group; and a
non-privileged owner. Privileged are SYSTEM, Enterprise Domain Controllers, Administrators, Account
Operators, Domain Admins, Domain Controllers, Schema/Enterprise Admins, (Enterprise) Key Admins and
Enterprise Read-only Domain Controllers (of any domain in the forest), SELF and CREATOR OWNER.
`acl . risky` shows only the marked entries, `acl . explicit` only the ones not inherited.

Queries: the security descriptor (one base search with the SD flags control, so unprivileged users
get owner and DACL) and one search per SID that is not well-known (cached). Attribute and class
GUIDs are named from a built-in table; others, like the LAPS attributes whose GUIDs differ per
forest, are named if `bofhound_collect` (preset `schema`) put the schema into the cache.

## Query cache

Repeated searches (same base, scope, filter, attributes and controls) within the TTL are answered from
the cache, without contacting the server. A broader cached search answers narrower ones as well
(same filter, base DN at or below the cached one, attributes included explicitly or through `*`):
after `bofhound_collect adcs`, `templates` only asks the server for the token of the bound user. This applies to every command, including the msldap
built-ins. The cache is kept per server and account and written to `./msldap-ops-cache/` as JSON, so
a new session reuses it.

```text
cache                  state, size, hits/misses, cache file
cache list             cached queries with age and number of results
cache flush [text]     drop everything, or the queries whose base DN or filter contains text
cache ttl <seconds>    lifetime of cached results (default 1800, --cache-ttl)
cache on | off         use the cache or always ask the server
```

Not cached: the keepalive, searches a command stopped early, failed searches. add/modify/delete
drop all cached queries. Changes made with other tools show up after the TTL or a `cache flush`.
Searches answered from the cache send nothing, so `opsec confirm` does not ask for them; `opsec`
shows them as one `[cache]` line and counts them separately (`[opsec] find_admins: 2 LDAP queries
sent, 8 answered from the cache`). The query journal records them with `"cached": true`; they are
not written to the bofhound log again. `--cache-memory-only` keeps the cache off the disk, `--no-cache` disables it.

The cache also keeps an index of every DN seen in a result, for navigation.

## Opsec

`opsec <mode>` (or `--opsec show|confirm` on the command line, which also covers the login) controls
what happens before an LDAP search is sent:

- `off`: nothing (default)
- `show`: the query (base, scope, filter, attributes, controls) is printed before it is sent
- `confirm`: the query is printed and needs confirmation: `y` send, `n` skip (the command gets an
  empty result), `a` send all further queries of the running command, `q` abort the command.
  The queries of the navigation commands `cd`, `ls` and `cat` of a single object are only shown;
  `cat *` and `cat` with a pattern search a whole container level and are confirmed.
- `dryrun`: queries are printed but not sent. Commands that build queries on the results of earlier
  ones (e.g. `find_admins`) only show their first stage; `help <command>` lists the queries of the
  msldap-ops commands.

After each command a summary shows what actually happened: queries sent, skipped, where the command
was aborted, and how many searches were answered from the cache. Every query, including skipped ones, is
recorded in the query journal.

The msldap shell sends a keepalive search on the domain object every 10 seconds. msldap-ops uses
300 seconds; `--keepalive SECONDS` changes it, `--keepalive 0` stops it after the login. Keepalive
queries are not shown or confirmed and not written to the bofhound log, only to the journal.

## Output

The prompt (`msldap-ops <DN> >`) is colored so that it stands out from the command output. All output,
including the msldap built-in commands, keeps its plain text layout and gets colors on top. `query`
and `cat` show every object with a separator line, its DN and aligned attribute names, values of
multi-valued attributes below each other (`query` ends with the number of objects); DN and attribute
names are colored, findings and `[!]` marks are red, `delegable` yellow, the queries shown by `opsec`
gray. On the terminal long lines wrap at the value column, and a long DN in the prompt is shortened
(`CN=x,...,DC=essos,DC=local`). Without a terminal (pipes, files) the output is plain text without
wrapping; `--no-color` or the `NO_COLOR` environment variable switch colors off.

Any command's output can go to a file instead of the screen:

```text
query (adminCount=1) sAMAccountName > admins.txt
find_admins >> report.txt
```

The file gets plain text. Opsec queries and questions stay on the screen, so `opsec confirm` works
while redirecting.

## Differences to msldap

msldap-ops keeps msldap's commands, but changes some where msldap's behaviour is not what a shell
user expects:

- `cat` takes the path first: `cat [path] [attributes]`. `cat *` shows every child of the current
  DN (in msldap: all attributes of the current object, now `cat` or `cat .`). msldap's order
  `cat cn,description CN=Users` is still recognized.
- `ls` takes a path or pattern (`ls CN=Users`, `ls Domain*`); msldap's `ls <anything>` (full DNs)
  works as before.
- `cd` resolves `..`, `../..` and relative paths properly, also with escaped commas, and stops at
  the top of the naming context with an explanation instead of a referral error.
- `query` and `cat` print objects in one layout (see [Output](#output)), `query` takes a base path
  and a scope.
- A pasted block of several lines runs one command per line.

## History

The command history is kept across sessions in `~/.local/state/msldap-ops/history` (or
`$XDG_STATE_HOME/msldap-ops/history`), readable by the user only. Commands with secrets - `login`
with a password or hash in the URL, `adduser`, `changeuserpw`, `addcomputer` with a password - are
available in the running session but not written to the file. `--history-file` picks another file,
`--no-history` keeps the history in memory only.

Up/Down search the history for entries starting with the typed text. Ctrl-R opens
[fzf](https://github.com/junegunn/fzf) over the history if it is installed (the typed text is the
initial query), otherwise the built-in reverse search.

## Development

```bash
uv sync
uv run msldap-ops --help
uv run pytest
```

msldap comes from the `main` branch of [glynx/msldap](https://github.com/glynx/msldap), pinned in
`uv.lock` (`uv lock --upgrade-package msldap` picks up new commits). To work against a local msldap
checkout, install it into the venv and run without syncing, otherwise uv puts the locked version back:

```bash
uv pip install -e ../msldap
uv run --no-sync msldap-ops ...
uv run --no-sync pytest
```

`dev/bofhound-roundtrip.py` writes a small log offline that can be imported with `uvx bofhound` to
check the format.

### Testing msldap-ops against GOAD

`dev/goad-test-ops.sh` runs queries against a GOAD lab with logging enabled and imports the log with
bofhound (via `uvx`). It uses the same `dev/goad.env` as the msldap test runner below and the msldap
checkout in `../msldap` (`MSLDAP_DIR=git` tests the locked git version instead).

### Testing the msldap fork against GOAD

`dev/goad-test-msldap.sh` runs the msldap live test suite and some CLI smoke tests against a
[GOAD](https://github.com/Orange-Cyberdefense/GOAD) lab. Run it on a host that can reach the lab;
defaults match a stock GOAD install and can be overridden via environment variables (see the script
header).

```bash
dev/goad-test-msldap.sh             # test fork-main (upstream main + our branches)
dev/goad-test-msldap.sh --compare   # additionally run upstream main as a baseline
```

Results are written to `dev/results/<timestamp>/`.
