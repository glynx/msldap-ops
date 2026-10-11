# msldap-ops

Operator toolkit on top of [msldap](https://github.com/skelsec/msldap), a pure-Python LDAP client
for Active Directory that does not depend on impacket.

Features:

- **Query logging** in a [pyldapsearch](https://github.com/Tw1sm/pyldapsearch)-compatible format, so
  that collected data can be imported into BloodHound with
  [bofhound](https://github.com/coffeegist/bofhound). Logs are written to the current working directory.

- **Collection presets** for bofhound, split per object type (users, computers, groups, OUs, GPOs,
  schema, ADCS, ...), so that no single query returns the whole directory.

- **Privileged accounts** (`admins`): recursive members of the protected groups, found by SID, with
  their risky settings.

- **Extended shell**: all msldap shell commands plus the msldap-ops commands.

msldap-ops currently depends on the [glynx/msldap](https://github.com/glynx/msldap) fork, which carries
fixes that are not (yet) upstream.

## Installation

```bash
uv tool install git+ssh://git@github.com/glynx/msldap-ops.git
```

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

`admins` lists the recursive members of Domain Admins, Enterprise/Schema/Enterprise Key Admins,
Administrators, Account/Server/Print/Backup Operators, Key Admins, Group Policy Creator Owners,
Domain Controllers and DnsAdmins. Groups are found by SID, so localized names work. Per account:

- `kerberoastable` (user with SPN), `asrep-roastable`, `password-not-required`,
  `password-never-expires`, `unconstrained-delegation` (not reported for DCs)
- `delegable`: neither "sensitive and cannot be delegated" nor in Protected Users
- `disabled`, pwdLastSet and lastLogonTimestamp

It also lists `adminCount=1` users that are no longer in any of these groups. Direct members from
other domains (foreign security principals, forest root groups) are shown with their DN. The forest
root groups can only be listed on a DC of the forest root.

In the shell, `log` shows the log files, `log off` / `log on` pause and resume logging.
`--log-dir` changes the directory, `--no-log` disables logging completely.

## Development

The repository expects the msldap checkout next to it (`../msldap`), see `[tool.uv.sources]` in
`pyproject.toml`.

```bash
uv sync
uv run msldap-ops --help
uv run pytest
```

`dev/bofhound-roundtrip.py` writes a small log offline that can be imported with `uvx bofhound` to
check the format.

### Testing msldap-ops against GOAD

`dev/goad-test-ops.sh` runs queries against a GOAD lab with logging enabled and imports the log with
bofhound (via `uvx`). It uses the same `dev/goad.env` as the msldap test runner below.

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
