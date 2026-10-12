# Queries and collection

[Back to README](../README.md)

Raw searches, query logging, bofhound presets and account enumeration.

Use `help <command>` in the shell for command-specific usage.

## LDAP queries

`query` accepts an LDAP filter followed by optional attributes, base and scope:

```text
query <filter> [attributes] [base] [scope]
```

Use `(objectClass=*)` to match every object; a bare `*` is not an LDAP filter. In the
attributes position, `*` requests all regular attributes. Attributes are comma separated.
The base defaults to the domain root, even after `cd`; use `.` for the current DN, a relative
path such as `CN=Users` or `..`, or an absolute DN. `-` keeps the default domain root.

| Scope | Searches |
| --- | --- |
| `base` | Only the base object |
| `one` | Direct children of the base |
| `sub` (default) | The base and all descendants |

Arguments are positional. To specify a scope, supply both attributes and base:
`query (objectClass=*) * - base` reads the domain object. In `query * - base`, the filter is
invalid, `-` occupies the attributes position, and `base` occupies the search base position.

Examples inside the interactive shell:

```text
query (objectClass=*) * - base
query (objectClass=*) * . base
query (objectClass=*) name,objectClass . one
query (sAMAccountName=admin*) sAMAccountName,description
query (objectCategory=group) cn,member CN=Users sub
query (&(objectCategory=person)(objectClass=user)) sAMAccountName
query (|(objectClass=computer)(objectClass=group)) name,objectClass
query (adminCount=1) *,nTSecurityDescriptor
```

These read the domain object, the current object, its direct children, accounts matching
`admin*`, groups under `CN=Users` relative to the current DN, user accounts, computers or groups,
and objects with `adminCount=1`, respectively. `&` combines conditions with AND, `|` with OR;
`*` inside a filter tests attribute presence (`(description=*)`) or matches part of a value
(`(sAMAccountName=admin*)`). To read just the current object, `cat .` is shorter.

When passing a query on the command line, quote the whole command so the shell preserves the
filter and wildcard characters:

```bash
msldap-ops 'ldap+ntlm-password://NORTH\user:password@192.168.56.11' login \
  'query (objectClass=*) * - base'
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

In the shell, `log` shows the log files, `log off` / `log on` pause and resume logging.
`--log-dir` changes the directory, `--no-log` disables logging completely.

## Collecting data for bofhound

`bofhound_collect` splits collection into queries by object type. ACL collection requests
`*,nTSecurityDescriptor` with the SD flags control; the DNS preset requests the attributes needed
for DNS nodes instead. The ADCS issuance-policy query additionally requests `msDS-OIDToGroupLink`
for template checks and cache reuse. The results are not printed, they go to the query log.

```text
bofhound_collect                 list the presets and their queries
bofhound_collect all             every preset, including DNS
bofhound_collect users,groups    selected presets
bofhound_collect all 5           wait 5 seconds between queries
bofhound_collect all 2-8         wait a random 2-8 seconds (jitter)
bofhound_collect dns             DNS nodes only (computer IP addresses)
```

bofhound evaluates DNS nodes since version 0.4.21; older versions list them as unknown objects.
DNS records enrich computer objects with IP addresses; the directory objects and ACL edges can
still be imported without DNS. See [bofhound's DNS processing](https://github.com/coffeegist/bofhound/blob/main/bofhound/ad/adds.py).
`all` includes the domain and forest DNS naming contexts. These zones can be large; select
individual presets when you want a narrower collection.

Presets: `domain`, `users`, `computers` (including gMSAs and trust accounts), `groups`, `ous`,
`containers`, `gpos`, `trusts`, `fsps`, `schema`, `adcs` (enterprise CAs, root/AIA CAs, NTAuth store,
templates, issuance policies), `partitions` (NetBIOS names) and `dns`. Base DNs are taken from the
RootDSE, so Configuration and Schema are found on child domain DCs as well.

The presets cover the domain the DC belongs to. For other domains of the forest or trusted forests,
connect to one of their DCs and run `bofhound_collect` again.

| Collection parameter | Default | Values |
| --- | --- | --- |
| `names` | List presets without collecting | Comma separated presets or `all` (includes `dns`) |
| `delay` | `0` seconds | Fixed seconds or a `MIN-MAX` jitter range |

Use a separate invocation for each domain's DC; logs can be combined with bofhound/BloodHound.

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

| Enumeration command | Default | Values |
| --- | --- | --- |
| `find_admins [pattern]` | `adm` | Name/description pattern; `-` skips the name search |
| `delegations [kind]` | `all` | `all`, `unconstrained`, `constrained`, `rbcd` |

## Trusts

`trusts` lists each trust with its direction, type, configured attributes and SID, relative to
the connected domain. It does not test authentication or effective SID filtering.

## Delegation and legacy commands

Commands superseded by msldap-ops are grouped under `Legacy msldap commands` in `help`, including
`unconstrained` and `constrained`. They remain callable, with detailed help via `help <command>`.
Use `delegations [all|unconstrained|constrained|rbcd]` for the combined overview, with separate
sections and counts, constrained delegation targets and the principals allowed through RBCD.

See [navigation](navigation.md) for paths and [cache and opsec](operations.md#query-cache) for query reuse.
