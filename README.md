# msldap-ops

Operator toolkit for Active Directory on top of [msldap](https://github.com/skelsec/msldap).
It adds directory navigation, enumeration, permission review and controlled changes to the msldap shell.
The dependency is the [glynx/msldap fork](https://github.com/glynx/msldap), which carries additional fixes.

![msldap-ops demo: directory navigation, delegation, ADCS checks, collection and undo](docs/assets/demo.gif)

- **Directory navigation:** `cd`, `ls`, `cat`, `find`, `tree` and a query-free `map`, with relative
  paths, completion, object icons and dimmed disabled accounts. [Navigation](docs/navigation.md)
- **Enumeration:** `find_admins` finds privileged accounts by SID and flags interesting account
  settings; `delegations` separates unconstrained, constrained and RBCD; `trusts` shows domain relationships.
- **Permission review:** readable `acl` output decodes AD rights and resolves principals;
  `laps_permissions` reviews LAPS read permissions without requesting passwords. [Permissions](docs/permissions.md)
- **ADCS checks:** `templates` checks ESC1–4, ESC9 and ESC13 for the evaluated token, with separate
  review hints; `cas` reviews CA directory-object permissions. [ADCS](docs/adcs.md)
- **BloodHound collection:** choose presets, include ACLs and DNS, add delay or jitter, and import
  query logs with [bofhound](https://github.com/coffeegist/bofhound). [Queries and collection](docs/queries.md)
- **Cache and identities:** reuse query results and known SID names across explicit domain
  connections; older identity labels show when they were last seen. [Cache](docs/operations.md#query-cache)
- **Controlled changes:** `opsec` shows operations, previews them with `dryrun`, or confirms writes
  with `confirm-write`. Inspect `changes`, `undo` supported writes, and add or selectively remove
  shadow credentials with `keycred`. [Changes and cleanup](docs/changes.md)

## Installation

```bash
uv tool install git+https://github.com/glynx/msldap-ops.git
```

Update with `uv tool upgrade msldap-ops`. Python 3.9 or newer is required.

## Quick start

Run from a directory for the engagement; query logs and caches are created there by default.
The connection URL uses msldap's format:

```bash
msldap-ops --opsec show 'ldap+ntlm-password://NORTH\user:password@192.0.2.10'
```

With no commands, msldap-ops logs in and opens the interactive shell. A typical session:

```text
help
cd CN=Users
ls
cat .
find *admin*
acl .
find_admins
delegations
templates
cas
```

`help <command>` shows parameters and examples. `msldap-ops --help` lists CLI options.
All msldap shell commands remain available; commands with replacements appear under `Legacy msldap commands`.

To run commands directly and then enter the shell:

```bash
msldap-ops 'ldap+ntlm-password://NORTH\user:password@192.0.2.10' login find_admins i
```

## ntlmrelayx + SOCKS

For ntlmrelayx's LDAP SOCKS handler, use `--ntlm-bind sicily`.
The proxy URL example and signing/channel-binding options are in [Connections](docs/operations.md#connections).

## Collect for BloodHound

In the interactive shell:

```text
bofhound_collect all
log
```

Then import the logs:

```bash
bofhound -i msldap-ops-logs/
```

`all` includes DNS records for computer IP addresses; `bofhound_collect dns` collects just DNS.
Collect selected presets with `bofhound_collect users,groups`, or add jitter with `bofhound_collect all 2-8`.
Connect to each domain's DC separately and combine the logs with bofhound/BloodHound.
See [Queries and collection](docs/queries.md) for all presets, filters and logging details.

## Commands and reference

| Area | Main commands | Documentation |
| --- | --- | --- |
| Navigation and lookup | `cd`, `ls`, `cat`, `find`, `map`, `tree`, `sid2dn` | [Paths, defaults and display](docs/navigation.md) |
| Queries and enumeration | `query`, `bofhound_collect`, `find_admins`, `delegations`, `trusts`, `log` | [Filters, collection and logs](docs/queries.md) |
| ADCS | `templates`, `cas` | [Template checks and CA ACL review](docs/adcs.md) |
| ACLs and LAPS | `acl`, `getsd`, `laps`, `laps_permissions` | [Permissions and password reads](docs/permissions.md) |
| Directory changes | `grant`, `revoke`, `chown`, `rbcd`, `keycred`, `setattr`, `uac`, `changes`, `undo` | [Writing and cleanup](docs/changes.md) |
| Session settings | `opsec`, `cache`, `transcript` | [Connections, CLI options, output and history](docs/operations.md) |

`laps` reads passwords; `laps_permissions` reviews read permissions without requesting password values.
`cas` reviews the CA's AD enrollment-service object and uses yellow `[review]` markers.
Direct CA RPC/HTTP checks and Windows LAPS decryption are outside the LDAP scope.

## Queries, writes and cached data

`opsec` defaults to `off`. Use `--opsec show` to see queries, `--opsec confirm` to confirm operations,
or `--opsec confirm-write` to confirm writes while reads run silently.
Supported changes can be inspected with `changes` and reversed with `undo`; see [cleanup limits](docs/changes.md#changes-and-undo).

Query logging and persistent caching are enabled by default:

| Setting | Default |
| --- | --- |
| Query logs | `./msldap-ops-logs/` |
| Query cache and identity catalogue | `./msldap-ops-cache/` |
| Query TTL | `7200` seconds (2 hours) |
| Keepalive | `300` seconds |

A longer TTL reduces LDAP traffic at the cost of freshness. `cache flush` clears current query results;
retained identity labels survive and show their last observation when old.
Use one `--cache-dir` per engagement to share known names across its domain connections.
Details and controls are in [Cache and identities](docs/operations.md#query-cache) and [Opsec](docs/operations.md#opsec).

## Development

See [Development](docs/development.md) for local checks, the query-log roundtrip and GOAD integration tests.
Open work is tracked in [TODO.md](TODO.md).
