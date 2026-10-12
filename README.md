# msldap-ops

Operator toolkit for Active Directory on top of [msldap](https://github.com/skelsec/msldap).
It adds directory navigation, enumeration, permission review and controlled changes to the msldap shell.
The dependency is the [glynx/msldap fork](https://github.com/glynx/msldap), which carries additional fixes.

- Browse AD with relative paths, completion, object icons and Rich trees.
- Collect directory data for BloodHound using presets and [bofhound](https://github.com/coffeegist/bofhound).
- Review privileged accounts, delegations, trusts, certificate templates, CA object ACLs and LAPS permissions.
- Reduce repeated queries with persistent caches and reuse known SID names across domain connections.
- Show or confirm LDAP operations, track changes and undo supported writes.

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
