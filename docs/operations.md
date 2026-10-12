# Connections and session settings

[Back to README](../README.md)

Bind options, query reuse, retained identities, output and history.

Use `help <command>` in the shell for command-specific usage.

## Connections

The connection URL is the same as for msldap:

```bash
msldap-ops 'ldap+ntlm-password://NORTH\user:password@192.168.56.11'
```

Commands can be passed as additional arguments; `i` drops into the interactive shell:

```bash
msldap-ops 'ldap+ntlm-password://NORTH\user:password@192.168.56.11' login 'query (adminCount=1) sAMAccountName'
```

Connection options are applied before login, including the automatic interactive login:

| Option | Use |
| --- | --- |
| `--ntlm-bind sicily` | Use SICILY NTLM binds, e.g. for ntlmrelayx's LDAP SOCKS handler. Preserves the password/hash and proxy settings in the URL. |
| `--ntlm-bind sasl` | Use SASL GSS-SPNEGO NTLM binds (the usual `ldap+ntlm-*` behavior). |
| `--no-signing` | Disable NTLM/Kerberos signing and sealing on plain LDAP. LDAPS already uses TLS for transport protection. |
| `--no-channel-binding` | Disable TLS channel binding on LDAPS. Has no effect on plain LDAP. |

Without these options the URL's authentication mode and msldap defaults are preserved; a failed
bind does not trigger an automatic fallback. `--ntlm-bind` requires an NTLM or SICILY URL and
does not convert Kerberos, simple or anonymous authentication. The shell commands `nosig` and
`nocb` remain available and must be run before `login` to affect that connection.

For an existing relayed LDAP session through ntlmrelayx SOCKS:

```bash
msldap-ops --ntlm-bind sicily \
  'ldap+ntlm-password://NORTH\user:unused@192.0.2.10/?proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080'
```

Use the target and `DOMAIN\user` of an active relay session. The LDAP SOCKS handler matches
that identity to the existing session rather than validating the supplied password against
the DC. The required compatibility setting is `--ntlm-bind sicily`: the handler accepts SICILY
binds rather than SASL GSS-SPNEGO. This was verified against a Ludus test lab without
`--no-signing`; that flag remains an optional, separate setting. This is an LDAP example;
disabling channel binding cannot fix an unsupported bind type.

## CLI reference

`msldap-ops [options] <url> [commands ...]`

With no commands, login runs automatically and the interactive shell opens. With commands,
they run in order; include `login` explicitly, and use `i` to enter the shell afterward.
The [msldap repository](https://github.com/glynx/msldap) documents the connection URL formats.

| Option | Default | Values / effect |
| --- | --- | --- |
| `--ntlm-bind` | Authentication mode from the URL | `sasl` or `sicily`; see [Connections](#connections) |
| `--no-signing` | Off | Disable signing/sealing on plain LDAP |
| `--no-channel-binding` | Off | Disable TLS channel binding on LDAPS |
| `--opsec` | `off` | `off`, `show`, `confirm`, `confirm-write`; shell also supports `dryrun` |
| `--keepalive SECONDS` | `300` | Keepalive interval; `0` disables it after login |
| `--log-dir DIRECTORY` | `./msldap-ops-logs/` | Query result logs and JSONL journal |
| `--no-log` | Off | Disable query logging |
| `--cache-dir DIRECTORY` | `./msldap-ops-cache/` | Project query caches and retained identities |
| `--cache-ttl SECONDS` | `7200` | Query result lifetime, in seconds |
| `--cache-memory-only` | Off | Keep queries/identities in memory; do not read or write cache files |
| `--no-cache` | Off | Disable query caching and identity lookups |
| `--history-file FILE` | `$XDG_STATE_HOME/msldap-ops/history` or `~/.local/state/msldap-ops/history` | Override shell history path |
| `--no-history` | Off | Keep history in memory only |
| `--transcript [FILE]` | Off | Append a session transcript; default file `./msldap-ops-transcript_<date>.log` |
| `--no-color` | Off | Plain output; also honored through `NO_COLOR` |
| `-v`, `--verbose` | Off | Increase verbosity; can be repeated |
| `-h`, `--help` | — | Show CLI help |

Query log formats and `log on/off` are covered under [Query logging](queries.md#query-logging).

## Opsec

`opsec <mode>` (or `--opsec show|confirm|confirm-write` on the command line, which also covers the login) controls
what happens before an LDAP search is sent:

- `off`: nothing (default)
- `show`: the query (base, scope, filter, attributes, controls) is printed before it is sent
- `confirm`: the query is printed and needs confirmation: `y` send, `n` skip (the command gets an
  empty result), `a` send all further queries of the running command, `q` abort the command.
  The queries of the navigation commands `cd`, `ls` and `cat` of a single object are only shown;
  `cat *` and `cat` with a pattern search a whole container level and are confirmed.
- `confirm-write`: reads run silently; only add, modify and delete operations are shown and
  confirmed. The same `y`, `n`, `a` and `q` answers apply; `a` lasts for the current command only.
- `dryrun`: queries are printed but not sent. Commands that build queries on the results of earlier
  ones (e.g. `find_admins`) only show their first stage; `help <command>` lists the queries of the
  msldap-ops commands.

Changes to the directory (add, modify, delete; e.g. `addusertogroup`, `setsd`, `changeuserpw`,
`addcomputer`, `shadowcred`) go through the same gate: shown in `show`, `confirm`, `confirm-write` and `dryrun` with
DN, operation, attributes and values (passwords hidden, security descriptors as SDDL), always
confirmed in `confirm` and `confirm-write` (also within navigation commands) and never sent in `dryrun`:

```text
[change #1] modify CN=Domain Admins,CN=Users,DC=essos,DC=local
            add member: CN=khal.drogo,CN=Users,DC=essos,DC=local
send? [y]es / [n]o, skip / [a]ll for this command / [q]uit command:
```

After each command a summary shows what actually happened: queries and changes sent, skipped, where
the command was aborted, and how many searches were answered from the cache. Every query and every
change, including skipped ones, is recorded in the query journal (changes with `"type": "write"`,
a record of what was changed, e.g. for the cleanup after an engagement).

The msldap shell sends a keepalive search on the domain object every 10 seconds. msldap-ops uses
300 seconds; `--keepalive SECONDS` changes it, `--keepalive 0` stops it after the login. Keepalive
queries are not shown or confirmed and not written to the bofhound log, only to the journal.

## Query cache

Repeated searches (same base, scope, filter, attributes and controls) within the TTL are answered from
the cache, without contacting the server. A broader cached search answers narrower ones as well
(same filter, base DN at or below the cached one, attributes included explicitly or through `*`):
after `bofhound_collect adcs`, `templates` only asks the server for the token of the bound user. A
read of a single object (`cat`, `acl`) is answered by any cached result that contains the object with
the wanted attributes, whatever filter found it: after `bofhound_collect all`, `cat` on a user, group
or computer sends nothing. This applies to every command, including the msldap built-ins. The cache is kept per server and account and written to `./msldap-ops-cache/` as JSON, so
a new session reuses it.

```text
cache                  state, size, hits/misses, cache file
cache list             cached queries with age and number of results
cache flush [text]     drop current queries and DN index, or queries matching text
cache identities       retained identity labels across domains, with source and last seen
cache identities clear clear the shared identity catalogue explicitly
cache ttl <seconds>    lifetime of cached results (default 7200 = 2 hours, --cache-ttl)
cache on | off         use the cache or always ask the server
```

Not cached: the keepalive, searches a command stopped early, failed searches. add/modify/delete
drop cached queries for the current server and account. Changes made with other tools show up
after the TTL or a `cache flush`. Other server/account namespaces remain untouched.

For engagements where reducing LDAP traffic matters more than freshness, increase the TTL
substantially, e.g. `--cache-ttl 28800` or `cache ttl 28800` for eight hours. Reusing cached results
reduces repeated queries, but changes made by other operators or administrators can remain
invisible for that long. Use `cache flush` before checks that require current data, or choose a
shorter TTL. Cache hits do not extend the lifetime of a result.

Searches answered from the cache send nothing, so `opsec confirm` does not ask for them; `opsec`
shows them as one `[cache]` line and counts them separately (`[opsec] find_admins: 2 LDAP queries
sent, 8 answered from the cache`). The query journal records them with `"cached": true`; they are
not written to the bofhound log again. `--cache-memory-only` keeps the cache off the disk, `--no-cache` disables it.

The cache also keeps an index of every DN seen in a result, for navigation.

### Identity catalogue

Identity labels are kept separately in `identities.sqlite3` in the same cache directory. Positive
observations of account SIDs/names, domain SIDs and trust/partition domain names survive the query
TTL, writes and `cache flush`. Existing JSON cache files in this directory contribute names even
when their results have expired. A newer observation of the same SID updates its name; an empty
search does not erase a known name. Cache hits do not refresh the observation time.
`sid2dn <SID>` requests both `objectSid` and `sAMAccountName` alongside the DN in the same query,
so an individual account lookup also contributes an identity label where its name is readable.

Connect to each domain's DC explicitly and use the same `--cache-dir` for the engagement. ACLs,
CA/template permissions and RBCD displays can then resolve foreign SIDs from previously collected
identities without another connection. Prefer NetBIOS domain names where known, otherwise DNS
names. Labels older than the query TTL show `(last seen: YYYY-MM-DD HH:MM UTC)` in gray. This is
historical naming information, not proof that the account still exists or has current permissions.
Group memberships, security descriptors and effective access are not taken from this catalogue.
`cache identities` shows the source server, collecting account and timestamp;
`cache identities clear` removes retained labels while leaving query caches intact.

Use a separate cache directory for each engagement. `cache off` bypasses identity lookups as well
as query reuse; `--cache-memory-only` neither reads nor writes identity data on disk, and
`--no-cache` disables both. Collection across domains is manual; combine the collected logs with
bofhound/BloodHound rather than expecting automatic LDAP or Global Catalog connections.

## Output

The prompt (`msldap-ops <DN> >`) is colored so that it stands out from the command output. All output,
including the msldap built-in commands, keeps its plain text layout and gets colors on top. `query`
and `cat` show every object with a separator line, its DN and aligned attribute names, values of
multi-valued attributes below each other (`query` ends with the number of objects). Results from the
query cache say so in gray: `(from cache: <time>)` at the DN (`cat`) or the count (`query`, `cat *`); DN and attribute
names are colored, findings and `[!]` marks are red, CA `[review]` marks and `delegable` yellow, the queries shown by `opsec`
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

The whole session can be written to a file as well, each command with a timestamp followed by its
output (plain text, including the queries shown by `opsec` and the answers to its questions):

```text
transcript on [file]      start, default ./msldap-ops-transcript_<date>.log (appended)
transcript off            stop
transcript                state and file
msldap-ops --transcript [file] ...   from the start
```

Commands with secrets (`login` with a password or hash in the URL, `changeuserpw`, `adduser`,
`addcomputer` with a password) are recorded without arguments. Output redirected with `> file` is
not repeated in the transcript.

## History

The command history is kept across sessions in `~/.local/state/msldap-ops/history` (or
`$XDG_STATE_HOME/msldap-ops/history`), readable by the user only. Commands with secrets - `login`
with a password or hash in the URL, `adduser`, `changeuserpw`, `addcomputer` with a password - are
available in the running session but not written to the file. `--history-file` picks another file,
`--no-history` keeps the history in memory only.

Up/Down search the history for entries starting with the typed text. Ctrl-R opens
[fzf](https://github.com/junegunn/fzf) over the history if it is installed (the typed text is the
initial query), otherwise the built-in reverse search.
