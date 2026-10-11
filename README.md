# msldap-ops

Operator toolkit on top of [msldap](https://github.com/skelsec/msldap), a pure-Python LDAP client
for Active Directory that does not depend on impacket.

Features:

- **Query logging** in a [pyldapsearch](https://github.com/Tw1sm/pyldapsearch)-compatible format, so
  that collected data can be imported into BloodHound with
  [bofhound](https://github.com/coffeegist/bofhound). Logs are written to the current working directory.

Planned:

- **Query presets**, e.g. a bofhound collection split per object type (users, computers, groups, ...)
  and queries for privileged accounts.
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
