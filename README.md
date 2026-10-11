# msldap-ops

Operator toolkit on top of [msldap](https://github.com/skelsec/msldap), a pure-Python LDAP client
for Active Directory that does not depend on impacket.

Planned features:

- **Query logging** in a [pyldapsearch](https://github.com/Tw1sm/pyldapsearch)-compatible format, so
  that collected data can be imported into BloodHound with
  [bofhound](https://github.com/coffeegist/bofhound). Logs are written to the current working directory.
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

## Development

The repository expects the msldap checkout next to it (`../msldap`), see `[tool.uv.sources]` in
`pyproject.toml`.

```bash
uv sync
uv run msldap-ops --help
uv run pytest
```

### Testing the msldap fork against GOAD

`dev/goad-test-msldap.sh` runs the msldap live test suite and some CLI smoke tests against a
[GOAD](https://github.com/Orange-Cyberdefense/GOAD) lab. Run it on a host that can reach the lab;
defaults match a stock GOAD install and can be overridden via environment variables (see the script
header).

```bash
dev/goad-test-msldap.sh             # test the fix branch
dev/goad-test-msldap.sh --compare   # additionally run upstream main as a baseline
```

Results are written to `dev/results/<timestamp>/`.
