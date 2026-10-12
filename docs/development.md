# Development

[Back to README](../README.md)

Run these commands from the msldap-ops repository root.

## Local checks

```bash
uv sync
uv run msldap-ops --help
env -u NO_COLOR TERM=xterm-256color uv run pytest
```

The dependency is the `main` branch of [glynx/msldap](https://github.com/glynx/msldap),
with its resolved commit recorded in `uv.lock`. Update it with:

```bash
uv lock --upgrade-package msldap
```

For msldap development and its own test suite, see the
[msldap repository](https://github.com/glynx/msldap).

## Query log roundtrip

[dev/bofhound-roundtrip.py](../dev/bofhound-roundtrip.py) writes an offline fixture log with a
domain, user, group, computer, membership and ACLs. Import it with bofhound to check the format:

```bash
uv run python dev/bofhound-roundtrip.py /tmp/msldap-ops-roundtrip
uvx bofhound -i /tmp/msldap-ops-roundtrip -o /tmp/msldap-ops-roundtrip/out
```

The resulting JSON should contain all four objects, group membership and GenericAll edges.

## GOAD integration checks

[dev/goad-test-ops.sh](../dev/goad-test-ops.sh) runs msldap-ops against a reachable
[GOAD](https://github.com/Orange-Cyberdefense/GOAD) lab with query logging enabled, then imports
the log with bofhound via `uvx`. It exercises navigation, collection, ACLs and other commands.

Copy [dev/goad.env.example](../dev/goad.env.example) to `dev/goad.env` and set the lab targets
and accounts. To test the dependency recorded in `uv.lock`, run:

```bash
MSLDAP_DIR=git dev/goad-test-ops.sh
```

Results are written to `dev/results/ops-<timestamp>/`, which is ignored by Git.
The runner performs live LDAP queries; local unit tests do not verify lab connectivity or
the behavior of a real DC.

## README demo

[dev/render-demo.py](../dev/render-demo.py) builds [the animated preview](assets/demo.gif) using
the shell commands and renderers with a fictional directory held in memory. It makes no network
connections and does not read credentials, query logs or caches from an engagement. The write
and undo chapter changes only the in-memory fixture. Results illustrate the UI, not a live AD assessment.

```bash
uv run --with pillow python dev/render-demo.py
```

Rendering needs DejaVu Sans Mono (regular and bold) and DejaVu Sans for the feature descriptions;
`--font /path/to/monospace.ttf` overrides them.
Noto Color Emoji is used for object icons when installed. Pillow is needed only to rebuild the
preview and is not a runtime dependency. The script also exports `docs/assets/demo.png` as a still.
