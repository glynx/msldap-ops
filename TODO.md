# TODO

## Core

- [x] Monkeypatch hooks on `msldap.connection.convert_result` and `MSLDAPClientConnection.search` /
      `pagedsearch` to see every raw search result with its query (shared by logging and the DN cache)
- [x] Query logging in pyldapsearch/bofhound format, written to the current working directory
      (`./msldap-ops-logs/`), verified against the bofhound parser (offline roundtrip)
- [x] Verify the query log against GOAD (`dev/goad-test-ops.sh`)
- [x] SD flags control by default when `nTSecurityDescriptor` is requested (`query` in the fork)
- [ ] Optional per-query output file (like pyldapsearch `-output`)
- [x] Session transcript (`transcript on|off`, `--transcript [file]`)

## Presets

- [x] bofhound collection split per object type: users, computers, groups, domain, OUs,
      containers, GPOs, trusts, schema (`schemaIDGUID`), ADCS (Configuration NC) -> `bofhound_collect`
- [x] Verify `bofhound_collect` against GOAD (`dev/goad-test-ops.sh`)
- [ ] `bofhound_collect` for other domains of the forest / trusted forests in one go (second connection
      or the Global Catalog, port 3268/3269: a partial replica of every domain of the forest)
- [x] Privileged accounts: `adminCount=1`, recursive members of the protected groups via
      `LDAP_MATCHING_RULE_IN_CHAIN`, groups resolved by RID/SID (localized names, e.g. "Domänen-Admins") -> `find_admins`
- [x] Admins with SPN, admins not in Protected Users / not "sensitive", admins with
      `PASSWORD_NEVER_EXPIRES`
- [x] Verify `find_admins` against GOAD (`dev/goad-test-ops.sh`)
- [ ] `find_admins` across the forest: resolve forest root group members via a second connection or the GC

## Opsec

- [x] `opsec off|show|confirm|dryrun` for every search, `--opsec`, query count per command
- [x] Keepalive every 300 s instead of 10 s, `--keepalive`
- [x] Verify against GOAD (`dev/goad-test-ops.sh`)
- [ ] Try `confirm` interactively
- [ ] Optional jitter for `bofhound_collect` delays
- [x] Writing operations (add/modify/delete, msldap's addusertogroup, setsd, changeuserpw, ...) go
      through the opsec gate (shown, confirmed, not sent in dryrun) and into the journal
- [ ] Review which writing commands are missing for daily work (granting rights such as
      GenericAll/WriteDacl/DCSync on an object, owner changes, shadow credentials cleanup, ...)

## Navigation

- [x] Query cache with TTL, persisted per server/account as JSON, `cache` command with flush;
      index of all DNs seen so far
- [ ] Verify the cache against GOAD (`dev/goad-test-ops.sh`)
- [x] `cd` completion from the cache instead of only the current level
- [x] `cd ..` above the naming context of the DC (e.g. from DC=north,... to DC=sevenkingdoms,...)
      fails with a raw "referral" error; explain it and offer the naming contexts of the DC instead
      (msldap also splits the DN at the first comma, escaped commas break `cd ..`)
- [x] `map` command: tree of the visited structure
- [ ] Verify navigation against GOAD (`dev/goad-test-ops.sh`), try the completion interactively
- [ ] `map` as a toolbar below the prompt (optional)

## Enumeration

- [ ] Delegation overview (unconstrained, constrained with/without protocol transition, RBCD), with
      a filter for single kinds
- [ ] LAPS in both versions: legacy (`ms-Mcs-AdmPwd`) and Windows LAPS (`msLAPS-Password`,
      `msLAPS-EncryptedPassword`, expiration), who can read it

## ADCS

- [x] Template output like certipy: decoded `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`,
      `msPKI-Private-Key-Flag`, EKUs, with the security relevant bits highlighted
      (ENROLLEE_SUPPLIES_SUBJECT, NO_SECURITY_EXTENSION, PEND_ALL_REQUESTS, ...) -> `templates`
- [x] Verify `templates` against GOAD (`dev/goad-test-ops.sh`)
- [ ] CA level checks (ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2, ESC7 CA permissions, ESC8 web enrollment)
      need the CA registry/RPC, not LDAP; at least list the CA permissions from LDAP
- [ ] List the CA permissions (ESC7) from LDAP
- [ ] Cross-domain / cross-forest checks (`adcs-check [DOMAIN\user]`): take the token groups from
      the user's own domain and map them to foreign security principals in the target forest,
      so that e.g. NORTH\jon.snow can be checked against the ESSOS CA. Same-forest users of
      other domains via the Global Catalog or a second connection.

## UX

- [x] Clearly separate prompt and command output; colored output with
      [rich](https://github.com/Textualize/rich) on top of the plain text layout
      (prompt_toolkit's patch_stdout runs with raw=True so that colors reach the terminal)
- [ ] Try the colors interactively; decide whether `map`/`tree` should become rich trees
- [x] Colors for the output of the msldap built-in commands (all output goes through a styling stream)
- [x] Separate records (query output) on the terminal
- [x] Redirect a command's output to a file (`> file`, `>> file`)
- [ ] Better command descriptions (parameters, allowed values) for the msldap-ops commands

## Release

- [x] Remove the `[tool.uv.sources]` path override once glynx/msldap `main` is pushed (git+https dependency)
