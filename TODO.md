# TODO

## Core

- [x] Monkeypatch hooks on `msldap.connection.convert_result` and `MSLDAPClientConnection.search` /
      `pagedsearch` to see every raw search result with its query (shared by logging and the DN cache)
- [x] Query logging in pyldapsearch/bofhound format, written to the current working directory
      (`./msldap-ops-logs/`), verified against the bofhound parser (offline roundtrip)
- [x] Verify the query log against GOAD (`dev/goad-test-ops.sh`)
- [x] SD flags control by default when `nTSecurityDescriptor` is requested (`query` in the fork)
- [ ] Optional per-query output file (like pyldapsearch `-output`)

## Presets

- [x] bofhound collection split per object type: users, computers, groups, domain, OUs,
      containers, GPOs, trusts, schema (`schemaIDGUID`), ADCS (Configuration NC) -> `collect`
- [x] Verify `collect` against GOAD (`dev/goad-test-ops.sh`)
- [ ] `collect` for other domains of the forest / trusted forests in one go (second connection or GC)
- [x] Privileged accounts: `adminCount=1`, recursive members of the protected groups via
      `LDAP_MATCHING_RULE_IN_CHAIN`, groups resolved by RID/SID (localized names, e.g. "Domänen-Admins") -> `admins`
- [x] Admins with SPN, admins not in Protected Users / not "sensitive", admins with
      `PASSWORD_NEVER_EXPIRES`
- [ ] Verify `admins` against GOAD (`dev/goad-test-ops.sh`)
- [ ] `admins` across the forest: resolve forest root group members via a second connection or the GC

## Navigation

- [ ] Cache of all DNs seen so far (optionally persisted per target)
- [ ] `cd` completion from the cache instead of only the current level
- [ ] `map` command: tree of the visited structure, optionally as a toolbar below the prompt

## ADCS

- [ ] Template output like certipy: decoded `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`,
      `msPKI-Private-Key-Flag`, EKUs, with the security relevant bits highlighted
      (ENROLLEE_SUPPLIES_SUBJECT, NO_SECURITY_EXTENSION, PEND_ALL_REQUESTS, ...)
- [ ] Cross-domain / cross-forest checks (`adcs-check [DOMAIN\user]`): take the token groups from
      the user's own domain and map them to foreign security principals in the target forest,
      so that e.g. NORTH\jon.snow can be checked against the ESSOS CA. Same-forest users of
      other domains via the Global Catalog or a second connection.

## UX

- [ ] Clearly separate prompt and command output; colored, structured output with
      [rich](https://github.com/Textualize/rich) (tables, trees, highlighting) on top of the
      prompt_toolkit based shell inherited from msldap
- [ ] Better command descriptions (parameters, allowed values) for the msldap-ops commands

## Release

- [ ] Remove the `[tool.uv.sources]` path override once glynx/msldap `main` is pushed
