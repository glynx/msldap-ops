# Certificate templates and CAs

[Back to README](../README.md)

LDAP discovery, template checks and review of CA directory-object permissions.

Use `help <command>` in the shell for command-specific usage.

## Templates

```text
templates                 table: CAs, client authentication, enrollee supplies subject,
                          manager approval, vulnerabilities
templates <name>          details of one template
templates vulnerable      details of the published templates with vulnerabilities
templates enabled         details of all published templates
```

The details follow certipy: msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag and
msPKI-Private-Key-Flag decoded one flag per line with the security relevant bits marked `[!]`,
EKUs, manager approval, authorized signatures, validity and renewal period, minimum key size and the
principals of the enrollment and object control permissions. Vulnerabilities (ESC1-4, ESC9, ESC13) are
checked for the token of the bound user; an account bound through a trust is checked as a low
privileged user of the connected domain, with an explicit note. This fallback does not evaluate
the foreign account's actual memberships or effective access.
The user's `msDS-PrincipalName` must match the bound identity before local token groups are used;
a same-named account in another domain cannot supply that token. Missing identity verification
also falls back with an explicit note.

The **Vulnerabilities** column contains findings for the evaluated token and compact yellow
review markers such as `ESC4 [?]`. A review marker does not establish a vulnerability for that token.
If both apply to the same ESC, the finding takes precedence. `none` means no finding or review
point from the implemented checks, not that the template is safe for every principal.
The overview keeps six columns; unpublished templates retain `-`. Structural observations are
explained as yellow `[review]` lines in `templates <name>` or `templates enabled`:

- **ESC3 target**: an authentication template accepts enrollment-agent requests (schema version 1,
  or version 2+ with one authorized signature and the Certificate Request Agent RA policy).
  It still requires a suitable agent certificate and CA enrollment-agent restrictions must be checked.
  The agent-issuing template carries the ESC3 finding; the target alone does not establish the chain.
- **ESC4 ACL**: other principals outside the known privileged SID groups own the template or have
  applicable allow ACEs for template control. Their identities are listed for review. Denies,
  memberships and effective access are not evaluated by this hint. A control right in the evaluated
  token remains an ESC4 finding, even when the template requires approval or signatures.
- **ESC13**: issuance-policy OIDs are correlated with `msDS-OIDToGroupLink` on LDAP issuance-policy
  objects. A finding requires a returned group link, an authentication template, applicable enrollment
  rights in the evaluated token and no manager approval or authorized signatures. Complex DACLs
  with deny or unsupported ACEs remain review points. A policy OID alone is insufficient; missing
  policy objects and failed lookups are reported as unassessed. Details show the returned **Policy
  Objects**, **Linked Groups** and an **ESC13 Check** status explaining the result. If an OID object
  is returned without `msDS-OIDToGroupLink`, the status says no group link was returned; this
  does not prove the attribute is unconfigured rather than unreadable. Returned links do not establish
  the linked group's privileges or a completed exploitation path.

See [Certipy's template escalation checks](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
for the distinction between agent templates, chain targets and linked issuance policies.

The table normally needs 4 LDAP searches: the user, tokenGroups, enrollment services and templates.
Templates with issuance policies add one search under `CN=OID` in the Configuration naming context.
Details additionally resolve uncached permission SIDs. `bofhound_collect adcs` explicitly requests
the policy group links; its cached results can answer the template, CA and policy searches.
Older collections may require one fresh policy search. No other domain, CA RPC or HTTP endpoint
is contacted. `templates vulnerable` includes published findings, excluding review-only templates;
use `templates enabled` to inspect all published templates and their review points.

To inspect a referenced policy directly, replace the OID and Configuration DN below. Quote the
base DN because it contains spaces. Disable the query cache temporarily with `cache off` when
you need a fresh LDAP result, then restore the previous cache setting.

```text
query (msPKI-Cert-Template-OID=<policy-oid>) msPKI-Cert-Template-OID,msDS-OIDToGroupLink "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=org"
```

An OID object without a returned `msDS-OIDToGroupLink` does not establish ESC13. LDAP omission
alone does not distinguish an unset attribute from one the connected account cannot read.

## CAs

```text
cas                 enterprise CAs and the ACLs of their AD enrollment-service objects
cas <name|host>     details for an exact CA name or DNS host name
```

`cas` shows the CA host, published templates, owner and decoded directory-object ACLs, with
resolved principals and yellow `[review]` markers for ACL review points. It uses one LDAP search with the
SD flags control plus uncached SID lookups, and reuses `bofhound_collect adcs` data. Deny ACEs,
inheritance and object-specific restrictions remain visible; this is an ACL review, not an
effective-access calculation. Missing or unreadable descriptors are reported as unassessed.

The LDAP ACL belongs to the **AD enrollment-service object**. It does not establish the CA
service's `ManageCA` or `ManageCertificates` permissions and is not an ESC7 confirmation.
`cas` lists the checks that remain unverified: ESC6 policy/EditFlags, ESC7 service permissions
and ESC11 request encryption need direct CA RPC/registry access. ESC8 Web Enrollment requires
contacting the actual HTTP(S) enrollment endpoint and checking authentication and EPA settings.
Advertised enrollment URLs from LDAP are metadata; their presence does not prove reachability
or vulnerable Web Enrollment. This command contacts only LDAP and never the CA service or web
endpoint. See [Certipy's CA configuration collection](https://github.com/ly4k/Certipy/blob/master/certipy/commands/ca.py)
and [Microsoft's Web Enrollment documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-authority-web-enrollment).

These commands use the [query cache and identity catalogue](operations.md#query-cache).
