# ACLs and LAPS permissions

[Back to README](../README.md)

Decode directory ACLs, review LAPS read permissions and read LAPS passwords where allowed.

Use `help <command>` in the shell for command-specific usage.

| Command | Default target | Selection |
| --- | --- | --- |
| `acl [path] [show]` | Current object (`.`) | `all` (default), `explicit`, `risky` |
| `getsd [path] [opts]` | Current object (`.`) | Raw SDDL; `p` or `g` for msldap's per-ACE tables |
| `laps [target]` | Current object, when it is a computer | Computer name, pattern or `all`; reads passwords |
| `laps_permissions [target]` | Current object, when it is a computer | Computer name, pattern or `all`; reviews permissions without reading passwords |

ACL paths resolve as for [navigation](navigation.md). LAPS targets are computer names or
patterns; `all` explicitly selects the whole domain.

## ACLs

`acl` shows the security descriptor of an object decoded: owner, group and one line per DACL entry
with allow/deny, the principal (resolved by name), the rights (FullControl, GenericWrite, WriteDacl,
WriteProperty, ExtendedRight, ...), the object type the entry is limited to (an attribute like
`member`, an extended right like `Reset Password`, a validated write like `Self-Membership`) and
where it applies (this object, descendants, `user objects`).

```text
ACL of CN=Domain Admins,CN=Users,DC=north,DC=sevenkingdoms,DC=local
  Owner: NORTH\Domain Admins
  Group: NORTH\Domain Admins
  DACL: 24 entries, 9 inherited

  Access        Principal                    Rights         Object           Applies to
  allow         NORTH\jon.snow               WriteProperty  member           this object   [!] Write member
  allow         NORTH\helpdesk               ExtendedRight  Reset Password   user objects  [!] Reset Password
  ...
```

`[!]` marks entries that let a principal outside the privileged groups take over the object: full
control, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, Reset Password, the DCSync rights,
writing `member`, `servicePrincipalName`, `msDS-KeyCredentialLink`,
`msDS-AllowedToActOnBehalfOfOtherIdentity` and similar attributes, adding oneself to a group; and a
non-privileged owner. Privileged are SYSTEM, Enterprise Domain Controllers, Administrators, Account
Operators, Domain Admins, Domain Controllers, Schema/Enterprise Admins, (Enterprise) Key Admins and
Enterprise Read-only Domain Controllers (of any domain in the forest), SELF and CREATOR OWNER.
To get the DN of an account or group, `find jaime.lannister`, `find "Small Council"` or `find *admin*`
lists type, account name and DN. `acl . risky` shows only the marked entries, `acl . explicit` only the ones not inherited.

Previously collected identities from the project's cache directory resolve account SIDs across
connections and domains; older labels show their last observation (see the [identity catalogue](operations.md#identity-catalogue)).
Well-known SIDs are named locally. Domain names come from retained identities, the connected domain and trusts
(loaded once per connection when needed); standard domain RIDs such as `512` identify Domain
Admins even in a trusted domain. Other unresolved accounts appear as
`SEVENKINGDOMS\<unresolved RID 1001> (S-1-5-21-...-1001)`: the domain is known, the account name
is not, and the complete SID is retained. An unresolved SID alone does not prove deletion.

Queries: the security descriptor (one base search with the SD flags control, so unprivileged users
get owner and DACL), trust discovery when needed, and one search per uncached account SID in the
connected domain. Foreign accounts are not queried through referrals. Results come from the query cache
when possible: the security descriptor from any earlier search that returned the object with the
SD flags control (e.g. `bofhound_collect`, then the first line says `(from cache: <time>)`), the
names of SIDs from any cached object with `objectSid` and `sAMAccountName`. After
`bofhound_collect`, `acl` therefore usually sends no query at all. Attribute and class
GUIDs are named from a built-in table; others, like the LAPS attributes whose GUIDs differ per
forest, are named if `bofhound_collect` (preset `schema`) put the schema into the cache.

## LAPS

`laps` reads the local administrator password managed by LAPS, both the legacy version
(`ms-Mcs-AdmPwd`) and Windows LAPS (`msLAPS-Password`). Reading it is sensitive and privileged, so
the command needs a target instead of dumping the whole domain by default:

```text
laps                      the current object, when it is a computer (same as laps .)
laps kingslanding$        one computer by sAMAccountName or name ('$' optional)
laps *srv*                computers matching a pattern
laps all                  every computer with LAPS (reads many passwords!)
```

For each computer it shows the LAPS version, the password where readable, and the expiration. A
Windows LAPS encrypted password (`msLAPS-EncryptedPassword`) cannot be decrypted over LDAP alone;
it is reported as encrypted (decryption needs an RPC call to the DC).

To review permissions without requesting password values, use the separate command:

```text
laps_permissions                 current object, when it is a computer
laps_permissions kingslanding$   one computer by account name or name
laps_permissions *srv*           matching computers
laps_permissions all             every computer in the domain
```

`laps_permissions` shows read-related allow and deny ACEs for legacy LAPS, Windows LAPS clear-text
passwords and encrypted values (including history and DSRM attributes). It resolves attribute and
property-set GUIDs from the forest's schema and preserves DACL order, inheritance and scope.
Missing descriptors or schema metadata are explicitly unassessed. The command makes one computer
search with the SD flags control, one targeted schema search and uncached SID lookups; queries
use the normal cache and opsec modes. No password attributes or encrypted values are requested,
and the command does not determine whether a computer actually uses LAPS.

If no LAPS password schema attributes are returned, the command prints one forest-wide notice
instead of repeating it for every computer and attribute. Without the corresponding schema
extension, that LAPS version cannot store passwords in AD anywhere in the forest. An empty
LDAP search can also mean limited schema visibility, so the notice does not prove the extensions
are absent. A returned schema object with unreadable or invalid metadata is reported separately.

The output separates `ReadProperty` and `ControlAccess`: confidential attributes require both,
so a read-property ACE alone does not establish password access. Group memberships and effective
access are not calculated. Reading an encrypted value also does not establish permission to
decrypt it. See Microsoft's [confidential attribute access checks](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential)
and [Windows LAPS schema reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference).

See [directory changes](changes.md) to grant or revoke rights.
