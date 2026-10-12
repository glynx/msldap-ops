# Directory changes and cleanup

[Back to README](../README.md)

Grant rights, edit attributes and manage credentials, with session change tracking and undo.

Use `help <command>` in the shell for command-specific usage.

Paths resolve as for [navigation](navigation.md); optional paths default to the current object
(`.`). Principals are SIDs or exact account names. All writes use the
[opsec gate](operations.md#opsec); `opsec confirm-write` confirms writes while reads run silently.
Write commands read their inputs from LDAP even when a query cache entry exists, so an older
cached DACL or account flag value cannot overwrite more recent changes. Read-only `uac`, `rbcd`
and `keycred` listings still use the cache. This does not make a read followed by a write atomic;
another operator can still change an object between those operations.

## Granting and revoking rights

`grant` and `revoke` add or remove an ACE on an object's DACL for a principal, by a high-level right
name instead of raw SDDL:

```text
grant <principal> <right> [path]    add the right
revoke <principal> <right> [path]   remove it again
```

`principal` is a SID or an exact account name (resolved to its SID), `path` the target object (as
for `cd`, default the current object). Rights: `fullcontrol`, `genericwrite`, `writedacl`,
`writeowner`, `allextendedrights`, `resetpassword`, `dcsync` (adds the two replication ACEs),
`writemembers`, `writespn`, `writekeycredential` (shadow credentials), `rbcd`.

The command reads the security descriptor, adds or removes the matching ACE(s) and writes back only
the DACL, so `WriteDacl` on the target is enough (writing the owner would need `WriteOwner` and the
DC rejects it). `grant` is idempotent (an ACE already present is not added again). The change goes
through opsec like any other, and `undo` restores the previous DACL.

## Owner, RBCD and key credentials

```text
chown <path> <principal>        set the owner of an object's security descriptor
rbcd [path]                     list the principals allowed to act on behalf of the object
rbcd <path> add <principal>     allow a principal (resource-based constrained delegation)
rbcd <path> clear               remove all RBCD
keycred [path]                  list the key credentials (msDS-KeyCredentialLink)
keycred <path> add [file.pfx]   add a shadow credential and save its certificate and private key
keycred <path> remove <id>      remove one credential by Device ID or Key ID
keycred <path> clear            remove all of them (clean up a shadow-credentials attack)
```

`chown` needs `WriteOwner`; owning an object lets you rewrite its DACL. `rbcd add` writes an
allow-all ACE for the principal into `msDS-AllowedToActOnBehalfOfOtherIdentity` (adding a key
credential is `keycred <path> add`). All of these go through opsec and are undoable.
Adding preserves existing credentials; undo removes only the new value. Listing shows Device IDs
and Key IDs for `remove`, so cleanup also works in later sessions. Removal deletes exactly one
matching value and is undoable; ambiguous IDs are refused. The PFX has no password
and is created with mode 0600 without overwriting files. Without a filename it is saved as
`keycred-<id>.pfx` in the local working directory. It is saved before the LDAP write and retained
if the write fails or is declined; `opsec dryrun` creates no file. `shadowcred` remains callable
as a legacy command; use `keycred` for the combined workflow.

## Editing attributes

`setattr`, `addattr` and `delattr` change an attribute directly, `uac` the account flags:

```text
setattr <path> <attribute> [value ...]   replace the value(s) (no value clears the attribute)
addattr <path> <attribute> <value>       add one value to a multi-valued attribute
delattr <path> <attribute> <value>       remove one value
uac [path]                               show the userAccountControl flags
uac <path> +FLAG -FLAG                    set (+) or clear (-) flags
```

Values are written as given, so attributes with a non-string syntax may be rejected by the server.
`uac` flag names are those of `userAccountControl`, e.g. `+DONT_REQUIRE_PREAUTH` (AS-REP roasting),
`+TRUSTED_FOR_DELEGATION`, `-ACCOUNTDISABLE`; a hex value also works. All of these are gated by
opsec and undoable.

## Changes and undo

Every directory change (add, modify, delete) is recorded in a session change log with its inverse,
so it can be undone:

```text
changes       list the changes of this session, newest last, with an index and whether each
              can be undone
undo          reverse the last change that can be undone
undo <n>      reverse change #n
```

Before a change is sent, the old value it needs for the inverse is read (one background search,
not shown or logged). `add`/`delete` of a value invert directly, a `replace` is restored to the old
value, and a created object is removed again. Not undoable automatically: deleting an object,
changing a password (the old one is unknown) and a value that could not be read back; `changes`
shows the reason. A successful `undo` removes the change from the list and is not itself added as a
new change; the query journal still records the undo write for the audit trail.
