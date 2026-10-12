# Navigation and lookup

[Back to README](../README.md)

Browse naming contexts, find objects and display the structure seen so far.

Use `help <command>` in the shell for command-specific usage.

## Navigation

```text
cd ..                    parent DN (refused above the naming context of the DC, with a hint)
cd ../..                 two levels up
cd CN=Computers          relative to the current DN, also deeper: OU=Servers,OU=Tier0
cd <DN>                  absolute, any naming context of the DC (e.g. CN=Configuration,...)
ls [path|pattern] [full] children of the current DN (no query) or of a path, e.g. ls CN=Users,
                         ls Domain*, ls ../OU=*; full prints DNs
cat [path] [attributes]  attributes of the current object (cat, cat .), of every child (cat *),
                         of matching children (cat CN=Domain*, cat ../OU=*) or of a DN/path
query <filter> [attributes] [base|path] [base|one|sub]
find <name|pattern> [path]  DNs of objects by sAMAccountName or name, '*' as wildcard
                         (searches the naming context of the current DN)
acl [path] [all|explicit|risky]  readable ACL of an object (owner, rights, object types, scope)
getsd [path] [p|g]       msldap's raw security descriptor, with paths as for cd
map [DN|path] [depth]    tree of the DNs seen so far below a DN (default: current, 3 levels)
tree [DN|path] [level]   directory tree queried from the DC (default: domain root, 1 level)
```

`cd` completes direct children of the current DN and the naming contexts of the DC. Deeper cached
paths appear after an unescaped comma (`cd CN=User,`). Escaped commas (`CN=Doe\, John`) are handled
without enabling deeper matches; completions are
quoted so that aiocmd's argument parsing keeps them intact. `cat` takes attributes as a comma separated
list (`cat * cn,description`); msldap's order `cat [attributes] [path]` works as well. `map` sends no query, it draws the DN
index of the query cache and may therefore be incomplete. `tree` asks the DC (one search per
container down to the level) and fills the cache, so its results show up in `map` as well.
Both use Rich trees with relative node names; `map` marks children hidden by its depth limit
with `(+n)`. Redirected output keeps the tree structure without terminal colors.

In the terminal, `ls`, `map` and `tree` share Rich labels, and `cat` adds a type icon to the DN:
🖥️ computer, 👤 user, 👥 group, 🗂️ OU, 📁 container, 🌐 domain, 📜 GPO/template, 🔗 trust and
📄 an unrecognized object class. If `userAccountControl` contains `ACCOUNTDISABLE`, the label
is gray and marked `[disabled]`; the object remains visible. Missing type or status metadata
adds no icon or status marker.

Listings and object reads request `objectClass` and `userAccountControl` together with their
existing attributes, without a separate query per object. `ls` of the current DN reuses the
listing from `cd`; cached metadata is reused as well. `map` and `tree` decorate only from metadata
already available, without additional lookups. Internally added attributes stay out of an
explicitly selected `cat` attribute list. Pipes, file output and `--no-color` keep plain labels.

| Command | Default target | Other defaults |
| --- | --- | --- |
| `ls` | Current DN | Reuses the current listing; `full` shows DNs |
| `cat` | Current object | All regular attributes; comma separated attribute list |
| `find` | Naming context of the current DN | Pattern required; `*` is a wildcard |
| `map` | Current DN | Depth `3`; `0` shows all known levels |
| `tree` | Domain root | Level `1`; `tree 2` is shorthand for two levels |

## SID lookup

`sid2dn <SID>` returns an object's DN. It requests `distinguishedName`, `objectSid` and
`sAMAccountName` in one query, so account names are also retained in the
[identity catalogue](operations.md#identity-catalogue). If an object has no readable
`sAMAccountName`, its DN is still returned without inventing an account name.

For msldap's other lookup commands (`sam2dn`, `dn2sid`, `dn2sam`, `sidresolv`), use
`help <command>` or the [msldap repository](https://github.com/glynx/msldap).

## Differences to msldap

msldap-ops keeps msldap's commands, but changes some where msldap's behaviour is not what a shell
user expects:

- `cat` takes the path first: `cat [path] [attributes]`. `cat *` shows every child of the current
  DN (in msldap: all attributes of the current object, now `cat` or `cat .`). msldap's order
  `cat cn,description CN=Users` is still recognized.
- `ls` takes a path or pattern (`ls CN=Users`, `ls Domain*`); msldap's `ls <anything>` (full DNs)
  works as before.
- `cd` resolves `..`, `../..` and relative paths properly, also with escaped commas, and stops at
  the top of the naming context with an explanation instead of a referral error.
- `query` and `cat` print objects in one layout (see [Output](operations.md#output)), `query` takes a base path
  and a scope.
- A pasted block of several lines runs one command per line.

Raw filter, attribute and scope examples are in [Queries](queries.md#ldap-queries).
