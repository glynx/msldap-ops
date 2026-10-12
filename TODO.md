# TODO

Only open work is listed here. Protocol features are limited to LDAP; direct CA checks via
RPC/registry or HTTP(S), and Windows LAPS decryption via MS-GKDI/RPC, are out of scope.
Automatic cross-domain collection and forest-wide `find_admins` are also out of scope: operators
connect to each DC explicitly and combine logs with bofhound/BloodHound. Previously observed
identity labels are shared within the project's cache directory.

## UX and documentation

- [ ] Optional `map` toolbar below the prompt.
