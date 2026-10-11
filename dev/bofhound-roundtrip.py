"""Offline check of the query log format against bofhound.

Writes a log with a domain, a user, a group and a computer (each with a security descriptor that
grants GenericAll to the user) and prints the uvx command that imports it:

	uv run python dev/bofhound-roundtrip.py /tmp/roundtrip
	uvx bofhound -i /tmp/roundtrip -o /tmp/roundtrip/out

The resulting JSON must contain the four objects, the group membership and the GenericAll edges.
"""

import sys
import uuid

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.sid import SID

from msldap_ops.hooks import QueryInfo, SearchEntry
from msldap_ops.querylog import QueryLog

DOMAIN_SID = 'S-1-5-21-1111111111-2222222222-3333333333'
BASE = 'DC=north,DC=sevenkingdoms,DC=local'
SD = SECURITY_DESCRIPTOR.from_sddl(
	'O:{0}-512G:{0}-512D:(A;;0xf01ff;;;{0}-1104)(A;;RP;;;S-1-5-11)'.format(DOMAIN_SID)
).to_bytes()


def sid(value):
	return [SID.from_string(value).to_bytes()]


def entry(dn, **attrs):
	attrs.setdefault('distinguishedName', [dn.encode()])
	attrs.setdefault('nTSecurityDescriptor', [SD])
	attrs.setdefault('objectGUID', [uuid.uuid4().bytes_le])
	attrs.setdefault('whenCreated', [b'20221213101112.0Z'])
	result = SearchEntry()
	result.raw = {
		'objectName': dn.encode(),
		'attributes': [{'type': k.encode(), 'attributes': v} for k, v in attrs.items()],
	}
	return result


ENTRIES = [
	entry(BASE, objectClass=[b'top', b'domain', b'domainDNS'], objectSid=sid(DOMAIN_SID), name=[b'north']),
	entry(
		'CN=jon.snow,CN=Users,' + BASE,
		objectClass=[b'top', b'person', b'organizationalPerson', b'user'],
		sAMAccountName=[b'jon.snow'], sAMAccountType=[b'805306368'], objectSid=sid(DOMAIN_SID + '-1104'),
		userAccountControl=[b'66048'], pwdLastSet=[b'133150000000000000'],
		servicePrincipalName=[b'HTTP/thewall.north.sevenkingdoms.local'],
		description=[b'Lord\r\nCommander'],
	),
	entry(
		'CN=Night Watch,CN=Users,' + BASE,
		objectClass=[b'top', b'group'], sAMAccountName=[b'Night Watch'], sAMAccountType=[b'268435456'],
		objectSid=sid(DOMAIN_SID + '-1107'), member=[('CN=jon.snow,CN=Users,' + BASE).encode()],
	),
	entry(
		'CN=WINTERFELL,OU=Domain Controllers,' + BASE,
		objectClass=[b'top', b'person', b'organizationalPerson', b'user', b'computer'],
		sAMAccountName=[b'WINTERFELL$'], sAMAccountType=[b'805306369'], objectSid=sid(DOMAIN_SID + '-1001'),
		dNSHostName=[b'winterfell.north.sevenkingdoms.local'], userAccountControl=[b'532480'],
	),
]


def main():
	querylog = QueryLog(sys.argv[1] if len(sys.argv) > 1 else 'dev/.work/roundtrip')
	query = QueryInfo('offline', BASE, '(objectClass=*)', [b'*', b'nTSecurityDescriptor'], 2, [])
	for e in ENTRIES:
		querylog.query_entry(query, e)
		query.count += 1
	querylog.query_end(query)
	print('written: %s' % querylog.path)
	print('import:  uvx bofhound -i %s -o %s/out' % (querylog.directory, querylog.directory))


if __name__ == '__main__':
	main()
