import datetime

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import records
from msldap_ops.shell import MSLDAPOpsConsole

DOMAIN = 'DC=essos,DC=local'


def test_record_lines():
	lines = records.record_lines(DOMAIN, {
		'objectClass': ['top', 'domain', 'domainDNS'],
		'distinguishedName': DOMAIN,
		'whenCreated': datetime.datetime(2026, 4, 20, 23, 31, 41, tzinfo=datetime.timezone.utc),
		'dSASignature': b'\x01\x00',
		'description': 'first\nsecond',
	})
	assert lines == [
		'---',
		'DN: DC=essos,DC=local',
		'  objectClass:       top',
		'                     domain',
		'                     domainDNS',
		'  distinguishedName: DC=essos,DC=local',
		'  whenCreated:       2026-04-20 23:31:41+00:00',
		'  dSASignature:      0100',
		'  description:       first',
		'                     second',
	]


def test_security_descriptor_as_sddl():
	sd = SECURITY_DESCRIPTOR.from_sddl('O:S-1-5-32-544G:S-1-5-32-544D:(A;;0xf01ff;;;S-1-5-32-544)')
	assert records.value_str('nTSecurityDescriptor', sd.to_bytes()).startswith('O:BAG:BA') or \
		records.value_str('nTSecurityDescriptor', sd.to_bytes()).startswith('O:S-1-5-32-544')


def test_long_names_do_not_break_the_layout():
	lines = records.record_lines('CN=x', {'a': 1, 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts': True})
	assert lines[2].startswith('  a:')
	assert lines[3] == '  msDS-ExpirePasswordsOnSmartCardOnlyAccounts: True'


class FakeClient:
	def __init__(self):
		self._serverinfo = {'namingContexts': [DOMAIN]}
		self.calls = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		self.calls.append((query, attributes, controls, tree, search_scope))
		for i in range(2 if search_scope == 2 else 1):
			yield {'objectName': 'CN=u%d,CN=Users,%s' % (i, DOMAIN), 'attributes': {'cn': 'u%d' % i}}, None


async def test_query_and_cat(capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = FakeClient()
	console._current_dn = 'CN=Users,' + DOMAIN

	assert await console.do_query('(cn=*)', 'cn,nTSecurityDescriptor', '..', 'one') is True
	query, attrs, controls, tree, scope = console.connection.calls[-1]
	assert attrs == ['cn', 'nTSecurityDescriptor'] and controls[0][0] == '1.2.840.113556.1.4.801'
	assert tree == DOMAIN and scope == 1
	out = capsys.readouterr().out
	assert out.count('---\nDN: ') == 1 and out.rstrip().endswith('(1 object)')

	assert await console.do_cat('*', 'CN=u0') is True
	query, attrs, controls, tree, scope = console.connection.calls[-1]
	assert (query, tree, scope, controls) == ('(objectClass=*)', 'CN=u0,CN=Users,' + DOMAIN, 0, None)
	assert 'objects)' not in capsys.readouterr().out

	assert await console.do_query('(cn=*)', '*', '-', 'bogus') is False

	# cat: the current object, every child, a pattern
	assert await console.do_cat() is True
	assert console.connection.calls[-1][3:] == ('CN=Users,' + DOMAIN, 0)
	assert await console.do_cat('.', 'cn') is True
	assert console.connection.calls[-1][1] == ['cn']
	capsys.readouterr()
	assert await console.do_cat('*') is True
	query, attrs, controls, tree, scope = console.connection.calls[-1]
	assert (query, attrs, tree, scope) == ('(objectClass=*)', ['*'], 'CN=Users,' + DOMAIN, 1)
	assert capsys.readouterr().out.rstrip().endswith('object)')
	assert await console.do_cat('../CN=Dom*', 'cn') is True
	query, attrs, controls, tree, scope = console.connection.calls[-1]
	assert (query, attrs, tree, scope) == ('(CN=Dom*)', ['cn'], DOMAIN, 1)


def test_search_errors_are_readable():
	from msldap.commons.exceptions import LDAPSearchException
	err = LDAPSearchException('noSuchObject', b"0000208D: NameErr: DSID-03100245, problem 2001 (NO_OBJECT), data 0, best match of:\n\t'CN=Builtin,DC=essos,DC=local'\n\x00")
	assert records.search_error(err, 'CN=Administrators,CN=Users,CN=Builtin,DC=essos,DC=local') == (
		'No such object: CN=Administrators,CN=Users,CN=Builtin,DC=essos,DC=local\n'
		'  closest existing object: CN=Builtin,DC=essos,DC=local')
	err = LDAPSearchException('insufficientAccessRights', b'00002098: SecErr: DSID-03150F94\n\x00')
	assert records.search_error(err, 'DC=x') == 'Search failed (insufficientAccessRights): 00002098: SecErr: DSID-03150F94'
	assert records.search_error(RuntimeError('boom'), 'DC=x') == 'Search failed: boom'


class TreeClient:
	_serverinfo = {'namingContexts': [DOMAIN]}

	def __init__(self):
		self.calls = []

	async def get_tree_plot(self, dn, level=2):
		self.calls.append((dn, level))
		return {dn: {'CN=Domain Admins,%s' % dn: {}, 'CN=Domain Users,%s' % dn: {}, 'CN=krbtgt,%s' % dn: {}}}


async def test_ls(capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = TreeClient()
	console._current_dn = DOMAIN
	console._MSLDAPClientConsole__current_dirs = {'CN=Users': 'CN=Users,' + DOMAIN, 'OU=Laps': 'OU=Laps,' + DOMAIN}

	# the current DN: known from cd, no query
	assert await console.do_ls() is True
	assert capsys.readouterr().out == 'CN=Users\nOU=Laps\n'
	assert await console.do_ls('OU=*') is True
	assert capsys.readouterr().out == 'OU=Laps\n'
	assert console.connection.calls == []
	# msldap: ls <anything> prints full DNs
	assert await console.do_ls('1') is True
	assert capsys.readouterr().out == 'CN=Users,%s\nOU=Laps,%s\n' % (DOMAIN, DOMAIN)

	# a path: the one level search of cd
	assert await console.do_ls('CN=Users') is True
	assert console.connection.calls[-1] == ('CN=Users,' + DOMAIN, 1)
	assert capsys.readouterr().out == 'CN=Domain Admins\nCN=Domain Users\nCN=krbtgt\n'
	assert await console.do_ls('Domain*,CN=Users', 'full') is True
	assert capsys.readouterr().out == 'CN=Domain Admins,CN=Users,%s\nCN=Domain Users,CN=Users,%s\n' % (DOMAIN, DOMAIN)
	assert await console.do_ls('CN=x*,CN=Users') is True
	assert capsys.readouterr().out == 'No match for CN=x*\n'


def test_rdn_matches():
	from msldap_ops.navigation import rdn_matches
	assert rdn_matches('CN=Domain Admins', '*')
	assert rdn_matches('CN=Domain Admins', 'domain*')
	assert rdn_matches('CN=Domain Admins', 'CN=Dom*')
	assert not rdn_matches('OU=Domain Controllers', 'CN=Dom*')
	assert rdn_matches('CN=x[1]', 'CN=x[1]*')
