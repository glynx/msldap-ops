import asyncio

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import acl

D = 'S-1-5-21-1-2-3'
SDDL = ('O:%(d)s-1105G:%(d)s-512D:AI'
	'(A;;0xf01ff;;;%(d)s-512)'                                              # Domain Admins: full control
	'(OA;;WP;bf9679c0-0de6-11d0-a285-00aa003049e2;;%(d)s-1105)'             # jon: write member
	'(OA;CIIO;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;%(d)s-1106)'  # reset password on users
	'(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-11)'               # authenticated users: add self
	'(A;CIID;0x20094;;;S-1-5-11)'                                           # inherited GenericRead
	'(D;;WP;;;S-1-1-0)'                                                     # deny everyone write
	'(OA;;RP;12345678-1234-1234-1234-123456789abc;;%(d)s-1105)'             # read of an unknown property
) % {'d': D}

NAMES = {D + '-1105': 'NORTH\\jon.snow', D + '-1106': 'NORTH\\helpdesk', D + '-512': 'NORTH\\Domain Admins'}


class FakeClient:
	def __init__(self, sddl=SDDL):
		self.sd = SECURITY_DESCRIPTOR.from_sddl(sddl).to_bytes()
		self.calls = []
		self.resolved = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		self.calls.append((query, attributes, tree, search_scope, controls[0][0]))
		yield {'objectName': tree, 'attributes': {'nTSecurityDescriptor': self.sd}}, None

	async def resolv_sid(self, sid):
		self.resolved.append(sid)
		if sid in NAMES:
			return NAMES[sid].split('\\')[0], NAMES[sid].split('\\')[1], None
		return {'S-1-5-11': ('BUILTIN', 'Authenticated Users'), 'S-1-1-0': ('BUILTIN', 'Everyone')}.get(sid, ('???', '???')) + (None,)


def collect(client=None):
	client = client or FakeClient()
	return client, asyncio.run(acl.collect(client, 'CN=g,DC=x'))


def test_rights():
	assert acl.rights(0xf01ff) == ['FullControl']
	assert acl.rights(0x20094) == ['GenericRead']
	assert acl.rights(0x20028) == ['GenericWrite']
	assert acl.rights(0x40000 | 0x80000) == ['WriteDacl', 'WriteOwner']
	assert acl.rights(0x10000000) == ['GenericAll']


def test_entries_are_decoded():
	client, (sd, entries, principals, source) = collect()
	assert source is None  # no cache: live
	assert client.calls == [('(objectClass=*)', ['nTSecurityDescriptor'], 'CN=g,DC=x', 0, '1.2.840.113556.1.4.801')]
	by = {(e.principal, e.object): e for e in entries}
	member = by[('NORTH\\jon.snow', 'member')]
	assert member.rights == ['WriteProperty'] and member.scope == 'this object' and member.findings == ['Write member']
	assert member.risky
	reset = by[('NORTH\\helpdesk', 'Reset Password')]
	assert reset.scope == 'user objects' and reset.applies_to == 'user' and reset.risky
	addself = by[('BUILTIN\\Authenticated Users', 'Self-Membership')]
	assert addself.findings == ['AddSelf'] and addself.risky
	admins = by[('NORTH\\Domain Admins', None)]
	assert admins.findings == ['FullControl'] and not admins.risky  # privileged
	read = by[('BUILTIN\\Authenticated Users', None)]
	assert read.inherited and read.scope == 'this object and descendants' and not read.findings
	deny = by[('BUILTIN\\Everyone', None)]
	assert not deny.allow and not deny.findings
	assert by[('NORTH\\jon.snow', '12345678-1234-1234-1234-123456789abc')].rights == ['ReadProperty']


def test_format():
	client, result = collect()
	lines = acl.format_acl('CN=g,DC=x', *result)
	assert lines[0] == 'ACL of CN=g,DC=x'
	assert lines[1] == '  Owner: NORTH\\jon.snow  [!] owner is not privileged (can rewrite the DACL)'
	assert lines[3] == '  DACL: 7 entries, 1 inherited'
	header = lines[5]
	assert header.split() == ['Access', 'Principal', 'Rights', 'Object', 'Applies', 'to']
	# deny first, inherited last
	assert lines[6].strip().startswith('deny ')
	assert lines[-1].strip().startswith('allow (inh.)')
	assert any(l.rstrip().endswith('[!] Write member') for l in lines)

	risky = acl.format_acl('CN=g,DC=x', *result, show='risky')
	assert len([l for l in risky if '[!]' in l and 'allow' in l]) == 3
	explicit = acl.format_acl('CN=g,DC=x', *result, show='explicit')
	assert not any('(inh.)' in l for l in explicit)


def test_schema_names_from_the_cache():
	import base64
	import uuid
	guid = uuid.UUID('12345678-1234-1234-1234-123456789abc')

	class Cache:
		queries = {'k': {'entries': [{'dn': 'CN=ms-Mcs-AdmPwd,CN=Schema', 'a': [
			['name', [base64.b64encode(b'ms-Mcs-AdmPwd').decode()]],
			['schemaIDGUID', [base64.b64encode(guid.bytes_le).decode()]]]}]}}

	names = acl.schema_names_from_cache(Cache())
	assert names == {str(guid): 'ms-Mcs-AdmPwd'}
	assert acl.GuidNames(names).object_type(str(guid), 'property') == 'ms-Mcs-AdmPwd'


def test_privileged():
	assert acl.is_privileged('S-1-5-18') and acl.is_privileged(D + '-519') and acl.is_privileged('S-1-5-10')
	assert not acl.is_privileged(D + '-513') and not acl.is_privileged('S-1-5-11')


def test_acl_command(capsys):
	from msldap_ops.shell import MSLDAPOpsConsole
	console = MSLDAPOpsConsole(None)
	console.connection = FakeClient()
	console.connection._serverinfo = {'namingContexts': ['DC=x']}
	console._current_dn = 'DC=x'
	assert asyncio.run(console.do_acl('risky')) is True
	assert console.connection.calls[-1][2] == 'DC=x'
	out = capsys.readouterr().out
	assert 'ACL of DC=x' in out and 'GenericRead' not in out
	assert asyncio.run(console.do_acl('CN=g', 'explicit')) is True
	assert console.connection.calls[-1][2] == 'CN=g,DC=x'
	assert asyncio.run(console.do_acl('.', 'bogus')) is False


def test_layout_follows_the_terminal_width():
	client, result = collect()
	wide = acl.format_acl('CN=g,DC=x', *result, width=200)
	assert wide == acl.format_acl('CN=g,DC=x', *result)  # fits: the plain table
	assert all(len(line) <= 200 for line in wide)
	# shrunk at word boundaries: no word is split
	rows = [('a', 'NORTH\\Domain Admins', 'x'), ('b', 'short', 'y')]
	widths = acl.fit_widths(rows, '  ', 20, wrap_columns=(1,))
	assert acl.table(rows, widths=widths) == ['  a  NORTH\\Domain  x', '     Admins', '  b  short         y']
	# too narrow for the table: one block per entry, nothing wider than the terminal
	narrow = acl.format_acl('CN=g,DC=x', *result, width=80)
	assert '  allow         NORTH\\jon.snow' in narrow
	assert '                WriteProperty: member (this object)  [!] Write' in narrow
	assert all(len(line) <= 80 for line in narrow)


def cached_sd_cache(tmp_path, controls):
	"""A cache holding the object CN=g,DC=x with the test security descriptor and an account."""
	from winacl.dtyp.sid import SID

	from msldap_ops.cache import QueryCache, query_key

	cache = QueryCache(str(tmp_path), persist=False)
	sd = SECURITY_DESCRIPTOR.from_sddl(SDDL).to_bytes()
	raws = [
		{'objectName': b'CN=g,DC=x', 'attributes': [{'type': b'nTSecurityDescriptor', 'attributes': [sd]}]},
		{'objectName': b'CN=jon.snow,DC=x', 'attributes': [
			{'type': b'objectSid', 'attributes': [SID.from_string(D + '-1105').to_bytes()]},
			{'type': b'sAMAccountName', 'attributes': [b'jon.snow']}]},
	]

	class Control:
		def __init__(self, data):
			self.data = data

		def dump(self):
			return self.data

	params = {'base': 'DC=x', 'search_scope': 2, 'query': '(objectClass=*)', 'attributes': ['*', 'nTSecurityDescriptor'],
		'controls': [Control(c) for c in controls]}
	key, parts = query_key('pagedsearch', params)
	cache.put(key, parts, raws)
	return cache


class SidCacheClient(FakeClient):
	"""resolv_sid like msldap: names from _sid_cache need no search."""

	def __init__(self):
		super().__init__()
		self._sid_cache = {}

	async def resolv_sid(self, sid):
		if sid.upper() in self._sid_cache:
			return 'NORTH', self._sid_cache[sid.upper()], None
		return await FakeClient.resolv_sid(self, sid)


def test_security_descriptor_and_names_from_the_cache(tmp_path):
	cache = cached_sd_cache(tmp_path, [b'1.2.840.113556.1.4.801 sd flags'])
	client = SidCacheClient()
	sd, entries, principals, source = asyncio.run(acl.collect(client, 'CN=g,DC=x', cache))
	assert client.calls == []  # no search for the security descriptor
	assert source is not None
	assert D + '-1105' not in client.resolved  # known from the cache
	assert principals[D + '-1105'] == 'NORTH\\jon.snow'
	assert acl.format_acl('CN=g,DC=x', sd, entries, principals, source)[0].startswith('ACL of CN=g,DC=x  (from the cache, ')


def test_cached_result_without_sd_flags_is_not_used(tmp_path):
	# without the SD flags control the cached descriptor may be partial (or the SACL variant)
	cache = cached_sd_cache(tmp_path, [b'1.2.840.113556.1.4.319 paged'])
	client = SidCacheClient()
	result = asyncio.run(acl.collect(client, 'CN=g,DC=x', cache))
	assert len(client.calls) == 1 and result[3] is None
