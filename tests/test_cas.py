import pytest
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import cas, templates
from msldap_ops.shell import MSLDAPOpsConsole
from test_cache import cached  # noqa: F401 (fixture)
from test_querylog import patched  # noqa: F401 (fixture)

CONFIG = 'CN=Configuration,DC=forest,DC=local'
DN = 'CN=FOREST-CA,CN=Enrollment Services,' + templates.pki_base(CONFIG)
DOM = 'S-1-5-21-1-2-3'
SDDL = ('O:%s-1105G:%s-512D:'
	'(D;;WP;;;%s-513)'
	'(A;;WD;;;%s-513)'
	'(OA;CIIO;WP;12345678-1234-1234-1234-123456789abc;;%s-513)') % (DOM, DOM, DOM, DOM, DOM)


def ca_entry(raw_sd=True):
	sd = SECURITY_DESCRIPTOR.from_sddl(SDDL)
	return {'objectName': DN, 'attributes': {
		'name': 'FOREST-CA', 'dNSHostName': 'ca.forest.local',
		'certificateTemplates': ['User', 'Machine'],
		'nTSecurityDescriptor': sd.to_bytes() if raw_sd else sd,
		'msPKI-Enrollment-Servers': ['1\n2\nhttps://ca.forest.local/service.svc\n'],
	}}


class Client:
	_tree = 'DC=child,DC=forest,DC=local'

	def __init__(self, entries=None):
		self.entries = entries if entries is not None else [ca_entry()]
		self.queries = []

	def _get_configuration_nc(self):
		return CONFIG

	async def pagedsearch(self, query, attributes, controls=None, tree=None):
		self.queries.append((query, attributes, tree, controls))
		for entry in self.entries:
			yield entry, None

	async def resolv_sid(self, sid):
		return 'FOREST', {DOM + '-1105': 'operator', DOM + '-513': 'Domain Users', DOM + '-512': 'Domain Admins'}.get(sid, sid), None


async def test_ca_search_uses_forest_configuration_and_sd_flags():
	client = Client()
	assert len(await cas.collect(client)) == 1
	query, attributes, base, controls = client.queries[0]
	assert query == '(objectClass=pKIEnrollmentService)'
	assert base == 'CN=Enrollment Services,' + templates.pki_base(CONFIG)
	assert 'nTSecurityDescriptor' in attributes
	assert controls == [templates.sd_flags_control()]
	assert len(client.queries) == 1


async def test_ca_selector_escapes_filter_metacharacters():
	client = Client()
	await cas.collect(client, 'CA*)(name=*)')
	assert '(name=CA\\2a\\29\\28name=\\2a\\29)' in client.queries[0][0]
	assert '(dNSHostName=CA\\2a\\29\\28name=\\2a\\29)' in client.queries[0][0]


@pytest.mark.parametrize('raw_sd', [True, False])
async def test_ca_acl_review_is_explicit_about_scope(raw_sd):
	client = Client()
	lines = await cas.detail_lines(client, ca_entry(raw_sd), width=80)
	out = '\n'.join(lines)
	assert 'CA FOREST-CA' in out
	assert 'Machine' in out and 'User' in out
	assert 'Permissions (AD enrollment-service object)' in out
	assert 'FOREST\\operator' in out
	assert 'WriteDacl' in out and 'deny' in out
	assert 'descendants' in out
	assert '[review] owner is not privileged' in out
	assert '[review] WriteDacl' in out
	assert '[!]' not in out
	assert 'not confirmed effective access or ESC7' in out
	assert 'ESC7: CA service ManageCA/ManageCertificates permissions; query CA RPC/registry.' in out
	assert 'ESC8: Web Enrollment and NTLM/EPA settings; check the actual HTTP(S) endpoint.' in out
	assert 'LDAP metadata; reachability and authentication are not checked' in out
	assert client.queries == []  # decoding a collected descriptor sends no extra LDAP search


async def test_missing_ca_descriptor_is_not_a_clean_check():
	entry = ca_entry()
	entry['attributes'].pop('nTSecurityDescriptor')
	out = '\n'.join(await cas.detail_lines(Client(), entry))
	assert 'Security descriptor unavailable; permissions not assessed.' in out
	assert 'ESC6:' in out and 'ESC7:' in out and 'ESC8:' in out and 'ESC11:' in out
	assert 'No vulnerabilities' not in out


async def test_bad_descriptor_keeps_ca_metadata_and_boundary_notes():
	entry = ca_entry()
	entry['attributes']['nTSecurityDescriptor'] = b'bad'
	out = '\n'.join(await cas.detail_lines(Client(), entry))
	assert 'CA FOREST-CA' in out
	assert 'Cannot decode the security descriptor' in out
	assert 'permissions not assessed' in out
	assert 'requires direct CA access' in out


async def test_ca_command_and_empty_results(capsys):
	console = MSLDAPOpsConsole(None)
	assert await console.do_cas() is False
	console.connection = Client()
	assert await console.do_cas() is True
	assert 'CA FOREST-CA' in capsys.readouterr().out
	console.connection = Client(entries=[])
	assert await console.do_cas() is True
	assert await console.do_cas('missing') is False
	assert 'No matching CAs' in capsys.readouterr().out


async def test_ca_command_reports_search_error(capsys):
	class FailingClient(Client):
		async def pagedsearch(self, *args, **kwargs):
			yield None, ValueError('test failure')
	console = MSLDAPOpsConsole(None)
	console.connection = FailingClient()
	assert await console.do_cas() is False
	assert 'test failure' in capsys.readouterr().out


async def test_cas_reuses_bofhound_ca_collection(cached):
	from msldap.protocol.messages import Control
	from test_cache import CountingConnection
	from test_querylog import raw_entry

	raw = raw_entry(DN)
	raw['attributes'].extend([
		{'type': b'name', 'attributes': [b'FOREST-CA']},
		{'type': b'dNSHostName', 'attributes': [b'ca.forest.local']},
		{'type': b'certificateTemplates', 'attributes': [b'User']},
	])
	connection = CountingConnection([raw])

	class Adapter(Client):
		async def pagedsearch(self, query, attributes, controls=None, tree=None):
			wire_controls = [Control({'controlType': oid.encode(), 'criticality': critical,
				'controlValue': value}) for oid, critical, value in controls or []]
			async for entry in connection.pagedsearch(tree, query, [a.encode() for a in attributes], controls=wire_controls):
				yield entry

	client = Adapter()
	# This is the enterprise-CAs query used by bofhound_collect adcs.
	async for _ in client.pagedsearch('(objectClass=pKIEnrollmentService)', ['*', 'nTSecurityDescriptor'],
			controls=[templates.sd_flags_control()], tree=templates.pki_base(CONFIG)):
		pass
	assert connection.server_calls == 1
	entries = await cas.collect(client)
	assert len(entries) == 1
	assert 'CA FOREST-CA' in '\n'.join(await cas.detail_lines(client, entries[0], cached))
	assert connection.server_calls == 1
	assert cached.hits == 1
