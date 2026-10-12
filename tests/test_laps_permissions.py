import uuid

import pytest
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import acl, laps, laps_permissions as permissions
from msldap_ops.shell import MSLDAPOpsConsole

DOMAIN = 'DC=north,DC=example'
SCHEMA = 'CN=Schema,CN=Configuration,DC=example'
LEGACY = '12345678-1234-1234-1234-123456789abc'
CLEAR = '22345678-1234-1234-1234-123456789abc'
ENCRYPTED = '32345678-1234-1234-1234-123456789abc'
PROPERTY_SET = 'f3531ec6-6330-4f8e-8d39-7a671fbac605'
UNRELATED = '42345678-1234-1234-1234-123456789abc'
ATTRIBUTES = {
	'ms-mcs-admpwd': permissions.Attribute('ms-Mcs-AdmPwd', LEGACY, None, True),
	'mslaps-password': permissions.Attribute('msLAPS-Password', CLEAR, None, True),
	'mslaps-encryptedpassword': permissions.Attribute('msLAPS-EncryptedPassword', ENCRYPTED, PROPERTY_SET, True),
}


def decoded(sddl):
	sd = SECURITY_DESCRIPTOR.from_sddl('D:' + sddl)
	return [acl.Entry(ace, str(ace.Sid), acl.GuidNames()) for ace in sd.Dacl.aces]


@pytest.mark.parametrize('ace,expected', [
	('(A;;RP;;;S-1-5-11)', ['ReadProperty']),
	('(A;;GR;;;S-1-5-11)', ['ReadProperty']),
	('(A;;CR;;;S-1-5-11)', ['ControlAccess']),
	('(A;;GA;;;S-1-5-11)', ['ReadProperty', 'ControlAccess']),
	('(A;;0xf01ff;;;S-1-5-11)', ['ReadProperty', 'ControlAccess']),
	('(A;;GW;;;S-1-5-11)', []),
	('(A;;0xc0000;;;S-1-5-11)', []),
	('(OA;;0x110;%s;;S-1-5-11)' % LEGACY, ['ReadProperty', 'ControlAccess']),
	('(OD;;0x110;%s;;S-1-5-11)' % LEGACY, ['ReadProperty', 'ControlAccess']),
	('(OA;;0x110;%s;;S-1-5-11)' % UNRELATED, []),
	('(OA;CIIO;0x110;%s;;S-1-5-11)' % LEGACY, []),
	('(OA;ID;0x110;%s;;S-1-5-11)' % LEGACY, ['ReadProperty', 'ControlAccess']),
])
def test_read_components(ace, expected):
	assert permissions.components(decoded(ace)[0], ATTRIBUTES['ms-mcs-admpwd']) == expected


def test_property_sets_and_confidential_flag():
	e = decoded('(OA;;0x110;%s;;S-1-5-11)' % PROPERTY_SET)[0]
	assert permissions.components(e, ATTRIBUTES['mslaps-encryptedpassword']) == ['ReadProperty', 'ControlAccess']
	assert permissions.components(e, ATTRIBUTES['mslaps-password']) == []
	public = permissions.Attribute('test', ENCRYPTED, PROPERTY_SET, False)
	assert permissions.components(e, public) == ['ReadProperty']


class Client:
	_tree = DOMAIN
	_serverinfo = {
		'defaultNamingContext': DOMAIN,
		'rootDomainNamingContext': 'DC=example',
		'schemaNamingContext': SCHEMA,
	}

	def __init__(self, sd='D:(A;;RP;;;S-1-5-11)(OA;;CR;%s;;S-1-5-32-544)' % LEGACY,
		entries=True, schema_error=None):
		self.calls = []
		self.sd = (sd.to_bytes() if isinstance(sd, SECURITY_DESCRIPTOR) else
			SECURITY_DESCRIPTOR.from_sddl(sd).to_bytes() if sd else None)
		self.entries = entries
		self.schema_error = schema_error
		self.resolved = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		# Check the complete LDAP request, including filters: no secret attributes at all.
		requested = {a.lower() for a in attributes}
		assert '*' not in requested
		assert not requested.intersection(n.lower() for n in permissions.PASSWORD_ATTRIBUTES)
		assert not any(n.lower() in query.lower() for n in permissions.PASSWORD_ATTRIBUTES) or tree == SCHEMA
		self.calls.append((query, attributes, controls, tree, search_scope))
		if tree == SCHEMA:
			if self.schema_error:
				yield None, self.schema_error
				return
			for attribute in ATTRIBUTES.values():
				yield {'objectName': 'CN=%s,%s' % (attribute.name, tree), 'attributes': {
					'lDAPDisplayName': attribute.name,
					'schemaIDGUID': uuid.UUID(attribute.guid).bytes_le,
					'attributeSecurityGUID': uuid.UUID(attribute.property_set).bytes_le if attribute.property_set else None,
					'searchFlags': 904,
				}}, None
		elif self.entries:
			yield {'objectName': 'CN=PC1,' + DOMAIN, 'attributes': {
				'cn': 'PC1', 'sAMAccountName': 'PC1$', 'nTSecurityDescriptor': self.sd,
			}}, None

	async def resolv_sid(self, sid):
		self.resolved.append(sid)
		return 'BUILTIN', {'S-1-5-11': 'Authenticated Users', 'S-1-5-32-544': 'Administrators'}.get(sid, sid), None


async def test_schema_guids_and_search_base():
	client = Client()
	assert await permissions.schema(client) == ATTRIBUTES
	query, attrs, controls, base, _ = client.calls[0]
	assert base == SCHEMA  # forest root, not the child domain
	assert attrs == permissions.SCHEMA_ATTRIBUTES and controls is None
	assert '(objectClass=attributeSchema)' in query


@pytest.mark.parametrize('target,scope', [('.', 0), ('PC1', 2), ('PC1$', 2), ('*srv*', 2), ('all', 2)])
async def test_command_selects_computers_without_password_reads(target, scope, capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = Client()
	console._current_dn = 'CN=PC1,' + DOMAIN
	assert await console.do_laps_permissions(target) is True
	query, attrs, controls, base, actual_scope = console.connection.calls[0]
	assert (base, query, actual_scope) == laps.search_target(target, console._current_dn, DOMAIN)
	assert actual_scope == scope
	assert attrs == ['cn', 'sAMAccountName', 'nTSecurityDescriptor']
	assert controls[0][0] == '1.2.840.113556.1.4.801'
	assert len(console.connection.calls) == 2
	out = capsys.readouterr().out
	assert 'LAPS permissions of CN=PC1,' in out
	assert 'BUILTIN\\Administrators' in out
	assert 'ReadProperty AND ControlAccess' in out
	assert 'decryption permission' in out
	assert '(1 object)' in out


async def test_deny_inheritance_and_unrelated_aces_are_preserved(capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = Client(sd=(
		'D:(OA;ID;0x110;%s;;S-1-5-11)' % LEGACY +
		'(OD;;CR;%s;;S-1-5-11)' % LEGACY +
		'(OA;CIIO;0x110;%s;;S-1-5-32-544)' % LEGACY +
		'(OA;;CR;%s;;S-1-5-32-544)' % UNRELATED))
	assert await console.do_laps_permissions('PC1') is True
	out = capsys.readouterr().out
	legacy = out.split('  Legacy LAPS')[1].split('  Windows LAPS')[0]
	assert 'allow (inh.)' in legacy and 'deny' in legacy
	assert legacy.index('allow (inh.)') < legacy.index('deny')  # original DACL order
	assert 'BUILTIN\\Administrators' not in legacy  # IO and unrelated GUID excluded


@pytest.mark.parametrize('sd', [None, SECURITY_DESCRIPTOR.from_bytes(b'\x01\x00\x00\x80' + b'\x00' * 16)])
async def test_missing_or_null_dacl_is_unassessed(sd, capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = Client(sd=sd)
	assert await console.do_laps_permissions('PC1') is False
	assert 'unassessed' in capsys.readouterr().out


async def test_schema_failure_is_unassessed(capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = Client(schema_error=ValueError('schema denied'))
	assert await console.do_laps_permissions('PC1') is False
	assert 'LAPS schema unavailable; permissions unassessed: schema denied' in capsys.readouterr().out


async def test_no_connection_or_no_computers(capsys):
	console = MSLDAPOpsConsole(None)
	assert await console.do_laps_permissions() is False
	assert 'Not connected' in capsys.readouterr().out
	console.connection = Client(entries=False)
	assert await console.do_laps_permissions('missing') is True
	assert 'No computers matched' in capsys.readouterr().out
	assert len(console.connection.calls) == 1  # no schema search needed


async def test_unknown_confidential_flag_and_narrow_layout():
	client = Client()
	entry = (await permissions.collect_computers(client, 'PC1', DOMAIN))[0]
	attributes = {'ms-mcs-admpwd': permissions.Attribute('ms-Mcs-AdmPwd', LEGACY, None, None)}
	lines, ok = await permissions.detail_lines(client, entry, attributes, width=80)
	assert not ok
	assert any('Confidential flag unavailable' in line for line in lines)
	assert any('allow' in line for line in lines)
	assert all(any(word in line for line in lines) for word in ('Authenticated', 'Users'))
	assert any('ControlAccess' in line for line in lines)


async def test_unreadable_schema_does_not_claim_no_permissions(monkeypatch, capsys):
	async def empty_schema(client):
		return {}
	monkeypatch.setattr(permissions, 'schema', empty_schema)
	console = MSLDAPOpsConsole(None)
	console.connection = Client()
	assert await console.do_laps_permissions('PC1') is False
	out = capsys.readouterr().out
	assert out.count('No LAPS password schema attributes were returned by LDAP.') == 1
	assert 'neither legacy nor Windows LAPS can store passwords' in out
	assert 'limited schema visibility; permissions unassessed' in out
	assert '(no matching read-related ACEs)' not in out
	assert 'LAPS permissions of' not in out
	assert console.connection.resolved == []


async def test_real_ldap_schema_conversion_preserves_valid_and_incomplete_objects():
	from msldap.protocol.typeconversion import convert_result
	class SchemaClient(Client):
		async def pagedsearch(self, query, attributes, **kwargs):
			for name, guid_bytes in [('ms-Mcs-AdmPwd', uuid.UUID(LEGACY).bytes_le), ('msLAPS-Password', b'bad')]:
				yield convert_result({'objectName': ('CN=%s,%s' % (name, SCHEMA)).encode(),
					'attributes': [
						{'type': b'lDAPDisplayName', 'attributes': [name.encode()]},
						{'type': b'attributeSecurityGUID', 'attributes': [uuid.UUID(PROPERTY_SET).bytes_le]},
						{'type': b'searchFlags', 'attributes': [b'904']},
					] + ([{'type': b'schemaIDGUID', 'attributes': [guid_bytes]}] if len(guid_bytes) == 16 else [])}), None
	attributes = await permissions.schema(SchemaClient())
	assert attributes['ms-mcs-admpwd'] == permissions.Attribute('ms-Mcs-AdmPwd', LEGACY, PROPERTY_SET, True)
	assert 'mslaps-password' in attributes and attributes['mslaps-password'] is None
	assert 'mslaps-encryptedpassword' not in attributes


async def test_no_schema_message_is_once_per_forest(capsys):
	class EmptySchemaClient(Client):
		async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
			if tree == SCHEMA:
				return
			async for entry, err in super().pagedsearch(query, attributes, controls, tree, search_scope):
				yield entry, err
				yield dict(entry, objectName='CN=PC2,' + DOMAIN), err
	console = MSLDAPOpsConsole(None)
	console.connection = EmptySchemaClient()
	assert await console.do_laps_permissions('all') is False
	out = capsys.readouterr().out
	assert out.count('No LAPS password schema attributes') == 1
	assert 'anywhere in this forest' in out
	assert 'Legacy LAPS' not in out
	assert console.connection.resolved == []


async def test_missing_version_is_one_section_notice():
	client = Client()
	entry = (await permissions.collect_computers(client, 'PC1', DOMAIN))[0]
	lines, ok = await permissions.detail_lines(client, entry, {'ms-mcs-admpwd': ATTRIBUTES['ms-mcs-admpwd']})
	assert ok
	text = '\n'.join(lines)
	assert text.count('No schema attributes returned') == 2
	assert 'msLAPS-EncryptedPasswordHistory' not in text
	assert 'ms-Mcs-AdmPwd' in text and 'ReadProperty' in text


async def test_found_schema_with_invalid_metadata_is_not_reported_as_absent():
	client = Client()
	entry = (await permissions.collect_computers(client, 'PC1', DOMAIN))[0]
	lines, ok = await permissions.detail_lines(client, entry, {'ms-mcs-admpwd': None})
	assert not ok
	text = '\n'.join(lines)
	assert 'schema objects were found' in text
	assert 'No LAPS password schema attributes' not in text
	assert 'cannot store passwords' not in text
	assert client.resolved == []
