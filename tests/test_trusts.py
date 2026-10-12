from types import SimpleNamespace

from msldap.ldap_objects.adtrust import TrustDirection, TrustType

from msldap_ops.shell import MSLDAPOpsConsole
from msldap_ops.trusts import format_trusts


def trust(**kwargs):
	fields = dict(trustPartner='sevenkingdoms.local', name='sevenkingdoms.local', flatName='SEVENKINGDOMS',
		trustDirection=TrustDirection.BIDIRECTIONAL, trustType=TrustType.UPLEVEL, trustAttributes=32,
		securityIdentifier='S-1-5-21-1798895762-2647094234-2649376422')
	return SimpleNamespace(**(fields | kwargs))


def test_trust_record_keeps_sid_and_attributes_with_domain():
	lines = format_trusts([trust()], 'DC=north,DC=sevenkingdoms,DC=local')
	assert '  sevenkingdoms.local' in lines
	assert '    Direction:  Bidirectional' in lines
	assert '    Type:       Active Directory' in lines
	assert '    Attributes: WITHIN_FOREST' in lines
	assert '    SID:        S-1-5-21-1798895762-2647094234-2649376422' in lines
	assert not any('TrustType.' in line or 'TrustDirection.' in line for line in lines)


def test_trust_records_preserve_unknown_flags_and_missing_fields():
	lines = format_trusts([trust(trustAttributes=32 | 0x10000, securityIdentifier=None)], 'DC=x')
	assert '    Attributes: WITHIN_FOREST, 0x10000' in lines
	assert '    SID:        (not returned)' in lines
	assert format_trusts([], 'DC=x') == ['Trusts from DC=x (0)', '  (none)']


async def test_trusts_command(capsys):
	class Client:
		_tree = 'DC=x'

		async def get_all_trusts(self):
			yield trust(), None

	console = MSLDAPOpsConsole(None)
	console.connection = Client()
	assert await console.do_trusts() is True
	assert 'Trusts from DC=x (1)' in capsys.readouterr().out


async def test_trusts_command_explains_errors(capsys):
	class Client:
		_tree = 'DC=x'

		async def get_all_trusts(self):
			yield None, ValueError('test search failure')

	console = MSLDAPOpsConsole(None)
	console.connection = Client()
	assert await console.do_trusts() is False
	assert 'test search failure' in capsys.readouterr().out
