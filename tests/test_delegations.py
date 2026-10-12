import asyncio

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import aces, delegations
from msldap_ops.shell import MSLDAPOpsConsole

SID = 'S-1-5-21-1-2-3-1105'


def test_queries_and_rows():
	assert '524288' in delegations.QUERIES['unconstrained'][0] and '8192' in delegations.QUERIES['unconstrained'][0]
	row = delegations.constrained_row({'objectName': 'CN=svc,DC=x',
		'attributes': {'sAMAccountName': 'svc', 'userAccountControl': 0x1000000 | 0x200,
			'msDS-AllowedToDelegateTo': ['HOST/dc', 'CIFS/dc']}})
	assert row['protocol_transition'] and row['targets'] == ['HOST/dc', 'CIFS/dc']
	row2 = delegations.constrained_row({'objectName': 'CN=s2,DC=x',
		'attributes': {'sAMAccountName': 's2', 'userAccountControl': 0x200, 'msDS-AllowedToDelegateTo': 'HTTP/x'}})
	assert not row2['protocol_transition'] and row2['targets'] == ['HTTP/x']


def test_rbcd_row_reads_allowed_sids():
	sd = SECURITY_DESCRIPTOR.from_bytes(aces.rbcd_with(None, SID))
	row = delegations.rbcd_row({'objectName': 'CN=pc,DC=x', 'attributes': {'sAMAccountName': 'pc$',
		'msDS-AllowedToActOnBehalfOfOtherIdentity': sd}})
	assert row['allowed'] == [SID]


def test_formatting():
	lines = delegations.format_constrained([{'name': 'svc', 'dn': 'd', 'protocol_transition': True, 'targets': ['HOST/dc']}])
	assert lines[0] == 'Constrained delegation (1)' and any('protocol transition' in l for l in lines)
	assert any('-> HOST/dc' in l for l in lines)


class Client:
	_tree = 'DC=x'

	def __init__(self):
		self.queries = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		self.queries.append(query)
		if '524288' in query:
			yield {'objectName': 'CN=ws01,DC=x', 'attributes': {'sAMAccountName': 'ws01$'}}, None
		elif 'AllowedToDelegateTo' in query:
			yield {'objectName': 'CN=svc,DC=x', 'attributes': {'sAMAccountName': 'svc',
				'userAccountControl': 0x200, 'msDS-AllowedToDelegateTo': ['HOST/dc']}}, None
		elif 'AllowedToActOnBehalf' in query:
			sd = SECURITY_DESCRIPTOR.from_bytes(aces.rbcd_with(None, SID))
			yield {'objectName': 'CN=pc,DC=x', 'attributes': {'sAMAccountName': 'pc$',
				'msDS-AllowedToActOnBehalfOfOtherIdentity': sd}}, None

	async def resolv_sid(self, sid):
		return 'NORTH', 'attacker', None


def test_command_all(capsys):
	c = MSLDAPOpsConsole(None)
	c.connection = Client()
	assert asyncio.run(c.do_delegations()) is True
	out = capsys.readouterr().out
	assert 'Unconstrained delegation (1)' in out and 'ws01$' in out
	assert 'Constrained delegation (1)' in out and 'HOST/dc' in out
	assert 'Resource-based' in out and 'NORTH\\attacker' in out
	assert len(c.connection.queries) == 3


def test_command_single_kind(capsys):
	c = MSLDAPOpsConsole(None)
	c.connection = Client()
	assert asyncio.run(c.do_delegations('unconstrained')) is True
	assert len(c.connection.queries) == 1
	assert asyncio.run(c.do_delegations('bogus')) is False
