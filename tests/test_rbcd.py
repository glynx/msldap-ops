import asyncio

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops.shell import MSLDAPOpsConsole

SID = 'S-1-5-21-1-2-3-1105'


class Client:
	_tree = 'DC=x'
	_serverinfo = {'namingContexts': ['DC=x']}

	def __init__(self, rbcd=None, keycred=None, principals=None):
		self.rbcd = rbcd
		self.keycred = keycred
		self.principals = principals or {}
		self.modified = []
		self.owner_changes = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		low = [str(a).lower() for a in attributes]
		if 'msds-allowedtoactonbehalfofotheridentity' in low:
			attrs = {}
			if self.rbcd is not None:
				attrs['msDS-AllowedToActOnBehalfOfOtherIdentity'] = SECURITY_DESCRIPTOR.from_bytes(self.rbcd)
			yield {'objectName': tree, 'attributes': attrs}, None
		elif 'msds-keycredentiallink' in low:
			yield {'objectName': tree, 'attributes': {'msDS-KeyCredentialLink': self.keycred} if self.keycred else {}}, None
		else:  # principal lookup
			from winacl.dtyp.sid import SID as WSID
			for name, sid in self.principals.items():
				if name in query:
					yield {'objectName': 'CN=%s,DC=x' % name, 'attributes': {'objectSid': WSID.from_string(sid).to_bytes(), 'sAMAccountName': name}}, None

	async def modify(self, dn, changes, controls=None):
		self.modified.append((dn, changes))
		return True, None

	async def change_priv_owner(self, sid, dn, target_attribute=None):
		self.owner_changes.append((sid, dn))
		return True, None

	async def resolv_sid(self, sid):
		return 'X', sid.split('-')[-1], None


def console(client):
	c = MSLDAPOpsConsole(None)
	c.connection = client
	c._current_dn = 'CN=pc,DC=x'
	return c


def test_rbcd_list_empty(capsys):
	assert asyncio.run(console(Client()).do_rbcd('.')) is True
	assert 'no RBCD configured' in capsys.readouterr().out


def test_rbcd_add_and_list():
	from msldap_ops import aces
	client = Client()
	c = console(client)
	assert asyncio.run(c.do_rbcd('.', 'add', SID)) is True
	dn, changes = client.modified[-1]
	data = changes['msDS-AllowedToActOnBehalfOfOtherIdentity'][0][1]
	assert any(str(a.Sid) == SID for a in SECURITY_DESCRIPTOR.from_bytes(data).Dacl.aces)


def test_rbcd_clear():
	client = Client(rbcd=__import__('msldap_ops.aces', fromlist=['rbcd_with']).rbcd_with(None, SID))
	c = console(client)
	assert asyncio.run(c.do_rbcd('.', 'clear')) is True
	assert client.modified[-1][1] == {'msDS-AllowedToActOnBehalfOfOtherIdentity': [('replace', [])]}


def test_keycred_list_and_clear(capsys):
	client = Client(keycred=['B:828:0002...:', 'B:828:0003...:'])
	c = console(client)
	assert asyncio.run(c.do_keycred('.')) is True
	assert '2 key credentials' in capsys.readouterr().out
	assert asyncio.run(c.do_keycred('.', 'clear')) is True
	assert client.modified[-1][1] == {'msDS-KeyCredentialLink': [('replace', [])]}


def test_keycred_empty(capsys):
	assert asyncio.run(console(Client()).do_keycred('.')) is True
	assert 'no key credentials' in capsys.readouterr().out


def test_chown_resolves_and_calls_change_owner():
	client = Client(principals={'jon.snow': SID})
	c = console(client)
	assert asyncio.run(c.do_chown('.', 'jon.snow')) is True
	assert client.owner_changes[-1] == (SID, 'CN=pc,DC=x')
