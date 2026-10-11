import asyncio

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import aces
from msldap_ops.shell import MSLDAPOpsConsole

BASE = 'O:S-1-5-32-544G:S-1-5-32-544D:(A;;0xf01ff;;;S-1-5-32-544)'
SID = 'S-1-5-21-1-2-3-1105'


class Client:
	_tree = 'DC=x'
	_serverinfo = {'namingContexts': ['DC=x']}

	def __init__(self, sddl=BASE, principals=None):
		self.sd = SECURITY_DESCRIPTOR.from_sddl(sddl).to_bytes()
		self.principals = principals or {}   # name -> sid
		self.modified = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		if 'nTSecurityDescriptor' in attributes or any('ntsecuritydescriptor' == str(a).lower() for a in attributes):
			yield {'objectName': tree, 'attributes': {'nTSecurityDescriptor': SECURITY_DESCRIPTOR.from_bytes(self.sd)}}, None
			return
		# principal lookup
		from winacl.dtyp.sid import SID as WSID
		for name, sid in self.principals.items():
			if name in query:
				yield {'objectName': 'CN=%s,DC=x' % name, 'attributes': {'objectSid': WSID.from_string(sid).to_bytes(), 'sAMAccountName': name}}, None

	async def set_objectacl_by_dn(self, dn, data, flags=None):
		self.modified.append((dn, data))
		self.sd = data  # apply so a following read sees it
		return True, None


def console(client):
	c = MSLDAPOpsConsole(None)
	c.connection = client
	c._current_dn = 'CN=Domain Admins,CN=Users,DC=x'
	return c


def last_aces(client):
	return SECURITY_DESCRIPTOR.from_bytes(client.sd).Dacl.aces


def test_grant_by_sid_writes_the_sd_back():
	client = Client()
	c = console(client)
	assert asyncio.run(c.do_grant(SID, 'dcsync')) is True
	assert len(client.modified) == 1
	assert client.modified[0][0] == 'CN=Domain Admins,CN=Users,DC=x'
	assert sum(str(a.Sid) == SID for a in last_aces(client)) == 2


def test_grant_resolves_an_account_name():
	client = Client(principals={'jon.snow': SID})
	c = console(client)
	assert asyncio.run(c.do_grant('jon.snow', 'resetpassword')) is True
	assert any(str(a.Sid) == SID for a in last_aces(client))


def test_grant_unknown_right(capsys):
	client = Client()
	assert asyncio.run(console(client).do_grant(SID, 'bogus')) is False
	assert 'Unknown right' in capsys.readouterr().out
	assert client.modified == []


def test_grant_then_revoke_roundtrip():
	client = Client()
	c = console(client)
	asyncio.run(c.do_grant(SID, 'genericall'))
	n_after_grant = sum(str(a.Sid) == SID for a in last_aces(client))
	asyncio.run(c.do_revoke(SID, 'genericall'))
	assert n_after_grant == 1 and sum(str(a.Sid) == SID for a in last_aces(client)) == 0


def test_grant_idempotent_sends_nothing(capsys):
	client = Client()
	c = console(client)
	asyncio.run(c.do_grant(SID, 'genericall'))
	client.modified.clear()
	assert asyncio.run(c.do_grant(SID, 'genericall')) is True
	assert client.modified == [] and 'already present' in capsys.readouterr().out
