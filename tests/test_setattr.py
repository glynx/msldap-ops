import asyncio

import pytest

from msldap_ops.shell import MSLDAPOpsConsole, apply_uac_flags, uac_flag_names


class Client:
	_serverinfo = {'namingContexts': ['DC=x']}

	def __init__(self, uac=None):
		self.modified = []
		self.uac = uac

	async def modify(self, dn, changes, controls=None):
		self.modified.append((dn, changes))
		return True, None

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		yield {'objectName': tree, 'attributes': {'userAccountControl': self.uac} if self.uac is not None else {}}, None


def console(client):
	c = MSLDAPOpsConsole(None)
	c.connection = client
	c._current_dn = 'CN=u,DC=x'
	return c


def test_setattr_replace_and_clear():
	client = Client()
	c = console(client)
	assert asyncio.run(c.do_setattr('.', 'description', 'hello', 'world')) is True
	assert client.modified[-1] == ('CN=u,DC=x', {'description': [('replace', ['hello', 'world'])]})
	assert asyncio.run(c.do_setattr('.', 'description')) is True
	assert client.modified[-1] == ('CN=u,DC=x', {'description': [('replace', [])]})


def test_addattr_delattr():
	client = Client()
	c = console(client)
	asyncio.run(c.do_addattr('.', 'servicePrincipalName', 'HOST/x'))
	assert client.modified[-1] == ('CN=u,DC=x', {'servicePrincipalName': [('add', ['HOST/x'])]})
	asyncio.run(c.do_delattr('.', 'servicePrincipalName', 'HOST/x'))
	assert client.modified[-1] == ('CN=u,DC=x', {'servicePrincipalName': [('delete', ['HOST/x'])]})


def test_uac_flag_helpers():
	assert uac_flag_names(0x202) == ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT']
	assert apply_uac_flags(0x200, ['+DONT_REQUIRE_PREAUTH']) == 0x200 | 0x400000
	assert apply_uac_flags(0x202, ['-ACCOUNTDISABLE']) == 0x200
	assert apply_uac_flags(0x200, ['+0x400000']) == 0x400200
	with pytest.raises(ValueError):
		apply_uac_flags(0, ['DONT_REQUIRE_PREAUTH'])  # missing +/-
	with pytest.raises(ValueError):
		apply_uac_flags(0, ['+NOPE'])


def test_uac_show(capsys):
	client = Client(uac=0x202)
	assert asyncio.run(console(client).do_uac('.')) is True
	out = capsys.readouterr().out
	assert '0x202' in out and 'ACCOUNTDISABLE' in out
	assert client.modified == []  # show only


def test_uac_set_and_unchanged(capsys):
	client = Client(uac=0x200)
	c = console(client)
	assert asyncio.run(c.do_uac('.', '+DONT_REQUIRE_PREAUTH')) is True
	assert client.modified[-1] == ('CN=u,DC=x', {'userAccountControl': [('replace', 0x400200)]})
	# setting the same flag again is a no-op (no modify)
	client.uac = 0x400200
	client.modified.clear()
	assert asyncio.run(c.do_uac('.', '+DONT_REQUIRE_PREAUTH')) is True
	assert client.modified == [] and 'unchanged' in capsys.readouterr().out
