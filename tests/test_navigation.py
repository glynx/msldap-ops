import pytest
from prompt_toolkit.document import Document

from msldap_ops import navigation
from msldap_ops.cache import QueryCache
from msldap_ops.shell import MSLDAPOpsConsole

DOMAIN = 'DC=north,DC=sevenkingdoms,DC=local'
NCS = [DOMAIN, 'CN=Configuration,DC=sevenkingdoms,DC=local', 'CN=Schema,CN=Configuration,DC=sevenkingdoms,DC=local',
	'DC=DomainDnsZones,' + DOMAIN]


def test_split_dn_keeps_escaped_commas():
	assert navigation.split_dn('CN=Doe\\, John,OU=Staff, DC=x') == ['CN=Doe\\, John', 'OU=Staff', 'DC=x']
	assert navigation.parent_dn('CN=Doe\\, John,OU=Staff,DC=x') == 'OU=Staff,DC=x'
	assert navigation.parent_dn('DC=x') is None


def test_is_under_compares_whole_rdns():
	assert navigation.is_under('CN=Users,' + DOMAIN, DOMAIN)
	assert navigation.is_under(DOMAIN.lower(), DOMAIN)
	assert not navigation.is_under('DC=sevenkingdoms,DC=local', DOMAIN)
	assert not navigation.is_under('DC=xnorth,DC=sevenkingdoms,DC=local', DOMAIN)


@pytest.mark.parametrize('path, expected', [
	('..', DOMAIN),
	('../..', DOMAIN),
	('.', 'OU=Servers,' + DOMAIN),
	('CN=Web', 'CN=Web,OU=Servers,' + DOMAIN),
	('OU=Tier0,OU=Admins', 'OU=Tier0,OU=Admins,OU=Servers,' + DOMAIN),
	('CN=Configuration,DC=sevenkingdoms,DC=local', 'CN=Configuration,DC=sevenkingdoms,DC=local'),
	('cn=users,dc=north,dc=sevenkingdoms,dc=local', 'cn=users,dc=north,dc=sevenkingdoms,dc=local'),
	('../CN=Users', 'CN=Users,' + DOMAIN),
])
def test_resolve(path, expected):
	current = 'OU=Servers,' + DOMAIN
	if path == '../..':
		current = 'CN=Web,OU=Servers,' + DOMAIN
	assert navigation.resolve(path, current, NCS) == expected


def test_resolve_refuses_to_leave_the_naming_contexts():
	with pytest.raises(ValueError, match='top of its naming context'):
		navigation.resolve('..', DOMAIN, NCS)
	with pytest.raises(ValueError, match='not stored on this DC'):
		navigation.resolve('DC=essos,DC=local', DOMAIN, ['DC=essos2,DC=local'])


def test_completer():
	known = ['CN=Users,' + DOMAIN, 'CN=jon.snow,CN=Users,' + DOMAIN, 'OU=Domain Controllers,' + DOMAIN, 'CN=Computers,DC=essos,DC=local']
	completer = navigation.DNCompleter(lambda: DOMAIN, lambda: known, lambda: NCS, lambda: ['CN=Builtin'])
	candidates = completer.candidates()
	assert candidates[:4] == ['CN=Builtin', 'CN=Users', 'OU=Domain Controllers', 'CN=jon.snow,CN=Users']
	assert 'CN=Configuration,DC=sevenkingdoms,DC=local' in candidates
	# DC=north is the top of its naming context, cd .. would be refused
	assert '..' not in candidates
	below = navigation.DNCompleter(lambda: 'CN=Users,' + DOMAIN, lambda: known, lambda: NCS).candidates()
	assert below[0] == '..' and 'CN=jon.snow' in below
	assert not any('essos' in c for c in candidates)

	completions = list(completer.get_completions(Document('ou=d'), None))
	assert [c.text for c in completions] == ["'OU=Domain Controllers'"]
	assert completions[0].start_position == -4


def test_tree_lines():
	known = ['CN=jon.snow,CN=Users,' + DOMAIN, 'CN=Users,' + DOMAIN, 'CN=WINTERFELL,OU=Domain Controllers,' + DOMAIN,
		'DC=sevenkingdoms,DC=local']
	assert navigation.tree_lines(known, DOMAIN) == [
		DOMAIN,
		'|-- CN=Users',
		'|   `-- CN=jon.snow',
		'`-- OU=Domain Controllers',  # never seen itself, but known as parent
		'    `-- CN=WINTERFELL',
	]
	assert navigation.tree_lines(known, DOMAIN, depth=1) == [DOMAIN, '|-- CN=Users (+1)', '`-- OU=Domain Controllers (+1)']


class FakeClient:
	def __init__(self):
		self._serverinfo = {'namingContexts': NCS}
		self.trees = []

	async def get_tree_plot(self, dn, level=1):
		self.trees.append(dn)
		return {dn: {'CN=child,' + dn: {}}}


async def test_cd_and_map(tmp_path, capsys):
	cache = QueryCache(str(tmp_path), persist=False)
	cache.dns = {'cn=jon.snow,cn=users,' + DOMAIN.lower(): ['CN=jon.snow,CN=Users,' + DOMAIN, 0]}
	console = MSLDAPOpsConsole(None, cache=cache)
	console.connection = FakeClient()
	console._current_dn = DOMAIN

	assert await console.do_cd('CN=Users') is True
	assert console._current_dn == 'CN=Users,' + DOMAIN
	assert console.connection.trees == ['CN=Users,' + DOMAIN]
	assert console.get_current_dirs() == ['CN=child']

	assert await console.do_cd('..') is True
	assert await console.do_cd('..') is False
	assert 'top of its naming context' in capsys.readouterr().out
	assert console._current_dn == DOMAIN

	assert await console.do_map() is True
	out = capsys.readouterr().out
	assert '`-- CN=jon.snow' in out
	assert "'tree' asks the DC" in out
	assert await console.do_map('CN=Users', 'x') is False


def test_quote_survives_shlex():
	import shlex
	for name in ['CN=Doe\\, John', 'OU=Domain Controllers', "CN=O'Brien", 'CN=Users']:
		assert shlex.split(navigation.quote(name)) == [name]


def test_cat_arguments():
	from msldap_ops.navigation import cat_arguments
	assert cat_arguments([]) == ('.', '*')
	assert cat_arguments(['', '']) == ('.', '*')
	assert cat_arguments(['*']) == ('*', '*')
	assert cat_arguments(['*', 'cn,member']) == ('*', 'cn,member')
	assert cat_arguments(['CN=Users', 'cn']) == ('CN=Users', 'cn')
	assert cat_arguments(['..']) == ('..', '*')
	# msldap's order: attributes first
	assert cat_arguments(['cn,description']) == ('.', 'cn,description')
	assert cat_arguments(['*', 'CN=Administrators']) == ('CN=Administrators', '*')
	assert cat_arguments(['cn', '..']) == ('..', 'cn')


def test_split_glob():
	from msldap_ops.navigation import split_glob
	assert split_glob('CN=Users') is None
	assert split_glob('.') is None
	assert split_glob('*') == ('.', '(objectClass=*)')
	assert split_glob('CN=Domain*') == ('.', '(CN=Domain*)')
	assert split_glob('OU=*,OU=Tier0') == ('OU=Tier0', '(OU=*)')
	assert split_glob('../*') == ('..', '(objectClass=*)')
	assert split_glob('../../CN=B*') == ('../..', '(CN=B*)')
	assert split_glob('CN=Doe\\, J*') == ('.', '(CN=Doe, J*)')
	assert split_glob('CN=a(b)*') == ('.', '(CN=a\\28b\\29*)')
	# only the last element may be a pattern
	assert split_glob('CN=x,OU=*') is None


def test_find(capsys):
	import asyncio

	from msldap_ops.shell import MSLDAPOpsConsole

	class Client:
		_tree = 'DC=x'
		_serverinfo = {'namingContexts': ['DC=x', 'CN=Configuration,DC=x']}
		calls = []

		async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
			self.calls.append((query, tree, search_scope))
			yield {'objectName': 'CN=jaime.lannister,OU=Crownlands,DC=x',
				'attributes': {'objectClass': ['top', 'person', 'organizationalPerson', 'user'], 'sAMAccountName': 'jaime.lannister'}}, None
			yield {'objectName': 'CN=ESC4,CN=Certificate Templates,CN=Configuration,DC=x',
				'attributes': {'objectClass': ['top', 'pKICertificateTemplate']}}, None

	console = MSLDAPOpsConsole(None)
	console.connection = Client()
	console._current_dn = 'OU=Crownlands,DC=x'
	assert asyncio.run(console.do_find('jaime*')) is True
	assert console.connection.calls[-1] == ('(|(sAMAccountName=jaime*)(name=jaime*))', 'DC=x', 2)
	assert capsys.readouterr().out == (
		'pKICertificateTemplate  -                CN=ESC4,CN=Certificate Templates,CN=Configuration,DC=x\n'
		'user                    jaime.lannister  CN=jaime.lannister,OU=Crownlands,DC=x\n'
		'(2 objects)\n')
	# in the Configuration NC it searches there; special characters are escaped
	console._current_dn = 'CN=Services,CN=Configuration,DC=x'
	assert asyncio.run(console.do_find('a(b)')) is True
	assert console.connection.calls[-1] == ('(|(sAMAccountName=a\\28b\\29)(name=a\\28b\\29))', 'CN=Configuration,DC=x', 2)


def test_match_spans():
	from msldap_ops.navigation import match_spans
	assert match_spans('jaime.lannister', '*lannister') == [(6, 15)]
	assert match_spans('Domain Admins', 'domain*') == [(0, 6)]
	assert match_spans('Domain Admins', '*adm*') == [(7, 10)]
	assert match_spans('Domain Admins', 'domain admins') == [(0, 13)]
	assert match_spans('Domain Admins', '*') == []
	assert match_spans('jon.snow', '*lannister') == []  # matched by the other attribute
	assert match_spans('a(b)', 'a(b)') == [(0, 4)]


def test_find_highlights_the_match(monkeypatch, capsys):
	import asyncio
	import re

	from msldap_ops import ui
	from msldap_ops.shell import MSLDAPOpsConsole

	class Client:
		_tree = 'DC=x'
		_serverinfo = {'namingContexts': ['DC=x']}

		async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
			yield {'objectName': 'CN=Jaime Lannister,DC=x',
				'attributes': {'objectClass': ['user'], 'sAMAccountName': 'jaime.lannister'}}, None

	monkeypatch.setattr(ui, 'output_width', lambda: 120)
	console = MSLDAPOpsConsole(None)
	console.connection = Client()
	console._current_dn = 'DC=x'
	assert asyncio.run(console.do_find('*lannister')) is True
	line = capsys.readouterr().out.splitlines()[0]
	assert re.sub(r'\x1b\[[0-9;]*m', '', line) == 'user  jaime.lannister  CN=Jaime Lannister,DC=x'
	# both matches are styled: in the account name and in the name of the DN
	assert line.count('\x1b[1;35m') == 2
	assert '\x1b[1;35mlannister\x1b[0m' in line and '\x1b[1;35mLannister\x1b[0m' in line

	# no terminal (file, pipe): plain text
	monkeypatch.setattr(ui, 'output_width', lambda: None)
	assert asyncio.run(console.do_find('*lannister')) is True
	assert '\x1b' not in capsys.readouterr().out


def test_groupmembers_resolves_paths(capsys):
	import asyncio

	from msldap_ops.shell import MSLDAPOpsConsole

	class Client:
		_serverinfo = {'namingContexts': ['DC=x']}

		def __init__(self):
			self.calls = []

		async def get_group_members(self, dn, recursive=False):
			self.calls.append((dn, recursive))
			for name in ('CN=a,DC=x', 'CN=b,DC=x'):
				yield type('O', (), {'distinguishedName': name})(), None

	console = MSLDAPOpsConsole(None)
	console.connection = Client()
	console._current_dn = 'CN=Domain Admins,CN=Users,DC=x'
	# '.' is the current object, recursive by default
	assert asyncio.run(console.do_groupmembers('.')) is True
	assert console.connection.calls[-1] == ('CN=Domain Admins,CN=Users,DC=x', True)
	out = capsys.readouterr().out
	assert 'CN=a,DC=x' in out and out.rstrip().endswith('(2 objects)')
	# a relative path and recursive off
	assert asyncio.run(console.do_groupmembers('..', '0')) is True
	assert console.connection.calls[-1] == ('CN=Users,DC=x', False)


def test_positional_completer():
	from prompt_toolkit.completion import WordCompleter
	from prompt_toolkit.document import Document

	from msldap_ops.navigation import PositionalCompleter

	pc = PositionalCompleter([None, WordCompleter(['dcsync', 'resetpassword', 'rbcd']), WordCompleter(['DC=x'])])

	def at(text):
		return [c.text for c in pc.get_completions(Document(text, len(text)), None)]

	# first argument (principal): no suggestions
	assert at('') == [] and at('jon') == []
	# second argument: the rights, filtered by the partial word
	assert at('jon ') == ['dcsync', 'resetpassword', 'rbcd']
	assert at('jon r') == ['resetpassword', 'rbcd']
	# third argument: the path completer
	assert at('jon dcsync ') == ['DC=x']
	# nothing past the defined positions
	assert at('jon dcsync DC=x extra ') == []
