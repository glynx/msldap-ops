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
