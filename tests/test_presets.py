import pytest

from msldap_ops import presets
from msldap_ops.querylog import QueryLog
from msldap_ops.shell import MSLDAPOpsConsole

# RootDSE of a child domain DC: Configuration and Schema live under the forest root
CHILD = {
	'defaultNamingContext': 'DC=north,DC=sevenkingdoms,DC=local',
	'rootDomainNamingContext': 'DC=sevenkingdoms,DC=local',
	'configurationNamingContext': 'CN=Configuration,DC=sevenkingdoms,DC=local',
	'schemaNamingContext': 'CN=Schema,CN=Configuration,DC=sevenkingdoms,DC=local',
}


def by_label(queries):
	return {q.label: q for q in queries}


def test_resolve_uses_rootdse_naming_contexts():
	q = by_label(presets.resolve(['users', 'schema', 'adcs', 'partitions', 'dns'], CHILD))
	assert q['users'].base == 'DC=north,DC=sevenkingdoms,DC=local'
	assert q['schema GUIDs'].base == 'CN=Schema,CN=Configuration,DC=sevenkingdoms,DC=local'
	assert q['schema GUIDs'].attributes == ['name', 'schemaIDGUID']
	assert q['certificate templates'].base == 'CN=Public Key Services,CN=Services,CN=Configuration,DC=sevenkingdoms,DC=local'
	assert 'msDS-OIDToGroupLink' in q['issuance policies'].attributes
	assert q['NetBIOS names'].base == 'CN=Partitions,CN=Configuration,DC=sevenkingdoms,DC=local'
	assert q['DNS nodes (domain zones)'].base == 'DC=DomainDnsZones,DC=north,DC=sevenkingdoms,DC=local'
	assert q['DNS nodes (forest zones)'].base == 'DC=ForestDnsZones,DC=sevenkingdoms,DC=local'


def test_resolve_falls_back_to_the_tree_without_rootdse():
	q = by_label(presets.resolve(['users', 'schema'], None, 'DC=essos,DC=local'))
	assert q['users'].base == 'DC=essos,DC=local'
	assert q['schema GUIDs'].base == 'CN=Schema,CN=Configuration,DC=essos,DC=local'


def test_all_includes_dns_without_duplicates():
	queries = presets.resolve(['users', 'all', 'users'], CHILD)
	names = [q.preset for q in queries]
	assert names.count('dns') == 2  # one search per naming context
	assert names[0] == 'users'
	assert names.count('users') == 1
	assert set(names) == set(presets.ALL) == set(presets.PRESETS)


def test_unknown_preset():
	with pytest.raises(ValueError, match="Unknown preset 'bogus'"):
		presets.resolve(['bogus'], CHILD)


def test_all_bofhound_queries_request_the_security_descriptor():
	for q in presets.resolve(['all'], CHILD):
		if q.preset not in ('schema', 'partitions', 'dns'):
			assert q.wants_sd, q.label


class FakeClient:
	def __init__(self, fail=()):
		self._serverinfo = CHILD
		self._tree = CHILD['defaultNamingContext']
		self.calls = []
		self.fail = fail

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		self.calls.append((query, attributes, controls, tree, search_scope))
		if query in self.fail:
			yield None, Exception('noSuchObject')
			return
		for i in range(2):
			yield {'objectName': 'CN=%d' % i, 'attributes': {}}, None


async def test_bofhound_collect_runs_every_query_and_continues_after_errors(capsys, tmp_path):
	console = MSLDAPOpsConsole(None, querylog=QueryLog(str(tmp_path)))
	console.connection = FakeClient(fail=('(objectClass=trustedDomain)',))
	assert await console.do_bofhound_collect('users,trusts,schema') is True

	calls = console.connection.calls
	assert [c[0] for c in calls] == ['(sAMAccountType=805306368)', '(objectClass=trustedDomain)', '(schemaIDGUID=*)']
	users, _, schema = calls
	assert users[2][0][0] == '1.2.840.113556.1.4.801'
	assert schema[2] is None
	out = capsys.readouterr().out
	assert 'error: noSuchObject' in out
	assert '4 objects from 3 queries, 1 failed' in out
	assert 'WARNING' not in out


async def test_bofhound_collect_warns_when_logging_is_off(capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = FakeClient()
	await console.do_bofhound_collect('users')
	assert 'WARNING: query logging is off' in capsys.readouterr().out


async def test_bofhound_collect_rejects_bad_input(capsys):
	console = MSLDAPOpsConsole(None)
	assert await console.do_bofhound_collect('users') is False  # not connected
	console.connection = FakeClient()
	assert await console.do_bofhound_collect('users', 'soon') is False
	assert await console.do_bofhound_collect('bogus') is False
	assert console.connection.calls == []


async def test_bofhound_collect_without_names_lists_presets(capsys):
	assert await MSLDAPOpsConsole(None).do_bofhound_collect() is True
	out = capsys.readouterr().out
	assert '(schemaIDGUID=*)' in out
	assert '(not in all)' not in out
