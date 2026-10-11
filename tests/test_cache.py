import functools
import json
import time

import pytest

from msldap.connection import MSLDAPClientConnection

from msldap_ops import hooks
from msldap_ops.cache import QueryCache, query_key, raw_from_json, raw_to_json
from msldap_ops.opsec import OpsecGate
from msldap_ops.querylog import QueryLog
from msldap_ops.shell import MSLDAPOpsConsole

from test_querylog import USER_SID, FakeConnection, collect, patched, raw_entry  # noqa: F401 (fixture)


class CountingConnection(FakeConnection):
	"""Counts how often the server is asked."""

	def __init__(self, entries, user='jon.snow'):
		FakeConnection.__init__(self, entries)
		self.credential = type('C', (), {'username': user, 'domain': 'NORTH'})()
		self.server_calls = 0


@pytest.fixture
def cached(patched, tmp_path):
	installed = MSLDAPClientConnection.pagedsearch
	original = installed.__msldap_ops_original__

	@functools.wraps(original)
	async def counting(self, *args, **kwargs):
		self.server_calls += 1
		async for item in original(self, *args, **kwargs):
			yield item

	# count the calls that pass the hook wrapper, i.e. reach the "server"
	MSLDAPClientConnection.pagedsearch = hooks._wrap_search(counting, 'controls')
	cache = QueryCache(str(tmp_path / 'cache'), ttl=60)
	hooks.set_cache(cache)
	hooks.add_listener(cache)
	yield cache
	MSLDAPClientConnection.pagedsearch = installed
	hooks.set_cache(None)
	hooks.set_gate(None)
	hooks.set_foreground(hooks.UNMANAGED)


async def search(conn, flt='(objectClass=user)', attrs=(b'*',)):
	return await collect(conn.pagedsearch('DC=north', flt, list(attrs), search_scope=2))


def test_raw_roundtrip():
	raw = raw_entry()
	assert raw_from_json(json.loads(json.dumps(raw_to_json(raw)))) == raw


def test_key_depends_on_what_changes_the_result():
	base = {'base': 'DC=north', 'query': '(a=b)', 'attributes': [b'cn', b'name'], 'search_scope': 2}
	k = query_key('pagedsearch', base)[0]
	assert query_key('pagedsearch', dict(base, attributes=[b'NAME', b'CN']))[0] == k
	assert query_key('pagedsearch', dict(base, base='dc=NORTH'))[0] == k
	assert query_key('pagedsearch', dict(base, search_scope=1))[0] != k
	assert query_key('pagedsearch', dict(base, query='(a=c)'))[0] != k
	assert query_key('pagedsearch', dict(base, attributes=[b'cn']))[0] != k
	assert query_key('search', base)[0] != k


async def test_repeated_search_is_answered_from_the_cache(cached):
	conn = CountingConnection([raw_entry()])
	first = await search(conn)
	second = await search(conn)
	assert conn.server_calls == 1
	# callers get the same converted result
	assert second[0][0]['attributes']['objectSid'] == USER_SID == first[0][0]['attributes']['objectSid']
	assert second[0][0].raw == first[0][0].raw
	assert cached.hits == 1
	assert 'cn=jon.snow,cn=users,dc=north,dc=sevenkingdoms,dc=local' in cached.dns


async def test_ttl(cached):
	conn = CountingConnection([raw_entry()])
	await search(conn)
	for item in cached.queries.values():
		item['stored'] = time.time() - 61
	await search(conn)
	assert conn.server_calls == 2


async def test_incomplete_and_failed_searches_are_not_cached(cached):
	conn = CountingConnection([raw_entry('CN=a,DC=north'), raw_entry('CN=b,DC=north')])
	gen = conn.pagedsearch('DC=north', '(x=*)', [b'*'])
	await gen.__anext__()
	await gen.aclose()  # caller stopped after the first result
	# the fake connection fails '(fail=*)' in search()
	results = await collect(CountingConnection([]).search('DC=north', '(fail=*)', [b'*']))
	assert results[-1][1] is not None
	assert cached.queries == {}


async def test_unique_searches_stopped_after_the_first_result_are_cached(cached):
	# e.g. msldap's get_ad_info(): (distinguishedName=<domain>) and return after the first entry
	conn = CountingConnection([raw_entry('DC=north')])
	for _ in range(2):
		gen = conn.pagedsearch('DC=north', '(distinguishedName=DC=north)', [b'*'])
		entry, err = await gen.__anext__()
		await gen.aclose()
	assert conn.server_calls == 1


def test_is_unique():
	from msldap_ops.cache import is_unique
	assert is_unique({'query': '(distinguishedName=CN=a,DC=x)', 'search_scope': 2})
	assert is_unique({'query': '(objectSid=S-1-5-21-1-2-3-512)', 'search_scope': 2})
	assert is_unique({'query': '(sAMAccountName=jon.snow)', 'search_scope': 2})
	assert is_unique({'query': '(objectClass=*)', 'search_scope': 0})
	assert not is_unique({'query': '(distinguishedName=*)', 'search_scope': 1})
	assert not is_unique({'query': '(sAMAccountName=jon*)', 'search_scope': 2})
	assert not is_unique({'query': '(&(objectClass=user)(sAMAccountName=x))', 'search_scope': 2})


async def test_background_queries_bypass_the_cache(cached):
	conn = CountingConnection([raw_entry()])
	hooks.set_foreground(None)  # no command running: keepalive
	await search(conn)
	await search(conn)
	assert conn.server_calls == 2
	assert cached.queries == {}


async def test_writes_invalidate_the_cache(cached):
	conn = CountingConnection([raw_entry()])
	await search(conn)

	async def modify(self, entry, changes, controls=None):
		return True, None

	installed = MSLDAPClientConnection.modify
	MSLDAPClientConnection.modify = hooks._wrap_write(modify)
	try:
		await conn.modify('CN=x', {})
	finally:
		MSLDAPClientConnection.modify = installed
	await search(conn)
	assert conn.server_calls == 2


async def test_cache_is_per_account_and_persisted(cached, tmp_path):
	jon = CountingConnection([raw_entry()], user='jon.snow')
	await search(jon)
	cached.save()
	assert cached.path.endswith('10.0.0.1_NORTH_jon.snow.json')

	sam = CountingConnection([raw_entry()], user='samwell.tarly')
	await search(sam)
	assert sam.server_calls == 1  # results depend on the ACLs of the account

	fresh = QueryCache(str(tmp_path / 'cache'), ttl=60)
	hooks.set_cache(fresh)
	jon2 = CountingConnection([raw_entry()], user='jon.snow')
	await search(jon2)
	assert jon2.server_calls == 0


async def test_cached_results_are_not_logged_again(cached, tmp_path):
	querylog = QueryLog(str(tmp_path / 'logs'))
	hooks.add_listener(querylog)
	conn = CountingConnection([raw_entry()])
	await search(conn)
	await search(conn)
	records = open(querylog.path).read()
	assert records.count('--------------------') == 1
	journal = [json.loads(line) for line in open(querylog.query_path)]
	assert [q['cached'] for q in journal] == [False, True]


async def test_opsec_shows_cache_hits_without_asking(cached):
	out = []
	gate = OpsecGate('confirm', ask=None, out=out.append)  # asking would fail
	hooks.set_gate(gate)
	conn = CountingConnection([raw_entry()])
	gate.mode = 'off'
	await search(conn)
	gate.mode = 'confirm'
	gate.start_command('query')
	assert len(await search(conn)) == 1
	assert out == ['[cache] (objectClass=user)  DC=north  scope=sub']
	gate.end_command()
	assert out[-1] == '[opsec] query: no LDAP queries issued, 1 answered from the cache'


def test_summary_counts_sent_and_cached_queries():
	out = []
	gate = OpsecGate('show', out=out.append)
	gate.start_command('find_admins')
	gate.counter, gate.cached_counter = 2, 8
	gate.end_command()
	assert out == ['[opsec] find_admins: 2 LDAP queries issued, 8 answered from the cache']


async def test_flush(cached):
	conn = CountingConnection([raw_entry()])
	await search(conn, '(objectClass=user)')
	await search(conn, '(objectClass=group)')
	assert cached.flush('group') == 1
	assert len(cached.queries) == 1
	assert cached.flush() == 1
	assert cached.queries == {} and cached.dns == {}


async def test_cache_command(cached, capsys):
	console = MSLDAPOpsConsole(None, cache=cached)
	await search(CountingConnection([raw_entry()]))
	assert await console.do_cache() is True
	out = capsys.readouterr().out
	assert 'Query cache: on, ttl 60s' in out
	assert '1 queries (1 results), 1 DNs known' in out
	assert await console.do_cache('list') is True
	assert '(objectClass=user)' in capsys.readouterr().out
	assert await console.do_cache('ttl', 'x') is False
	assert await console.do_cache('ttl', '10') is True and cached.ttl == 10
	assert await console.do_cache('off') is True and not cached.enabled
	assert await console.do_cache('flush') is True
	assert 'Dropped 1 cached query and the DN index' in capsys.readouterr().out
