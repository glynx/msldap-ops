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
	assert out[-1] == '[opsec] query: no LDAP queries sent, 1 answered from the cache'


def test_summary_counts_sent_and_cached_queries():
	out = []
	gate = OpsecGate('show', out=out.append)
	gate.start_command('find_admins')
	gate.counter, gate.sent, gate.cached_counter = 2, 2, 8
	gate.end_command()
	assert out == ['[opsec] find_admins: 2 LDAP queries sent, 8 answered from the cache']


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


def parts(base='cn=public key services,cn=services,cn=configuration,dc=x', scope=2, flt='(objectClass=pKICertificateTemplate)', attrs=('*', 'ntsecuritydescriptor'), controls=('sd',)):
	return {'kind': 'pagedsearch', 'base': base, 'scope': scope, 'filter': flt, 'attributes': sorted(attrs), 'controls': list(controls), 'types_only': False}


def test_covers():
	from msldap_ops.cache import covers
	collect = parts()
	templates = parts(base='cn=certificate templates,' + collect['base'], attrs=('cn', 'name', 'mspki-certificate-name-flag', 'ntsecuritydescriptor', 'pkiexpirationperiod'))
	assert covers(collect, templates)
	# nTSecurityDescriptor is not part of '*'
	assert not covers(parts(attrs=('*',)), templates)
	# constructed attributes are not part of '*'
	assert not covers(collect, parts(attrs=('msds-user-account-control-computed',)))
	assert not covers(collect, parts(attrs=('tokengroups',)))
	# '*' cannot be served from an explicit attribute list
	assert not covers(parts(attrs=('cn',)), parts(attrs=('*',)))
	assert not covers(collect, parts(flt='(objectClass=user)'))
	# the SD flags control only matters for nTSecurityDescriptor
	sd_flags = b'1.2.840.113556.1.4.801'.hex()
	with_sd = parts(controls=(sd_flags,))
	assert covers(with_sd, parts(controls=(), attrs=('name', 'certificatetemplates')))
	assert not covers(with_sd, parts(controls=()))
	assert not covers(parts(controls=('other',)), parts(controls=(), attrs=('name',)))
	# a narrower cached base or another scope does not cover
	assert not covers(templates, collect)
	assert not covers(collect, parts(base='cn=certificate templates,' + collect['base'], scope=1))
	assert not covers(collect, parts(scope=1))
	# 'cn=services,...' is not below 'cn=public key services,...' although it is a suffix
	assert not covers(parts(base='services,dc=x'), parts(base='cn=services,dc=x'))


async def test_broader_cached_search_answers_a_narrower_one(cached):
	pki = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=x'
	tpl = raw_entry('CN=ESC1,CN=Certificate Templates,' + pki)
	ca = raw_entry('CN=ESSOS-CA,CN=Enrollment Services,' + pki)
	conn = CountingConnection([tpl, ca])
	from msldap.protocol.messages import Control
	# as msldap's client passes them to the connection
	sd = [Control({'controlType': b'1.2.840.113556.1.4.801', 'criticality': True, 'controlValue': b'0\x03\x02\x01\x07'})]
	await collect(conn.pagedsearch(pki, '(objectClass=pKICertificateTemplate)', [b'*', b'nTSecurityDescriptor'], controls=sd))

	results = await collect(conn.pagedsearch('CN=Certificate Templates,' + pki, '(objectClass=pKICertificateTemplate)', [b'objectSid', b'nTSecurityDescriptor'], controls=sd))
	assert conn.server_calls == 1
	# reduced to the wanted base and attributes
	assert [e['objectName'] for e, _ in results] == ['CN=ESC1,CN=Certificate Templates,' + pki]
	assert set(results[0][0]['attributes']) == {'objectSid', 'nTSecurityDescriptor'}


async def test_templates_after_bofhound_collect_come_from_the_cache(cached):
	"""Real msldap client: the controls are built by msldap, the keys must still match."""
	from msldap.client import MSLDAPClient

	from msldap_ops import presets, templates
	from msldap_ops.shell import sd_flags_control

	config = 'CN=Configuration,DC=x'
	pki = templates.pki_base(config)
	conn = CountingConnection([raw_entry('CN=ESC1,CN=Certificate Templates,' + pki), raw_entry('CN=CA,CN=Enrollment Services,' + pki)])
	client = MSLDAPClient(None, None, connection=conn)
	client._tree = 'DC=x'
	client._serverinfo = {'defaultNamingContext': 'DC=x', 'configurationNamingContext': config}

	for q in presets.resolve(['adcs'], client._serverinfo):
		controls = [sd_flags_control()] if q.wants_sd else None
		await collect(client.pagedsearch(q.filter, q.attributes, controls=controls, tree=q.base))
	calls = conn.server_calls

	await collect(client.pagedsearch('(objectClass=pKIEnrollmentService)', templates.CA_ATTRIBUTES, tree='CN=Enrollment Services,' + pki))
	await collect(client.pagedsearch('(objectClass=pKICertificateTemplate)', templates.TEMPLATE_ATTRIBUTES, controls=[templates.sd_flags_control()], tree='CN=Certificate Templates,' + pki))
	assert conn.server_calls == calls


async def test_cached_results_are_marked_in_the_output(cached, capsys):
	from msldap_ops.shell import SearchWatch

	conn = CountingConnection([raw_entry()])
	watch = SearchWatch()
	hooks.add_listener(watch)
	try:
		await search(conn)
		assert watch.cached_at is None  # live
		await search(conn)
		assert watch.cached_at is not None and conn.server_calls == 1
	finally:
		hooks.remove_listener(watch)


def test_cache_note_layout_and_style():
	import datetime

	from msldap_ops import records, ui
	stored = datetime.datetime(2026, 10, 11, 19, 42)
	assert records.count_line(3, stored) == '(3 objects)  (from cache: 2026-10-11 19:42)'
	assert records.record_lines('CN=x', {'cn': 'x'}, stored)[1] == 'DN: CN=x  (from cache: 2026-10-11 19:42)'
	assert records.count_line(1) == '(1 object)'

	def spans(line):
		text = ui.styled(line)
		return [(line[s.start:s.end], str(s.style)) for s in text.spans]

	assert spans('DN: CN=x  (from cache: 2026-10-11 19:42)') == [
		('DN: CN=x', 'bold cyan'), ('  (from cache: 2026-10-11 19:42)', 'bright_black')]
	assert ('ACL of DC=x', 'bold') in spans('ACL of DC=x  (from cache: 2026-10-11 19:42)')
	assert spans('ACL of DC=x') == [('ACL of DC=x', 'bold')]
