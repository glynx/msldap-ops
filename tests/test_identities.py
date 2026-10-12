import json
import time
from types import SimpleNamespace

import pytest
from winacl.dtyp.sid import SID

from msldap_ops import acl, templates, ui
from msldap_ops.cache import QueryCache, raw_to_json
from msldap_ops.identities import IdentityCatalogue
from msldap_ops.shell import MSLDAPOpsConsole

DOMAIN = 'S-1-5-21-1-2-3'
USER = DOMAIN + '-1105'
BASE = 'DC=north,DC=sevenkingdoms,DC=local'


def raw(dn, **attrs):
	return {'objectName': dn.encode(), 'attributes': [
		{'type': key.encode(), 'attributes': [v if isinstance(v, bytes) else v.encode() for v in (value if isinstance(value, list) else [value])]}
		for key, value in attrs.items()]}


def records(name='jon.snow'):
	return [
		raw(BASE, objectClass=['top', 'domainDNS'], objectSid=SID.from_string(DOMAIN).to_bytes()),
		raw('CN=NORTH,CN=Partitions,CN=Configuration,' + BASE,
			nCName=BASE, nETBIOSName='NORTH', dnsRoot='north.sevenkingdoms.local'),
		raw('CN=' + name + ',CN=Users,' + BASE, objectSid=SID.from_string(USER).to_bytes(), sAMAccountName=name),
	]


def connection(server='dc.north', user='operator'):
	return SimpleNamespace(target=SimpleNamespace(hostname=server), credential=SimpleNamespace(domain='NORTH', username=user))


class NoLookup:
	domainsid = 'S-1-5-21-4-5-6'

	def __init__(self):
		self.calls = 0

	async def resolv_sid(self, sid):
		self.calls += 1
		raise AssertionError('a learned foreign identity should require no LDAP lookup')


async def test_old_foreign_names_survive_expiry_writes_flush_and_reconnect(tmp_path, monkeypatch):
	now = time.time()
	monkeypatch.setattr('msldap_ops.cache.time.time', lambda: now - 100)
	cache = QueryCache(str(tmp_path), ttl=60)
	cache.bind(connection())
	cache.put('users', {}, records())
	cache.save()
	foreign_path = cache.path
	foreign_snapshot = open(foreign_path, 'rb').read()
	monkeypatch.setattr('msldap_ops.cache.time.time', lambda: now)
	cache.bind(connection('dc.other'))
	cache.expire()
	cache.invalidate_queries()
	cache.flush()
	# No operation against the second domain rewrites the first namespace.
	assert open(foreign_path, 'rb').read() == foreign_snapshot
	fresh = QueryCache(str(tmp_path), ttl=60)
	fresh.bind(connection('dc.other'))
	client = NoLookup()
	names = await acl.resolve(client, [USER], fresh)
	assert client.calls == 0
	assert names[USER].startswith('NORTH\\jon.snow (last seen: ')
	assert names[USER].endswith(' UTC)')
	principal = fresh.identities.get('principal', USER)
	assert principal['observed'] == now - 100
	assert principal['server'] == 'dc.north' and principal['account'] == 'NORTH\\operator'
	# Identity data cannot answer LDAP attribute reads or supply a security descriptor.
	assert fresh.find_attribute('CN=jon.snow,CN=Users,' + BASE, 'nTSecurityDescriptor') is None
	assert not fresh.queries


@pytest.mark.parametrize('server', ['dc.north', 'dc.other'])
async def test_expired_legacy_names_are_migrated_before_active_cache_expiry(tmp_path, server):
	cache = QueryCache(str(tmp_path), ttl=60)
	cache.server, cache.account = 'dc.north', 'NORTH\\operator'
	old = time.time() - 1000
	with open(cache.path, 'w') as stream:
		json.dump({'version': 1, 'server': cache.server, 'account': cache.account, 'queries': {
			'old': {'stored': old, 'query': {}, 'entries': [raw_to_json(r) for r in records()]}}}, stream)
	fresh = QueryCache(str(tmp_path), ttl=60)
	fresh.bind(connection(server))
	assert fresh.queries == {}
	assert fresh.identities.get('principal', USER)['observed'] == old
	assert 'last seen:' in (await acl.resolve(NoLookup(), [USER], fresh))[USER]


def test_partial_old_observations_fill_gaps_without_reverting_newer_names(tmp_path):
	store = IdentityCatalogue(str(tmp_path))
	store.observe([raw_to_json(r) for r in records('renamed')[:1] + records('renamed')[2:]], 200, 'newdc', 'newuser')
	trust = raw('CN=north,CN=System,DC=other', securityIdentifier=SID.from_string(DOMAIN).to_bytes(),
		name='north.sevenkingdoms.local', flatName='NORTH')
	store.observe([raw_to_json(trust)] + [raw_to_json(r) for r in records()], 100, 'olddc', 'olduser')
	assert store.get('principal', USER)['name'] == 'renamed'
	assert store.get('principal', USER)['observed'] == 200
	assert store.domain(DOMAIN)['name'] == 'NORTH'
	assert store.domain(DOMAIN)['observed'] == 100  # the NetBIOS label really is old
	# Empty searches and entries without a usable account name cannot erase an identity.
	store.observe([], 300)
	store.observe([raw_to_json(raw('CN=foreign,CN=ForeignSecurityPrincipals,DC=other', objectSid=SID.from_string(USER).to_bytes()))], 400)
	assert store.get('principal', USER)['name'] == 'renamed'
	assert store.get('principal', USER)['observed'] == 200


def test_two_sessions_merge_different_domains_and_keep_newest_rename(tmp_path):
	a = IdentityCatalogue(str(tmp_path))
	b = IdentityCatalogue(str(tmp_path))
	a.observe([raw_to_json(r) for r in records()], 100)
	b.observe([raw_to_json(raw('CN=foreign,DC=other', objectSid=SID.from_string('S-1-5-21-4-5-6-1001').to_bytes(), sAMAccountName='foreign'))], 200)
	b.observe([raw_to_json(r) for r in records('renamed')], 300)
	a.observe([raw_to_json(r) for r in records()], 200)
	assert a.get('principal', USER)['name'] == 'renamed'
	assert b.get('principal', USER)['name'] == 'renamed'
	assert len([r for r in a.rows() if r['kind'] == 'principal']) == 2


async def test_explicit_clear_survives_restart_even_when_query_snapshot_is_saved(tmp_path):
	cache = QueryCache(str(tmp_path))
	cache.bind(connection())
	cache.put('users', {}, records())
	cache.save()
	assert cache.identities.clear() == 3
	cache.seen(records()[0])  # navigation dirties the query snapshot after clear
	cache.save()
	fresh = QueryCache(str(tmp_path))
	fresh.bind(connection())
	assert fresh.identities.rows() == []
	assert 'users' in fresh.queries  # clear only affects the identity catalogue
	fresh.put('new', {}, records('renamed'))
	assert fresh.identities.get('principal', USER)['name'] == 'renamed'


async def test_memory_only_never_imports_or_writes_disk_and_off_bypasses_labels(tmp_path):
	persistent = QueryCache(str(tmp_path))
	persistent.put('users', {}, records())
	before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
	memory = QueryCache(str(tmp_path), persist=False)
	assert memory.identities.rows() == []
	memory.put('users', {}, records('memory'))
	assert (await acl.resolve(NoLookup(), [USER], memory))[USER] == 'NORTH\\memory'
	memory.enabled = False
	assert (await acl.resolve(NoLookup(), [USER], memory))[USER] == USER
	assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


async def test_dns_fallback_known_foreign_rid_and_unresolved_account(tmp_path):
	cache = QueryCache(str(tmp_path), persist=False)
	cache.put('domain', {}, records()[:1])
	client = NoLookup()
	names = await acl.resolve(client, [DOMAIN + '-512', DOMAIN + '-9999'], cache)
	assert client.calls == 0
	assert names[DOMAIN + '-512'] == 'north.sevenkingdoms.local\\Domain Admins'
	assert names[DOMAIN + '-9999'] == 'north.sevenkingdoms.local\\<unresolved RID 9999> (%s-9999)' % DOMAIN


async def test_users_only_collection_resolves_foreign_name_using_its_dn(tmp_path):
	cache = QueryCache(str(tmp_path), persist=False)
	cache.put('users', {}, records()[2:])
	client = NoLookup()
	assert await acl.resolve(client, [USER], cache) == {USER: 'north.sevenkingdoms.local\\jon.snow'}
	assert client.calls == 0


async def test_template_labels_use_catalogue_without_changing_access_token(tmp_path):
	from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
	cache = QueryCache(str(tmp_path), persist=False)
	cache.put('users', {}, records())
	sd = SECURITY_DESCRIPTOR.from_sddl('O:%sG:%sD:(A;;GA;;;%s)' % (USER, USER, USER))
	info = SimpleNamespace(template=SimpleNamespace(nTSecurityDescriptor=sd.to_bytes()))
	assert await templates.resolve_principals(NoLookup(), info, cache) == {USER: 'NORTH\\jon.snow'}


async def test_catalogue_commands_show_provenance_and_clear(tmp_path, capsys):
	cache = QueryCache(str(tmp_path), persist=False)
	cache.bind(connection())
	cache.put('users', {}, records())
	console = MSLDAPOpsConsole(None, cache=cache)
	assert await console.do_cache('identities') is True
	out = capsys.readouterr().out
	assert USER in out and 'jon.snow' in out and 'dc.north' in out and 'NORTH\\operator' in out
	assert 'UTC' in out
	assert await console.do_cache('identities', 'clear') is True
	assert 'Cleared 3 retained identity records' in capsys.readouterr().out
	assert not cache.identities.rows() and cache.queries


def test_historical_label_and_timestamp_are_gray():
	line = '  allow  NORTH\\Domain Admins (last seen: 2026-10-12 08:00 UTC)  GenericAll'
	text = ui.styled(line)
	spans = [(text.plain[s.start:s.end], str(s.style)) for s in text.spans]
	assert ('NORTH\\Domain Admins', 'bright_black') in spans
	assert ('(last seen: 2026-10-12 08:00 UTC)', 'bright_black') in spans
