import base64
import json
import uuid

import pytest
from winacl.dtyp.sid import SID

import msldap.connection
from msldap.commons.common import MSLDAPClientStatus
from msldap.connection import MSLDAPClientConnection

from msldap_ops import hooks
from msldap_ops.querylog import QueryLog, format_entry

USER_SID = 'S-1-5-21-1111111111-2222222222-3333333333-1104'
USER_GUID = '12345678-1234-5678-9abc-def012345678'
SD_BYTES = bytes.fromhex('01000494') + b'\x00' * 16


def raw_entry(dn='CN=jon.snow,CN=Users,DC=north,DC=sevenkingdoms,DC=local', **extra):
	attributes = [
		(b'objectClass', [b'top', b'person', b'organizationalPerson', b'user']),
		(b'distinguishedName', [dn.encode()]),
		(b'sAMAccountType', [b'805306368']),
		(b'objectSid', [SID.from_string(USER_SID).to_bytes()]),
		(b'objectGUID', [uuid.UUID(USER_GUID).bytes_le]),
		(b'nTSecurityDescriptor', [SD_BYTES]),
		(b'whenCreated', [b'20221213101112.0Z']),
		(b'pwdLastSet', [b'133150000000000000']),
		(b'description', [b'first line\r\nsecond line']),
		(b'userCertificate', [b'\x30\x82\x01\x00']),
		(b'unknownBlob', [b'\x00\x01\xff']),
	]
	attributes += list(extra.items())
	return {
		'objectName': dn.encode(),
		'attributes': [{'type': k, 'attributes': v} for k, v in attributes],
	}


def parse(lines):
	"""Minimal version of the bofhound record parser: key/value split at the first colon."""
	records, current = [], None
	for line in lines:
		if line == '-' * 20:
			current = {}
			records.append(current)
		elif line.startswith('Retrieved '):
			current = None
		elif current is not None:
			key, value = line.split(':', 1)
			current[key.strip().lower()] = value.strip()
	return records


def test_format_entry():
	lines = format_entry(raw_entry())
	assert lines[0] == '-' * 20
	record = parse(lines)[0]
	assert record['objectclass'] == 'top, person, organizationalPerson, user'
	assert record['samaccounttype'] == '805306368'
	assert record['objectsid'] == USER_SID
	assert record['objectguid'].lower() == USER_GUID
	assert base64.b64decode(record['ntsecuritydescriptor']) == SD_BYTES
	# timestamps stay in their raw LDAP form, like ldapsearch BOF and pyldapsearch write them
	assert record['whencreated'] == '20221213101112.0Z'
	assert record['pwdlastset'] == '133150000000000000'
	assert record['description'] == 'first line second line'
	assert 'usercertificate' not in record
	assert base64.b64decode(record['unknownBlob'.lower()]) == b'\x00\x01\xff'


def test_schema_guid_format_is_accepted_by_bofhound():
	lines = format_entry({'objectName': b'CN=ms-Mcs-AdmPwd,CN=Schema', 'attributes': [
		{'type': b'name', 'attributes': [b'ms-Mcs-AdmPwd']},
		{'type': b'schemaIDGUID', 'attributes': [uuid.UUID(USER_GUID).bytes_le]},
	]})
	# bofhound uses the value as is if it contains a dash, otherwise it base64 decodes it
	assert parse(lines)[0]['schemaidguid'].lower() == USER_GUID


class FakeConnection(MSLDAPClientConnection):
	"""Connection whose original search yields canned entries through convert_result."""

	def __init__(self, entries):
		self.entries = entries
		self.status = MSLDAPClientStatus.RUNNING
		self.target = type('T', (), {'hostname': None, 'ip': '10.0.0.1'})()


@pytest.fixture
def patched(monkeypatch):
	async def fake_search(self, base, query, attributes, search_scope=2, size_limit=1000, types_only=False, derefAliases=0, timeLimit=None, controls=None, return_done=False):
		if return_done:
			# the native messages msldap's real pagedsearch consumes
			for raw in self.entries:
				yield {'protocolOp': raw, 'controls': None}, None
			yield {'protocolOp': {'resultCode': 'success', 'diagnosticMessage': ''}, 'controls': []}, None
			return
		for raw in self.entries:
			# looked up at call time, like the real search does
			yield msldap.connection.convert_result(raw), None
		if query == '(fail=*)':
			yield None, Exception('boom')

	monkeypatch.setattr(MSLDAPClientConnection, 'search', fake_search)
	hooks.install()
	yield
	hooks.uninstall()
	hooks._listeners.clear()


class Recorder:
	def __init__(self):
		self.events = []

	def query_start(self, query):
		self.events.append(('start', query.query))

	def query_entry(self, query, entry):
		self.events.append(('entry', entry.raw is not None, entry['objectName']))

	def query_end(self, query):
		self.events.append(('end', query.count, query.error is not None))


async def collect(gen):
	return [item async for item in gen]


async def test_hook_reports_query_and_keeps_results(patched):
	recorder = Recorder()
	hooks.add_listener(recorder)
	conn = FakeConnection([raw_entry()])
	results = await collect(conn.search('DC=north', '(objectClass=user)', [b'*'], search_scope=2))

	assert len(results) == 1
	entry, err = results[0]
	assert err is None
	# callers still get the converted msldap result
	assert entry['attributes']['objectSid'] == USER_SID
	assert recorder.events == [
		('start', '(objectClass=user)'),
		('entry', True, 'CN=jon.snow,CN=Users,DC=north,DC=sevenkingdoms,DC=local'),
		('end', 1, False),
	]


async def test_pagedsearch_is_reported_once(patched):
	# msldap's real pagedsearch, which calls search(return_done=True) for every page
	recorder = Recorder()
	hooks.add_listener(recorder)
	conn = FakeConnection([raw_entry('CN=a,DC=north'), raw_entry('CN=b,DC=north')])
	results = await collect(conn.pagedsearch('DC=north', '(objectClass=user)', [b'*'], search_scope=1))

	assert [e['objectName'] for e, _ in results] == ['CN=a,DC=north', 'CN=b,DC=north']
	assert results[0][0]['attributes']['objectSid'] == USER_SID
	assert recorder.events == [
		('start', '(objectClass=user)'),
		('entry', True, 'CN=a,DC=north'),
		('entry', True, 'CN=b,DC=north'),
		('end', 2, False),
	]


async def test_hook_reports_errors(patched):
	recorder = Recorder()
	hooks.add_listener(recorder)
	await collect(FakeConnection([]).search('DC=north', '(fail=*)', [b'*']))
	assert recorder.events[-1] == ('end', 0, True)


async def test_hook_ignores_internal_page_requests(patched):
	recorder = Recorder()
	hooks.add_listener(recorder)
	await collect(FakeConnection([raw_entry()]).search('DC=north', '(x=*)', [b'*'], return_done=True))
	assert recorder.events == []


async def test_failing_listener_does_not_break_the_query(patched):
	class Broken:
		def query_entry(self, query, entry):
			raise RuntimeError('listener bug')

	hooks.add_listener(Broken())
	results = await collect(FakeConnection([raw_entry()]).search('DC=north', '(x=*)', [b'*']))
	assert len(results) == 1


async def test_uninstall_restores_msldap(patched):
	hooks.uninstall()
	assert MSLDAPClientConnection.search.__name__ == 'fake_search'
	assert not hasattr(MSLDAPClientConnection.search, '__msldap_ops_original__')
	hooks.install()


async def test_querylog_writes_bofhound_records(patched, tmp_path):
	querylog = QueryLog(str(tmp_path / 'logs'))
	hooks.add_listener(querylog)
	conn = FakeConnection([raw_entry('CN=a,DC=north'), raw_entry('CN=b,DC=north')])
	await collect(conn.search('DC=north', '(objectClass=user)', [b'*', b'nTSecurityDescriptor']))

	lines = open(querylog.path, encoding='utf-8').read().splitlines()
	assert lines[-1] == 'Retrieved 2 results total'
	records = parse(lines)
	assert [r['distinguishedname'] for r in records] == ['CN=a,DC=north', 'CN=b,DC=north']

	query = json.loads(open(querylog.query_path, encoding='utf-8').read().splitlines()[-1])
	assert query['filter'] == '(objectClass=user)'
	assert query['attributes'] == ['*', 'nTSecurityDescriptor']
	assert query['scope'] == 'sub'
	assert query['server'] == '10.0.0.1'
	assert query['count'] == 2


async def test_querylog_skips_records_bofhound_cannot_identify(patched, tmp_path):
	querylog = QueryLog(str(tmp_path / 'logs'))
	hooks.add_listener(querylog)
	dn_only = {'objectName': b'CN=Users,DC=north', 'attributes': [
		{'type': b'distinguishedName', 'attributes': [b'CN=Users,DC=north']},
	]}
	await collect(FakeConnection([dn_only, raw_entry('CN=a,DC=north')]).search('DC=north', '(x=*)', [b'distinguishedName']))

	lines = open(querylog.path, encoding='utf-8').read().splitlines()
	assert [r['distinguishedname'] for r in parse(lines)] == ['CN=a,DC=north']
	assert lines[-1] == 'Retrieved 1 results total'
	query = json.loads(open(querylog.query_path, encoding='utf-8').read())
	assert (query['count'], query['logged']) == (2, 1)


def test_records_bofhound_handles_without_sid_or_guid_are_kept():
	from msldap_ops.querylog import is_identifiable

	def raw(**attrs):
		return {'objectName': b'x', 'attributes': [{'type': k.encode(), 'attributes': v} for k, v in attrs.items()]}

	assert is_identifiable(raw(name=[b'ms-Mcs-AdmPwd'], schemaIDGUID=[uuid.UUID(USER_GUID).bytes_le]))
	assert is_identifiable(raw(objectClass=[b'top', b'crossRef'], nETBIOSName=[b'NORTH']))
	assert is_identifiable(raw(objectClass=[b'top', b'dnsNode'], dnsRecord=[b'\x04\x00']))
	assert not is_identifiable(raw(distinguishedName=[b'CN=Users,DC=north']))
	assert not is_identifiable(raw(objectClass=[b'top', b'container'], distinguishedName=[b'CN=Users,DC=north']))


async def test_querylog_can_be_switched_off(patched, tmp_path):
	querylog = QueryLog(str(tmp_path / 'logs'))
	querylog.enabled = False
	hooks.add_listener(querylog)
	await collect(FakeConnection([raw_entry()]).search('DC=north', '(x=*)', [b'*']))
	assert not (tmp_path / 'logs').exists()
