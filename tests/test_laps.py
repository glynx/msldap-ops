import asyncio
import datetime
import json

from msldap_ops import laps

WIN_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def entry(dn, **attrs):
	return {'objectName': dn, 'attributes': attrs}


def test_filetime():
	# 2024-01-01 as a FILETIME
	ft = int((datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc) - WIN_EPOCH).total_seconds()) * 10_000_000
	assert laps.filetime(ft) == datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
	assert laps.filetime(None) is None
	assert laps.filetime(0) is None
	assert laps.filetime(0x7FFFFFFFFFFFFFFF) is None
	# an already-converted datetime is kept
	now = datetime.datetime.now(datetime.timezone.utc)
	assert laps.filetime(now) == now


def test_windows_password_json():
	blob = json.dumps({'n': 'Administrator', 'p': 'S3cret!', 't': '0'})
	assert laps.windows_password(blob) == ('Administrator', 'S3cret!')
	assert laps.windows_password(blob.encode()) == ('Administrator', 'S3cret!')
	assert laps.windows_password(None) == (None, None)
	# not JSON: returned as the raw password
	assert laps.windows_password('plain') == (None, 'plain')


def test_legacy_entry():
	e = laps.LapsEntry(entry('CN=PC1,DC=x', **{'cn': 'PC1', 'sAMAccountName': 'PC1$',
		'ms-Mcs-AdmPwd': 'LegacyPw1', 'ms-Mcs-AdmPwdExpirationTime': 0}))
	assert e.version == 'legacy' and e.password == 'LegacyPw1' and e.configured
	assert laps.format_entry(e) == ['PC1$  (legacy)', '  password: LegacyPw1']


def test_windows_entry_encrypted():
	e = laps.LapsEntry(entry('CN=PC2,DC=x', **{'sAMAccountName': 'PC2$',
		'msLAPS-EncryptedPassword': b'\x01\x02\x03'}))
	assert e.version == 'windows (encrypted)' and e.password is None and e.encrypted
	lines = laps.format_entry(e)
	assert lines[0] == 'PC2$  (windows (encrypted))'
	assert 'RPC call' in lines[1]


def test_windows_entry_cleartext():
	blob = json.dumps({'n': 'Administrator', 'p': 'WinPw!'})
	e = laps.LapsEntry(entry('CN=PC3,DC=x', **{'sAMAccountName': 'PC3$', 'msLAPS-Password': blob}))
	assert e.version == 'windows' and e.windows_account == 'Administrator' and e.password == 'WinPw!'
	assert laps.summary([e]) == '1 computer with LAPS, 1 password readable'


def test_entry_without_laps_is_not_configured():
	assert not laps.LapsEntry(entry('CN=PC4,DC=x', sAMAccountName='PC4$')).configured


class Client:
	_tree = 'DC=x'

	def __init__(self, entries):
		self.entries = entries
		self.queries = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		self.queries.append(query)
		for e in self.entries:
			yield e, None


def run_laps(entries, target):
	from msldap_ops.shell import MSLDAPOpsConsole
	console = MSLDAPOpsConsole(None)
	console.connection = Client(entries)
	ok = asyncio.run(console.do_laps(target))
	return console.connection, ok


def test_command_on_the_current_object(capsys):
	from msldap.protocol.constants import BASE

	from msldap_ops.shell import MSLDAPOpsConsole
	e = entry('CN=PC1,DC=x', **{'sAMAccountName': 'PC1$', 'ms-Mcs-AdmPwd': 'Pw1'})

	class BaseClient(Client):
		async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
			self.queries.append((query, tree, search_scope))
			for item in self.entries:
				yield item, None

	console = MSLDAPOpsConsole(None)
	console.connection = BaseClient([e])
	console._current_dn = 'CN=PC1,DC=x'
	# laps and laps . both read the current object with a base search
	assert asyncio.run(console.do_laps()) is True
	assert console.connection.queries[-1] == ('(sAMAccountType=805306369)', 'CN=PC1,DC=x', BASE)
	assert 'Pw1' in capsys.readouterr().out
	assert asyncio.run(console.do_laps('.')) is True
	assert console.connection.queries[-1][1:] == ('CN=PC1,DC=x', BASE)


def test_command_on_a_non_computer(capsys):
	from msldap_ops.shell import MSLDAPOpsConsole
	console = MSLDAPOpsConsole(None)
	console.connection = Client([])  # base search returns nothing (filter does not match)
	console._current_dn = 'CN=jon,DC=x'
	assert asyncio.run(console.do_laps()) is True
	assert 'is not a computer with LAPS' in capsys.readouterr().out


def test_command_targets_one_machine(capsys):
	e = entry('CN=PC1,DC=x', **{'sAMAccountName': 'PC1$', 'ms-Mcs-AdmPwd': 'Pw1'})
	conn, ok = run_laps([e], 'PC1')
	assert ok is True
	assert conn.queries == ['(&(sAMAccountType=805306369)(|(sAMAccountName=PC1$)(name=PC1)))']
	assert 'Pw1' in capsys.readouterr().out


def test_command_all(capsys):
	e = entry('CN=PC1,DC=x', **{'sAMAccountName': 'PC1$', 'ms-Mcs-AdmPwd': 'Pw1'})
	conn, ok = run_laps([e], 'all')
	assert conn.queries == ['(sAMAccountType=805306369)']
