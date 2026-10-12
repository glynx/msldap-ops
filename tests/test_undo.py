import asyncio

import pytest

from msldap_ops import changes, hooks
from msldap_ops.hooks import RawValue


class Conn:
	target = type('T', (), {'hostname': 'dc', 'ip': None})()

	def __init__(self, old=None):
		self.old = old or {}          # lowercased attr -> [raw bytes]
		self.sent = []                # applied modify/add/delete
		self.reads = []

	async def modify(self, entry, changes, controls=None):
		self.sent.append(('modify', entry, changes))
		return True, None

	async def add(self, entry, attributes):
		self.sent.append(('add', entry, attributes))
		return True, None

	async def delete(self, entry):
		self.sent.append(('delete', entry))
		return True, None

	async def search(self, base, query, attributes, search_scope=2, controls=None):
		self.reads.append((base, [a.decode() for a in attributes], controls is not None))
		attrs = [{'type': name, 'attributes': self.old.get(name.decode().lower(), [])} for name in attributes]
		entry = hooks.SearchEntry({})
		entry.raw = {'objectName': base, 'attributes': attrs}
		yield entry, None


@pytest.fixture
def wired():
	log = changes.ChangeLog()
	hooks.add_listener(log)
	hooks.set_foreground(hooks.UNMANAGED)
	yield log
	hooks.remove_listener(log)


def wrap(name):
	original = getattr(hooks.MSLDAPClientConnection, name).__msldap_ops_original__ if hasattr(getattr(hooks.MSLDAPClientConnection, name), '__msldap_ops_original__') else getattr(Conn, name)
	return hooks._wrap_write(getattr(Conn, name))


def run_modify(conn, dn, changes_dict):
	return asyncio.run(hooks._wrap_write(Conn.modify)(conn, dn, changes_dict))


def run_add(conn, dn, attrs):
	return asyncio.run(hooks._wrap_write(Conn.add)(conn, dn, attrs))


def run_delete(conn, dn):
	return asyncio.run(hooks._wrap_write(Conn.delete)(conn, dn))


def test_add_value_inverts_to_delete(wired):
	conn = Conn()
	run_modify(conn, 'CN=Admins,DC=x', {'member': [('add', ['CN=jon,DC=x'])]})
	assert len(wired) == 1
	change = wired.changes[0]
	assert change.undoable and change.undo == ('modify', 'CN=Admins,DC=x', {'member': [('delete', ['CN=jon,DC=x'])]}, None)
	assert conn.reads == []  # add/delete need no read


def test_delete_value_inverts_to_add(wired):
	conn = Conn()
	run_modify(conn, 'CN=Admins,DC=x', {'member': [('delete', ['CN=jon,DC=x'])]})
	assert wired.changes[0].undo == ('modify', 'CN=Admins,DC=x', {'member': [('add', ['CN=jon,DC=x'])]}, None)


def test_sd_replace_undo_reuses_the_forward_controls(wired):
	conn = Conn(old={'ntsecuritydescriptor': [b'OLDSD']})
	# the forward change carried a (fake) SD flags control; the undo must reuse it
	control = object()
	asyncio.run(hooks._wrap_write(Conn.modify)(conn, 'CN=g,DC=x',
		{'nTSecurityDescriptor': [('replace', b'NEWSD')]}, [control]))
	assert conn.reads and conn.reads[0][2] is True  # old SD read with the SD flags control
	op, dn, changes, controls = wired.changes[0].undo
	assert op == 'modify' and dn == 'CN=g,DC=x' and controls == [control]
	value = changes['nTSecurityDescriptor'][0][1]
	assert isinstance(value, RawValue) and value.encode() == [b'OLDSD']


def test_other_replace_restores_old_value(wired):
	conn = Conn(old={'description': [b'old text']})
	run_modify(conn, 'CN=g,DC=x', {'description': [('replace', 'new text')]})
	op_, dn_, changes_, controls_ = wired.changes[0].undo
	assert op_ == 'modify' and dn_ == 'CN=g,DC=x' and controls_ is None
	op, value = changes_['description'][0]
	assert op == 'replace' and isinstance(value, RawValue) and value.encode() == [b'old text']


def test_add_object_inverts_to_delete(wired):
	conn = Conn()
	run_add(conn, 'CN=evil,DC=x', {'objectClass': ['top', 'computer']})
	assert wired.changes[0].undo == ('delete', 'CN=evil,DC=x', None, None)


def test_delete_object_is_not_undoable(wired):
	conn = Conn()
	run_delete(conn, 'CN=x,DC=x')
	assert not wired.changes[0].undoable and 'cannot be undone' in wired.changes[0].reason


def test_secret_change_is_not_undoable(wired):
	conn = Conn()
	run_modify(conn, 'CN=u,DC=x', {'unicodePwd': [('replace', '"New1!"')]})
	assert not wired.changes[0].undoable and 'secret' in wired.changes[0].reason
	assert conn.reads == []  # the secret is not read


def test_apply_undo_sd_reuses_controls(wired):
	control = object()
	conn = Conn(old={'ntsecuritydescriptor': [b'OLDSD']})
	asyncio.run(hooks._wrap_write(Conn.modify)(conn, 'CN=g,DC=x',
		{'nTSecurityDescriptor': [('replace', b'NEWSD')]}, [control]))
	change = wired.last_undoable()
	ok, err = asyncio.run(changes.apply_undo(conn, change))
	# the undo wrote the old bytes back with the same control
	assert ok and conn.sent[-1][0] == 'modify' and conn.sent[-1][1] == 'CN=g,DC=x'
	assert conn.sent[-1][2]['nTSecurityDescriptor'][0][1].encode() == [b'OLDSD']


def test_undo_removes_the_change_and_records_nothing_new(wired):
	conn = Conn()
	run_modify(conn, 'CN=Admins,DC=x', {'member': [('add', ['CN=jon,DC=x'])]})
	assert len(wired) == 1
	change = wired.last_undoable()
	ok, err = asyncio.run(wired.undo(conn, change))
	assert ok and err is None
	assert conn.sent[-1] == ('modify', 'CN=Admins,DC=x', {'member': [('delete', ['CN=jon,DC=x'])]})
	# the change is gone and the undo write itself was not added as a new change
	assert len(wired) == 0 and wired.last_undoable() is None


def test_changes_and_undo_commands(capsys):
	from msldap_ops.shell import MSLDAPOpsConsole
	log = changes.ChangeLog()
	conn = Conn()
	console = MSLDAPOpsConsole(None, changes_log=log)
	console.connection = conn
	hooks.add_listener(log)
	hooks.set_foreground(hooks.UNMANAGED)
	try:
		run_modify(conn, 'CN=Admins,DC=x', {'member': [('add', ['CN=jon,DC=x'])]})
		run_delete(conn, 'CN=x,DC=x')
	finally:
		hooks.remove_listener(log)

	assert asyncio.run(console.do_changes()) is True
	out = capsys.readouterr().out
	assert '1  ' in out and 'modify CN=Admins,DC=x' in out and '[undoable]' in out
	assert 'delete CN=x,DC=x' in out and 'no undo:' in out

	# undo the last undoable change (the modify; the delete is not undoable)
	assert asyncio.run(console.do_undo()) is True
	assert conn.sent[-1] == ('modify', 'CN=Admins,DC=x', {'member': [('delete', ['CN=jon,DC=x'])]})
	assert 'Undone' in capsys.readouterr().out
	# nothing left
	assert asyncio.run(console.do_undo()) is True
	assert 'No change that can be undone' in capsys.readouterr().out
	# a bad index
	assert asyncio.run(console.do_undo('9')) is False


def test_summary_shortens_security_descriptor_and_long_values():
	from msldap_ops import changes

	class Info:
		operation = 'modify'
		dn = 'CN=g,DC=x'
		changes = [('replace', 'nTSecurityDescriptor', ['O:' + 'A' * 500])]

	assert changes.describe(Info()) == 'modify CN=g,DC=x: replace nTSecurityDescriptor=<security descriptor>'
	Info.changes = [('add', 'description', ['x' * 200])]
	line = changes.describe(Info())
	assert line.endswith('...') and len(line) < 120
