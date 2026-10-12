import hashlib
import stat
import struct
import uuid

import pytest
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

from msldap_ops import changes, hooks, keycred
from msldap_ops.opsec import OpsecGate
from msldap_ops.shell import MSLDAPOpsConsole

DN = 'CN=pc,DC=x'


@pytest.fixture(scope='module')
def credentials():
	return [keycred.generate('pc$', DN) for _ in range(2)]


class Client:
	_tree = 'DC=x'
	_serverinfo = {'namingContexts': ['DC=x']}

	def __init__(self, values):
		self.values = list(values)
		self.modified = []

	async def pagedsearch(self, *args, **kwargs):
		yield {'objectName': DN, 'attributes': {'sAMAccountName': 'pc$', 'msDS-KeyCredentialLink': self.values}}, None

	async def modify(self, entry, changes, controls=None):
		self.modified.append((entry, changes))
		for operation, values in changes['msDS-KeyCredentialLink']:
			if operation == 'add':
				self.values.extend(values)
			elif operation == 'delete':
				self.values = [v for v in self.values if v not in values]
		return True, None


@pytest.fixture
def console(monkeypatch, credentials):
	monkeypatch.setattr(Client, 'modify', hooks._wrap_write(Client.modify))
	client = Client([credentials[0][0]])
	log = changes.ChangeLog()
	c = MSLDAPOpsConsole(None, changes_log=log)
	c.connection, c._current_dn = client, DN
	hooks.add_listener(log)
	hooks.set_gate(c.gate)
	try:
		yield c
	finally:
		hooks.remove_listener(log)
		hooks.set_gate(None)


def test_generated_key_matches_pfx_and_wire_hashes(credentials):
	value, pfx = credentials[0]
	key, cert, _ = load_key_and_certificates(pfx, None)
	assert key.public_key().public_numbers() == cert.public_key().public_numbers()
	blob = bytes.fromhex(value.split(':', 3)[2])
	fields, offsets, offset = {}, {}, 4
	while offset < len(blob):
		length, identifier = struct.unpack_from('<HB', blob, offset)
		offset += 3
		fields[identifier] = blob[offset:offset + length]
		offset += length
		offsets[identifier] = offset
	assert fields[1] == hashlib.sha256(fields[3]).digest()
	assert fields[2] == hashlib.sha256(blob[offsets[2]:]).digest()
	# Decode the RSA blob independently and compare it with the exported certificate.
	magic, bits, exponent_len, modulus_len, _, _ = struct.unpack_from('<6I', fields[3])
	assert magic == int.from_bytes(b'RSA1', 'little') and bits == key.key_size
	assert int.from_bytes(fields[3][24:24 + exponent_len], 'big') == key.public_key().public_numbers().e
	assert int.from_bytes(fields[3][24 + exponent_len:24 + exponent_len + modulus_len], 'big') == key.public_key().public_numbers().n
	assert keycred.identifiers(value)['device_id'] == str(uuid.UUID(bytes_le=fields[6]))


async def test_add_and_undo_preserve_other_values(console, tmp_path):
	original = list(console.connection.values)
	filename = tmp_path / 'credential.pfx'
	assert await console.do_keycred('.', 'add', str(filename)) is True
	assert stat.S_IMODE(filename.stat().st_mode) == 0o600
	assert load_key_and_certificates(filename.read_bytes(), None)[0] is not None
	assert len(console.connection.values) == 2
	assert console.changes_log.changes[-1].undoable
	assert await console.do_undo() is True
	assert console.connection.values == original


async def test_no_overwrite_or_write_when_export_fails(console, tmp_path):
	filename = tmp_path / 'credential.pfx'
	filename.write_bytes(b'keep')
	assert await console.do_keycred('.', 'add', str(filename)) is False
	assert filename.read_bytes() == b'keep'
	assert console.connection.modified == []


@pytest.mark.parametrize('mode, answer', [('confirm-write', 'n'), ('dryrun', None)])
async def test_add_respects_gate_and_dryrun_has_no_file(console, tmp_path, mode, answer):
	async def ask(text):
		return answer
	console.gate = OpsecGate(mode, ask=ask, out=lambda _: None)
	console.gate.start_command('keycred')
	hooks.set_gate(console.gate)
	filename = tmp_path / 'credential.pfx'
	assert await console.do_keycred('.', 'add', str(filename)) is False
	assert console.connection.modified == []
	assert filename.exists() is (mode != 'dryrun')


@pytest.mark.parametrize('selector', ['device_id', 'key_id'])
async def test_remove_and_undo_in_new_session(console, credentials, selector, capsys):
	console.connection.values.append(credentials[1][0])
	original = list(console.connection.values)
	assert await console.do_keycred() is True
	ids = keycred.identifiers(original[0])
	assert ids[selector] in capsys.readouterr().out
	assert len(console.changes_log) == 0  # no add/undo history is needed
	assert await console.do_keycred('.', 'remove', ids[selector]) is True
	assert console.connection.values == original[1:]
	assert await console.do_undo() is True
	assert set(console.connection.values) == set(original)


async def test_remove_refuses_missing_or_ambiguous_ids(console):
	assert await console.do_keycred('.', 'remove', str(uuid.uuid4())) is False
	value = console.connection.values[0]
	console.connection.values.append(value)
	assert await console.do_keycred('.', 'remove', keycred.identifiers(value)['device_id']) is False
	assert console.connection.modified == []


async def test_remove_is_confirmed(console):
	async def ask(text):
		return 'n'
	console.gate = OpsecGate('confirm-write', ask=ask, out=lambda _: None)
	console.gate.start_command('keycred')
	hooks.set_gate(console.gate)
	value = console.connection.values[0]
	assert await console.do_keycred('.', 'remove', keycred.identifiers(value)['key_id']) is False
	assert console.connection.modified == []


@pytest.mark.parametrize('value', ['B:2:00:CN=pc,DC=x', 'B:4:0002:CN=pc,DC=x', 'B:2:zz:CN=pc,DC=x'])
def test_malformed_credentials_are_not_selected(value):
	assert keycred.identifiers(value) is None
	assert keycred.matches(value, 'anything') is False
	assert '(unparsed)' in keycred.format_value(value)[0]
