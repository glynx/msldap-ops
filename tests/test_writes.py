import asyncio
import json

import pytest
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import hooks
from msldap_ops.opsec import OpsecGate
from msldap_ops.querylog import QueryLog


class Answers:
	def __init__(self, *answers):
		self.answers = list(answers)
		self.asked = 0

	async def __call__(self, text):
		self.asked += 1
		return self.answers.pop(0)


class Target:
	target = type('T', (), {'hostname': 'dc01', 'ip': None})()


sent = []


async def modify(self, entry, changes, controls=None):
	sent.append(('modify', entry, changes))
	return True, None


async def add(self, entry, attributes):
	sent.append(('add', entry, attributes))
	return True, None


async def delete(self, entry):
	sent.append(('delete', entry))
	return True, None


@pytest.fixture
def gate():
	sent.clear()
	out = []
	gate = OpsecGate('confirm', ask=Answers(), out=out.append)
	gate.start_command('addusertogroup')
	hooks.set_gate(gate)
	yield gate, out
	hooks.set_gate(None)
	for listener in list(hooks._listeners):
		hooks.remove_listener(listener)


def run(func, *args):
	return asyncio.run(hooks._wrap_write(func)(Target(), *args))


def test_change_is_shown_and_confirmed(gate):
	gate, out = gate
	gate.ask.answers.append('y')
	assert run(modify, 'CN=Domain Admins,DC=x', {'member': [('add', [b'CN=jon,DC=x'])]}) == (True, None)
	assert out[:2] == ['[change #1] modify CN=Domain Admins,DC=x', '            add member: CN=jon,DC=x']
	assert sent and gate.ask.asked == 1
	gate.end_command()
	assert out[-1] == '[opsec] addusertogroup: no LDAP queries sent, 1 change sent'


def test_skipped_change_is_not_sent(gate):
	gate, out = gate
	gate.ask.answers.append('n')
	ok, err = run(delete, 'CN=x,DC=x')
	assert ok is False and str(err) == 'not sent: skipped by the operator'
	assert sent == []
	gate.end_command()
	assert out[-1] == '[opsec] addusertogroup: no LDAP queries sent, 1 change not sent'


def test_dryrun_sends_no_change(gate):
	gate, out = gate
	gate.set_mode('dryrun')
	ok, err = run(modify, 'CN=x,DC=x', {'description': [('replace', 'pwned')]})
	assert ok is False and 'opsec dryrun' in str(err) and sent == []
	assert out[0].startswith('[dryrun #1] modify CN=x,DC=x') and out[1].strip() == 'replace description: pwned'
	gate.end_command()
	assert out[-1] == '[opsec] addusertogroup: 1 change shown, none sent'


def test_changes_are_confirmed_even_in_navigation_commands(gate):
	gate, out = gate
	gate.start_command('cat')
	gate.ask.answers.append('q')
	ok, err = run(delete, 'CN=x,DC=x')
	assert ok is False and sent == [] and gate.ask.asked == 1


def test_secrets_and_descriptors_in_the_display(gate):
	gate, out = gate
	gate.set_mode('show')
	sd = SECURITY_DESCRIPTOR.from_sddl('O:S-1-5-32-544D:(A;;0xf01ff;;;S-1-5-32-544)')
	run(add, 'CN=evil,CN=Computers,DC=x', {'objectClass': ['top', 'computer'], 'unicodePwd': '"Secret1!"',
		'msDS-AllowedToActOnBehalfOfOtherIdentity': sd.to_bytes()})
	text = '\n'.join(out)
	assert 'set objectClass: top; computer' in text
	assert 'set unicodePwd: <hidden>' in text and 'Secret1' not in text
	assert 'set msDS-AllowedToActOnBehalfOfOtherIdentity: O:' in text
	run(modify, 'CN=u,DC=x', {'msDS-KeyCredentialLink': [('add', b'\x00\x01' * 200)]})
	assert out[-1].endswith('... (800 characters)')


def test_changes_are_journaled(gate, tmp_path):
	gate, out = gate
	gate.set_mode('off')
	log = QueryLog(str(tmp_path))
	hooks.add_listener(log)
	run(modify, 'CN=u,DC=x', {'unicodePwd': [('replace', '"New1!"')]})
	record = json.loads(open(log.query_path).read().splitlines()[-1])
	assert record['type'] == 'write' and record['operation'] == 'modify' and record['dn'] == 'CN=u,DC=x'
	assert record['changes'] == [{'op': 'replace', 'attribute': 'unicodePwd', 'values': ['<hidden>']}]
	assert record['ok'] is True and record['server'] == 'dc01'
	assert out == []  # off: nothing shown


@pytest.mark.parametrize('operation, args', [
	(add, ('CN=x,DC=x', {'objectClass': ['user']})),
	(modify, ('CN=x,DC=x', {'description': [('add', 'example')]})),
	(delete, ('CN=x,DC=x',)),
])
@pytest.mark.parametrize('answer, allowed', [('y', True), ('n', False), ('q', False)])
def test_confirm_write_gates_all_write_operations(gate, operation, args, answer, allowed):
	gate, out = gate
	gate.set_mode('confirm-write')
	gate.ask.answers.append(answer)
	ok, err = run(operation, *args)
	assert ok is allowed
	assert bool(sent) is allowed
	assert gate.ask.asked == 1
	assert out[0].startswith('[change #1] ')
	gate.end_command()
	assert out[-1].startswith('[opsec] addusertogroup: ')


def test_confirm_write_all_resets_for_next_command(gate):
	gate, out = gate
	gate.set_mode('confirm-write')
	gate.ask.answers.extend(['a', 'n'])
	assert run(delete, 'CN=x,DC=x') == (True, None)
	assert run(delete, 'CN=y,DC=x') == (True, None)
	assert gate.ask.asked == 1
	gate.start_command('next')
	assert run(delete, 'CN=z,DC=x')[0] is False
	assert gate.ask.asked == 2
