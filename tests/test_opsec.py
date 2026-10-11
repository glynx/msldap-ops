import asyncio
import json

import pytest

from msldap_ops import hooks
from msldap_ops.opsec import OpsecGate, format_query
from msldap_ops.querylog import QueryLog
from msldap_ops.shell import MSLDAPOpsConsole

from test_querylog import FakeConnection, collect, patched, raw_entry  # noqa: F401 (fixture)


class Answers:
	def __init__(self, *answers):
		self.answers = list(answers)
		self.asked = 0

	async def __call__(self, text):
		self.asked += 1
		return self.answers.pop(0)


def make_gate(mode, *answers, command='test'):
	out = []
	gate = OpsecGate(mode, ask=Answers(*answers), out=out.append)
	hooks.set_gate(gate)
	gate.start_command(command)
	return gate, out


@pytest.fixture
def gated(patched):
	yield
	hooks.set_gate(None)
	hooks.set_foreground(hooks.UNMANAGED)


async def search(flt='(objectClass=user)'):
	conn = FakeConnection([raw_entry()])
	return await collect(conn.pagedsearch('DC=north', flt, [b'*', b'nTSecurityDescriptor'], search_scope=2))


async def test_show_prints_and_sends(gated):
	gate, out = make_gate('show')
	results = await search()
	assert len(results) == 1
	assert out[0] == '[ldap #1] DC=north  scope=sub'
	assert out[1] == '          filter: (objectClass=user)'
	assert out[2] == '          attributes: *,nTSecurityDescriptor'
	gate.end_command()
	assert out[-1] == '[opsec] test: 1 LDAP query issued'


async def test_confirm_yes_no(gated):
	gate, out = make_gate('confirm', 'maybe', 'y', 'n')
	assert len(await search()) == 1
	assert await search() == []
	assert gate.ask.asked == 3  # 'maybe' is asked again


async def test_confirm_only_shows_navigation_queries(gated):
	gate, out = make_gate('confirm', command='cd')  # no answers: asking would fail
	assert len(await search()) == 1
	assert len(await search()) == 1
	assert out[0].startswith('[ldap #1] ')


async def test_dryrun_does_not_send_navigation_queries_either(gated):
	gate, out = make_gate('dryrun', command='cat')
	assert await search() == []


async def test_no_summary_for_navigation_commands(gated):
	gate, out = make_gate('show', command='cat')
	await search()
	gate.end_command()
	assert not any(line.startswith('[opsec]') for line in out)


async def test_confirm_all_sends_the_rest_of_the_command(gated):
	gate, out = make_gate('confirm', 'a')
	assert len(await search()) == 1
	assert len(await search()) == 1
	assert gate.ask.asked == 1
	gate.start_command('next')
	gate.ask.answers.append('y')
	await search()
	assert gate.ask.asked == 2  # 'all' only lasts for one command


async def test_confirm_quit_aborts_the_command(gated):
	gate, out = make_gate('confirm', 'q')
	results = await search()
	assert results[0][0] is None and isinstance(results[0][1], hooks.QueryAborted)
	# further queries of the same command fail without asking
	results = await search()
	assert isinstance(results[0][1], hooks.QueryAborted)
	assert gate.ask.asked == 1


async def test_dryrun_sends_nothing(gated, tmp_path):
	querylog = QueryLog(str(tmp_path))
	hooks.add_listener(querylog)
	gate, out = make_gate('dryrun')
	assert await search() == []
	assert out[0].startswith('[dryrun #1] ')
	gate.end_command()
	assert out[-1] == '[opsec] test: 1 LDAP query shown, none sent'
	journal = json.loads(open(querylog.query_path).read())
	assert journal['skipped'] is True
	# nothing for bofhound, not even an empty 'Retrieved' line
	assert not (tmp_path / querylog.path.split('/')[-1]).exists()


async def test_background_queries_are_not_gated_or_logged(gated, tmp_path):
	querylog = QueryLog(str(tmp_path))
	hooks.add_listener(querylog)
	gate, out = make_gate('confirm')  # no answers: asking would fail
	hooks.set_foreground(asyncio.current_task())
	results = await asyncio.create_task(search('(distinguishedName=DC=north)'))
	assert len(results) == 1
	assert out == []
	journal = json.loads(open(querylog.query_path).read())
	assert journal['background'] is True
	assert not (tmp_path / querylog.path.split('/')[-1]).exists()


async def test_queries_between_commands_are_background(gated):
	# e.g. the keepalive firing while the prompt waits for input
	gate, out = make_gate('confirm')  # no answers: asking would fail
	hooks.set_foreground(None)
	assert len(await search('(distinguishedName=DC=north)')) == 1
	assert out == []


def test_format_query_hides_the_paged_control():
	q = hooks.QueryInfo('dc', 'DC=x', '(a=b)', [], 0, [{'controlType': b'1.2.840.113556.1.4.319'}, {'controlType': b'1.2.840.113556.1.4.801'}])
	assert format_query(q)[2].endswith('attributes: (all)  controls: sd-flags')
	assert format_query(q)[0] == '[ldap] DC=x  scope=base'


async def test_console_marks_commands_and_switches_modes(gated, capsys):
	out = []
	gate = OpsecGate('off', out=out.append)
	console = MSLDAPOpsConsole(None, gate=gate)
	assert await console._run_single_command('opsec', ['show']) is True
	assert gate.mode == 'show'
	assert hooks._foreground is None  # no command running anymore
	assert await console._run_single_command('opsec', ['bogus']) is False
	assert 'opsec mode: show' in capsys.readouterr().out
