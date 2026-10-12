import pytest

from msldap.examples.msldapclient import MSLDAPClientConsole

from msldap_ops import cli
from msldap_ops.shell import MSLDAPOpsConsole


def test_shell_extends_msldap_console():
	assert issubclass(MSLDAPOpsConsole, MSLDAPClientConsole)


def test_help_exits_cleanly(monkeypatch, capsys):
	monkeypatch.setattr('sys.argv', ['msldap-ops', '--help'])
	with pytest.raises(SystemExit) as exc:
		cli.main()
	assert exc.value.code == 0
	assert 'msldap-ops' in capsys.readouterr().out


async def test_log_command(tmp_path, capsys):
	from msldap_ops.querylog import QueryLog

	querylog = QueryLog(str(tmp_path))
	console = MSLDAPOpsConsole(None, querylog=querylog)
	assert await console.do_log('off') is True
	assert querylog.enabled is False
	assert await console.do_log('maybe') is False
	assert await console.do_log('on') is True
	out = capsys.readouterr().out
	assert 'Query logging: on' in out
	assert str(tmp_path) in out


async def test_log_command_without_logging(capsys):
	console = MSLDAPOpsConsole(None)
	assert await console.do_log() is True
	assert '--no-log' in capsys.readouterr().out


def test_failed_login_leaves_no_connection(monkeypatch):
	import asyncio

	from msldap.examples.msldapclient import MSLDAPClientConsole

	from msldap_ops.shell import MSLDAPOpsConsole

	async def failing_login(self, url=None):
		self.connection = object()
		return False

	monkeypatch.setattr(MSLDAPClientConsole, 'do_login', failing_login)
	console = MSLDAPOpsConsole(None)
	assert asyncio.run(console.do_login('ldap://x')) is False
	assert console.connection is None


def test_pasted_block_runs_line_by_line(capsys):
	import asyncio

	from msldap_ops.shell import MSLDAPOpsConsole

	class Session:
		def __init__(self, inputs):
			self.inputs = list(inputs)

		async def prompt_async(self, *args, **kwargs):
			if not self.inputs:
				raise EOFError
			return self.inputs.pop(0)

	console = MSLDAPOpsConsole(None)
	ran = []

	async def record(command, args):
		ran.append([command] + args)

	console._run_single_command = record
	console.session = Session(['cache\nopsec show\n\nnosuchcommand', "opsec 'show", 'log'])
	asyncio.run(console._run_prompt_forever())
	assert ran == [['cache'], ['opsec', 'show'], ['log']]
	out = capsys.readouterr().out
	assert 'Command nosuchcommand not found!' in out and 'Cannot parse' in out


def test_parse_delay():
	import pytest

	from msldap_ops.shell import parse_delay
	assert parse_delay('0') == (0.0, 0.0)
	assert parse_delay('3') == (3.0, 3.0)
	assert parse_delay('2-8') == (2.0, 8.0)
	for bad in ('5-2', 'x', '-1', '2-'):
		with pytest.raises(ValueError):
			parse_delay(bad)
