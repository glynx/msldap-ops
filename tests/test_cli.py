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
