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
