import pytest

from msldap_ops import hooks, ui
from msldap_ops.opsec import OpsecGate
from msldap_ops.shell import MSLDAPOpsConsole, split_redirect


@pytest.mark.parametrize('args, expected', [
	(['(cn=x)', 'cn'], (['(cn=x)', 'cn'], None, False)),
	(['(cn=x)', '>', 'out.txt'], (['(cn=x)'], 'out.txt', False)),
	(['(cn=x)', '>>', 'out.txt'], (['(cn=x)'], 'out.txt', True)),
	(['(cn=x)', '>out.txt'], (['(cn=x)'], 'out.txt', False)),
	(['>>out.txt'], ([], 'out.txt', True)),
	# '>' inside a filter is not a redirect
	(['(pwdLastSet>=1)'], (['(pwdLastSet>=1)'], None, False)),
])
def test_split_redirect(args, expected):
	assert split_redirect(args) == expected


@pytest.mark.parametrize('args', [['>'], ['x', '>', 'a', 'b'], ['>a', 'b']])
def test_split_redirect_errors(args):
	with pytest.raises(ValueError):
		split_redirect(args)


@pytest.fixture
def console(tmp_path):
	out = []
	console = MSLDAPOpsConsole(None, gate=OpsecGate('show', out=out.append))
	console.screen = out
	yield console
	hooks.set_foreground(hooks.UNMANAGED)


async def test_output_goes_to_the_file(console, tmp_path, capsys):
	target = tmp_path / 'help.txt'
	assert await console._run_single_command('help', ['map', '>', str(target)]) is True
	assert target.read_text().startswith('Usage: map [dn] [depth]')
	out = capsys.readouterr().out
	assert 'Usage: map' not in out
	assert 'Output written to %s' % target in out

	assert await console._run_single_command('help', ['log', '>>', str(target)]) is True
	text = target.read_text()
	assert 'Usage: map' in text and 'Usage: log' in text
	assert 'Output appended to' in capsys.readouterr().out


async def test_unwritable_file(console, tmp_path, capsys):
	assert await console._run_single_command('help', ['>', str(tmp_path / 'missing' / 'x.txt')]) is False
	assert 'Cannot write' in capsys.readouterr().out


async def test_opsec_lines_stay_on_the_screen(tmp_path, capsys):
	from msldap_ops.opsec import default_out
	target = tmp_path / 'x.txt'
	console = MSLDAPOpsConsole(None)

	async def fake(self):
		default_out('[ldap #1] DC=x  scope=sub')
		print('result line')
		return True

	MSLDAPOpsConsole.do_fake = fake
	try:
		await console._run_single_command('fake', ['>', str(target)])
	finally:
		del MSLDAPOpsConsole.do_fake
		hooks.set_foreground(hooks.UNMANAGED)
	assert target.read_text() == 'result line\n'
	assert '[ldap #1] DC=x' in capsys.readouterr().out
