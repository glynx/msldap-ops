import pytest
from prompt_toolkit.formatted_text import FormattedText

from msldap_ops import ui
from msldap_ops.shell import MSLDAPOpsConsole


@pytest.fixture
def color():
	ui.set_enabled(True)
	yield
	ui.set_enabled(None)


@pytest.fixture
def plain():
	ui.set_enabled(False)
	yield
	ui.set_enabled(None)


def test_plain_output_is_unchanged(plain, capsys):
	ui.emit(['  Enrollee Supplies Subject       : True [!]', '[opsec] x: 1 LDAP query sent'])
	assert capsys.readouterr().out == '  Enrollee Supplies Subject       : True [!]\n[opsec] x: 1 LDAP query sent\n'


def test_colors_keep_the_text(color, capsys):
	line = '    eddard.stark  user  direct  kerberoastable, delegable'
	ui.emit([line])
	out = capsys.readouterr().out
	assert '\x1b[' in out
	# without the escape sequences the line is the same
	import re
	assert re.sub(r'\x1b\[[0-9;]*m', '', out) == line + '\n'


def test_styles():
	spans = {str(ui.styled('  Enrollee Supplies Subject       : True [!]')[s.start:s.end]): s.style for s in ui.styled('  Enrollee Supplies Subject       : True [!]').spans}
	assert spans['True [!]'] == 'bold red'
	cache = ui.styled('[cache] (a=b)  DC=x  scope=sub')
	assert cache.spans[0].style == 'cyan' and cache.spans[0].end == len('[cache]')


def test_no_color_environment(monkeypatch):
	ui.set_enabled(None)
	monkeypatch.setenv('NO_COLOR', '1')
	assert ui.enabled() is False


def test_prompt_follows_msldap_assignments(color):
	console = MSLDAPOpsConsole(None)
	console.prompt = '[DC=north,DC=sevenkingdoms,DC=local]> '
	assert isinstance(console.prompt, FormattedText)
	assert ('ansicyan bold', 'DC=north,DC=sevenkingdoms,DC=local') in list(console.prompt)


def test_plain_prompt_keeps_the_msldap_format(plain):
	console = MSLDAPOpsConsole(None)
	console.prompt = '[DC=x]> '
	assert console.prompt == '[DC=x]> '


def spans(line):
	text = ui.styled(line)
	return [(line[s.start:s.end], s.style) for s in text.spans]


def test_esc_only_highlighted_as_finding():
	assert spans('Template ESC1') == [('Template ESC1', 'bold')]
	assert spans('  Template Name                   : ESC1') == []
	assert spans('  Display Name                    : ESC1') == []
	assert ('ESC1', 'bold red') in spans('    ESC1                          : Users can enroll, enrollee supplies subject')
	# templates table: the name column stays plain, the vulnerabilities column is highlighted
	row = '  ESC1         ESSOS-CA  yes          yes               no        ESC1, ESC9'
	assert spans(row) == [('ESC1, ESC9', 'bold red')]


def test_password_never_expires_is_not_colored():
	assert spans('    eddard.stark  user  direct  password-never-expires, delegable') == [('delegable', 'yellow')]
