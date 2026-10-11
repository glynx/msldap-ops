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


def strip_ansi(text):
	import re
	return re.sub(r'\x1b\[[0-9;]*m', '', text)


def test_colors_keep_the_text(color):
	import io
	target = io.StringIO()
	stream = ui.StyledStream(target)
	line = '    eddard.stark  user  direct  kerberoastable, delegable'
	stream.write(line[:10])
	assert target.getvalue() == ''  # line buffered
	stream.write(line[10:] + '\n')
	assert '\x1b[' in target.getvalue()
	# without the escape sequences the line is the same
	assert strip_ansi(target.getvalue()) == line + '\n'


def test_plain_stream_passes_through(plain):
	import io
	target = io.StringIO()
	ui.StyledStream(target).write('---\nDN: CN=x\n')
	assert target.getvalue() == '---\nDN: CN=x\n'


def test_records_are_separated_on_the_terminal(color):
	assert strip_ansi(ui.render('---')).startswith('\u2500\u2500\u2500')
	header = strip_ansi(ui.render('Template ESC1')).split('\n')
	assert header[0].startswith('\u2500') and header[1] == 'Template ESC1'
	assert ('DN: CN=jon.snow,DC=x', 'bold cyan') in spans('DN: CN=jon.snow,DC=x')
	assert ('  sAMAccountName:', 'blue') in spans('  sAMAccountName: jon.snow')
	# the templates details use ' : ', those keys stay plain
	assert spans('  Template Name                   : ESC1') == []


def test_styles():
	assert ('True [!]', 'bold red') in spans('  Enrollee Supplies Subject       : True [!]')
	for line in ['[cache] (a=b)  DC=x  scope=sub', '[ldap #1] DC=x  scope=sub', '          filter: (a=b)',
			'          attributes: *,nTSecurityDescriptor  controls: sd-flags', '[dryrun #2] DC=x  scope=one']:
		assert spans(line) == [(line, 'bright_black')]
	assert spans('send? [y]es / [n]o, skip') == [('send? [y]es / [n]o, skip', 'bold')]


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
