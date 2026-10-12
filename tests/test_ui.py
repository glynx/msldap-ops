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
	assert spans('  [review] WriteDacl') == [('[review]', 'yellow')]
	for line in ['[cache] (a=b)  DC=x  scope=sub', '[ldap #1] DC=x  scope=sub', '          filter: (a=b)',
			'          attributes: *,nTSecurityDescriptor  controls: sd-flags', '[dryrun #2] DC=x  scope=one']:
		assert spans(line) == [(line, 'bright_black')]
	assert spans('send? [y]es / [n]o, skip') == [('send? [y]es / [n]o, skip', 'bold')]


def test_disabled_dn_is_gray_instead_of_bold_cyan():
	from rich.console import Console
	line = 'DN: 👤 CN=disabled,DC=x [disabled]  (from cache: 2026-10-12 10:00)'
	text = ui.styled(line)
	style = text.get_style_at_offset(Console(), line.index('CN='))
	assert style.color.name == 'bright_black' and style.bold is False
	assert text.plain == line


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
	assert spans('  ESC4  ESSOS-CA  no  no  yes  ESC4 [?]') == [('ESC4 [?]', 'yellow')]
	assert spans('  Custom  ESSOS-CA  yes  no  no  ESC1, ESC4 [?], ESC9') == [
		('ESC1', 'bold red'), ('ESC9', 'bold red'), ('ESC4 [?]', 'yellow')]
	assert spans('  Custom  ESSOS-CA  yes  no  no  ESC13 [?], ESC4 [?]') == [
		('ESC13 [?]', 'yellow'), ('ESC4 [?]', 'yellow')]
	assert not any(style == 'bold red' for _, style in spans('    [review] ESC4 ACL             : Other principals can control the template'))


def test_password_never_expires_is_not_colored():
	assert spans('    eddard.stark  user  direct  password-never-expires, delegable') == [('delegable', 'yellow')]


def test_long_values_wrap_at_the_value_column(color):
	line = '  description:            Members of this group can remotely query authorization attributes'
	assert ui.wrap(line, 60) == [
		'  description:            Members of this group can remotely',
		'                          query authorization attributes',
	]
	# no spaces (hex): hard breaks, still below the value column
	assert ui.wrap('  dSASignature: ' + 'ab' * 30, 40) == [
		'  dSASignature: ' + 'ab' * 12,
		'                ' + 'ab' * 12,
		'                ' + 'ab' * 6,
	]
	assert strip_ansi(ui.render(line, 60)).split('\n') == ui.wrap(line, 60)


def test_short_lines_are_not_wrapped(color):
	assert ui.wrap('  cn: Users', 80) == ['  cn: Users']


def test_prompt_dn_is_shortened_to_fit():
	dn = 'CN=Access Control Assistance Operators,CN=Builtin,DC=essos,DC=local'
	assert ui.short_dn(dn, 100) == dn
	assert ui.short_dn('CN=a,OU=b,OU=c,OU=d,DC=essos,DC=local', 33) == 'CN=a,...,OU=d,DC=essos,DC=local'
	assert ui.short_dn(dn, 40) == 'CN=Access Control Assistance Operators,...,DC=essos,DC=local'


def test_styled_stream_keeps_the_terminal_reachable():
	# prompt_toolkit asks fileno() for the terminal size; io.TextIOBase's own fileno() raised
	import io
	import sys
	stream = ui.StyledStream(sys.__stdout__)
	assert stream.fileno() == sys.__stdout__.fileno()
	assert stream.encoding == sys.__stdout__.encoding
	assert ui.StyledStream(io.StringIO()).encoding is None


def test_deferred_inner_stream_does_not_restyle_help(color):
	import io
	from contextlib import redirect_stdout
	pending = io.StringIO()
	with redirect_stdout(ui.StyledStream(pending)):
		MSLDAPOpsConsole(None).do_help('spns')
	# prompt_toolkit forwards output later, after the help context has ended.
	target = io.StringIO()
	inner = ui.StyledStream(target)
	inner.style_output = False
	inner.write(pending.getvalue())
	assert 'kerberoastable' in target.getvalue()
	assert '\x1b[31m' not in target.getvalue()
