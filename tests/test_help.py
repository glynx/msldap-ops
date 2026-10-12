from msldap_ops import ui
from msldap_ops.shell import HELP_CATEGORIES, MSLDAPOpsConsole


def test_help_groups_commands(capsys):
	console = MSLDAPOpsConsole(None)
	assert console.do_help() is True
	out = capsys.readouterr().out
	# every category with its commands appears, our commands grouped
	for title in ['Session:', 'Connection:', 'Navigation:', 'Enumeration:', 'ADCS:', 'DNS:', 'Writing (changes the directory):', 'Legacy msldap commands:']:
		assert title in out
	def section(title):
		return out.split(title + ':')[1].split('\n\n')[0]
	for name in ['cd ', 'cat ', 'find ']:
		assert name in section('Navigation')
	for name in ['login', 'nocb', 'nosig', 'nullcb', 'exit', 'quit']:
		assert name in section('Connection')
	for name in ['unconstrained', 'constrained', 'modify', 'changeowner', 'certtemplates']:
		assert name in section('Legacy msldap commands')
	assert 'Use delegations unconstrained.' in section('Legacy msldap commands')
	assert 'addusertogroup <user_dn> <group_dn> *' in section('Writing (changes the directory)')
	assert 'shadowcred' in section('Legacy msldap commands')
	assert 'Use keycred <path> add.' in section('Legacy msldap commands')
	assert 'certify2' in section('ADCS')
	assert 'cas ' in section('ADCS')
	assert 'Use cas.' in section('Legacy msldap commands')
	assert 'dnsquery' in section('DNS')
	assert ' *' in next(line for line in section('DNS').splitlines() if line.strip().startswith('dnsadd '))
	assert 'groupmembers' in section('Enumeration')
	assert 's4u2proxy' in section('Enumeration')



def test_help_single_command_still_detailed(capsys):
	console = MSLDAPOpsConsole(None)
	assert console.do_help('laps') is True
	out = capsys.readouterr().out
	assert out.startswith('Usage: laps') and 'both LAPS versions' in out


def test_every_categorized_command_exists():
	console = MSLDAPOpsConsole(None)
	available = set(console.command_list)
	for _, names in HELP_CATEGORIES:
		for name in names:
			assert name in available, name


def test_category_headings_are_bold():
	spans = [(t.start, t.end, str(t.style)) for t in ui.styled('Navigation:').spans]
	assert any(style == 'bold' for _, _, style in spans)


def test_delegation_heading_uses_existing_bold_style():
	text = ui.styled('Resource-based constrained delegation (1)')
	assert [str(span.style) for span in text.spans] == ['bold']


def test_help_summaries_are_short():
	import inspect
	from msldap_ops.shell import HELP_SUMMARIES, LEGACY_REPLACEMENTS
	console = MSLDAPOpsConsole(None)
	for name in console.command_list:
		if name == '?' or name in LEGACY_REPLACEMENTS:
			continue
		summary = HELP_SUMMARIES.get(name, (inspect.getdoc(console._get_command(name)) or '').split('\n')[0])
		assert len(summary) <= 65, (name, summary)


def test_requested_commands_have_categories():
	groups = dict(HELP_CATEGORIES)
	assert {'whoami', 'whoamiraw'} <= set(groups['Session'])
	assert {'dmsas', 'gpos', 'badsuccessor_check'} <= set(groups['Enumeration'])
	assert {'create_broken_dmsa_user', 'dmsasetdelegatedmsastate'} <= set(groups['Writing (changes the directory)'])


def test_help_does_not_highlight_findings(monkeypatch):
	import io
	from contextlib import redirect_stdout
	from msldap_ops.shell import WRITING_COMMANDS
	monkeypatch.setattr(ui, '_enabled', True)
	target = io.StringIO()
	with redirect_stdout(ui.StyledStream(target)):
		MSLDAPOpsConsole(None).do_help()
	out = target.getvalue()
	assert '\x1b[1mEnumeration:' in out
	assert 'kerberoastable' in out
	assert '\x1b[31m' not in out
	assert 'create_broken_dmsa_user' in WRITING_COMMANDS
	assert 'dmsasetdelegatedmsastate' in WRITING_COMMANDS
	# The help context must not affect later enumeration output.
	assert any(str(span.style) == 'red' for span in ui.styled('kerberoastable').spans)
