from msldap_ops import ui
from msldap_ops.shell import HELP_CATEGORIES, MSLDAPOpsConsole


def test_help_groups_commands(capsys):
	console = MSLDAPOpsConsole(None)
	assert console.do_help() is True
	out = capsys.readouterr().out
	# every category with its commands appears, our commands grouped
	for title in ['Session:', 'Navigation:', 'Enumeration:', 'Lookup:', 'ADCS:', 'DNS:', 'Writing (changes the directory):']:
		assert title in out
	assert 'Other msldap commands:' in out  # the long tail
	# a few commands land in the right section
	nav = out.split('Navigation:')[1].split('\n\n')[0]
	for name in ['cd ', 'cat ', 'find ']:
		assert name in nav
	writing = out.split('Writing')[1]
	assert 'addusertogroup' in writing
	# writing commands are marked with * in any category (also ADCS/DNS)
	assert 'addusertogroup <user_dn> <group_dn> *' in out
	adcs = out.split('ADCS:')[1].split('\n\n')[0]
	assert 'templates ' in adcs and 'addenrollmentright' in adcs and 'addenrollmentright <certtemplatename> <user_dn> *' in out
	dns = out.split('DNS:')[1].split('\n\n')[0]
	assert 'dnsquery' in dns and 'dnsadd ' in dns and ' *' in dns.split('dnsadd')[1].split('\n')[0]


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
