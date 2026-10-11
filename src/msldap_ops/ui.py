"""Terminal output: colors on top of the plain text layout.

The msldap-ops commands keep their plain text layout (copy/paste and grep work, and so do the GOAD
checks); rich only adds colors, and only when stdout is a terminal. NO_COLOR or --no-color switch
them off.
"""

import os
import re
import shutil
import sys

from prompt_toolkit.formatted_text import FormattedText
from rich.console import Console
from rich.text import Text

_enabled = None

# (regex, style) applied to every line of msldap-ops output, in this order
RULES = [
	(r'\[!\]', 'bold red'),
	(r'\bTrue \[!\]', 'bold red'),
	# ESC findings, not template names (GOAD's templates are called ESC1, ...): the finding lines
	# below "Vulnerabilities" and the last column of the templates table
	(r'(?<=^    )ESC\d+(?= +: )', 'bold red'),
	(r'(?<=  )ESC\d+(, ESC\d+)*$', 'bold red'),
	(r'\b(kerberoastable|asrep-roastable|unconstrained-delegation|password-not-required)\b', 'red'),
	(r'\bdelegable\b', 'yellow'),
	(r'\b(disabled|not found|not published[^)]*|\(not published\))', 'dim'),
	# the query display of opsec show/confirm/dryrun: header, filter and attribute lines
	(r'^\[(ldap|dryrun) #\d+\] .*$', 'bright_black'),
	(r'^ +(filter|attributes): .*$', 'bright_black'),
	(r'^\[cache\] .*$', 'bright_black'),
	(r'^\[opsec\].*$', 'dim'),
	(r'^send\? .*$', 'bold'),
	(r'^(Privileged groups in|Privileged accounts:|adminCount=1 users|Name or description contains|Template |Errors:).*$', 'bold'),
	(r'^  (Permissions|\[!\] Vulnerabilities.*)$', 'bold'),
	(r'^Note: .*$', 'yellow'),
	(r'^WARNING: .*$', 'bold yellow'),
]
_COMPILED = [(re.compile(rx), style) for rx, style in RULES]


def set_enabled(value):
	global _enabled
	_enabled = value


def enabled():
	if _enabled is not None:
		return _enabled
	if os.environ.get('NO_COLOR'):
		return False
	# the shell replaces sys.stdout with prompt_toolkit's proxy, ask the real terminal
	return sys.__stdout__ is not None and sys.__stdout__.isatty()


def _console():
	return Console(file=sys.stdout, force_terminal=True, width=shutil.get_terminal_size().columns,
		highlight=False, soft_wrap=True, emoji=False, markup=False)


def styled(line):
	text = Text(line)
	for rx, style in _COMPILED:
		text.highlight_regex(rx, style)
	return text


def emit(lines):
	"""Prints msldap-ops output lines, colored when possible."""
	if isinstance(lines, str):
		lines = [lines]
	if not enabled():
		for line in lines:
			print(line)
		return
	console = _console()
	for line in lines:
		console.print(styled(line))


def out(line):
	emit([line])


def prompt(dn):
	"""Prompt that stands out from the command output."""
	if not enabled():
		return '[%s]> ' % dn if dn else '> '
	parts = [('ansibrightblack', 'msldap-ops')]
	if dn:
		parts += [('', ' '), ('ansicyan bold', dn)]
	parts += [('ansigreen bold', ' > ')]
	return FormattedText(parts)
