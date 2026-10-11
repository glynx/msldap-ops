"""Terminal output: colors on top of the plain text layout.

All output of the shell, including the msldap built-in commands, goes through StyledStream, which
colors it line by line before it reaches the terminal. The text itself keeps its plain layout
(copy/paste and grep work, and so do the GOAD checks); only on a terminal records get a separator
line and colors. NO_COLOR or --no-color switch this off.
"""

import io
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
	(r'^ACL of .*?(?=  \(from the cache, |$)', 'bold'),
	(r'^  Access +Principal +Rights +Object +Applies to$', 'bold'),
	(r'^  deny\b', 'yellow'),
	(r'^Note: .*$', 'yellow'),
	(r'^WARNING: .*$', 'bold yellow'),
	# records of msldap's query command
	(r'^DN: .*?(?=  \(from the cache, |$)', 'bold cyan'),
	(r'^Attributes:$', 'bright_black'),
	(r'^  [A-Za-z][\w;-]*:(?= |$)', 'blue'),
	(r'^\(\d+ objects?\)', 'bright_black'),
	(r'  \(from the cache, [^)]*\)$', 'bright_black'),
	(r'^    - ', 'bright_black'),
]
# lines that end a record (msldap's query prints '---') and lines that start one
RECORD_END = re.compile(r'^---$')
RECORD_START = re.compile(r'^Template \S')
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


def _width():
	return shutil.get_terminal_size().columns


def output_width():
	"""Width to lay out tables for: the terminal width, or None when the output goes to a file
	or pipe (no wrapping there)."""
	if not enabled():
		return None
	try:
		if not sys.stdout.isatty():
			return None
	except (AttributeError, ValueError):
		return None
	return _width()


def separator():
	return Text('\u2500' * min(_width(), 100), style='bright_black')


def styled(line):
	text = Text(line)
	for rx, style in _COMPILED:
		text.highlight_regex(rx, style)
	return text


ATTRIBUTE_LINE = re.compile(r'^( *[A-Za-z][\w;-]*: +)\S')
MIN_WRAP_WIDTH = 20


def wrap_spans(line, width):
	"""Where to split a line longer than the terminal: [(indent, start, end)]. Continuation lines
	are indented to the value column of an attribute line ('  description:   ...') or to the
	line's own indentation; breaks at spaces, hard breaks only within long words (hex, base64)."""
	if len(line) <= width:
		return [(0, 0, len(line))]
	m = ATTRIBUTE_LINE.match(line)
	indent = len(m.group(1)) if m else len(line) - len(line.lstrip(' '))
	if width - indent < MIN_WRAP_WIDTH:
		indent = 0
	spans, pos, pad = [], 0, 0
	while len(line) - pos + pad > width:
		room = width - pad
		cut = line.rfind(' ', pos + (indent if pad == 0 else 0) + 1, pos + room + 1)
		if cut == -1:
			spans.append((pad, pos, pos + room))
			pos += room
		else:
			spans.append((pad, pos, cut))
			pos = cut + 1
			while pos < len(line) and line[pos] == ' ':
				pos += 1
		pad = indent
	spans.append((pad, pos, len(line)))
	return spans


def wrap(line, width):
	return [' ' * pad + line[a:b].rstrip() for pad, a, b in wrap_spans(line, width)]


def render(line, width=None):
	"""ANSI rendering of one output line (without the newline), wrapped to the terminal width."""
	if '\x1b' in line:
		return line  # already colored
	if RECORD_END.match(line):
		texts = [separator()]
	else:
		full = styled(line)
		texts = []
		for pad, a, b in wrap_spans(line, width or _width()):
			text = Text(' ' * pad)
			text.append_text(full[a:b])
			texts.append(text)
		if RECORD_START.match(line):
			texts.insert(0, separator())
	buf = io.StringIO()
	console = Console(file=buf, force_terminal=True, width=100000, highlight=False, soft_wrap=True,
		emoji=False, markup=False)
	for i, text in enumerate(texts):
		console.print(text, end='' if i == len(texts) - 1 else '\n')
	return buf.getvalue()


class StyledStream(io.TextIOBase):
	"""Line buffered stdout wrapper that colors every complete line."""

	def __init__(self, target):
		self.target = target
		self._buf = ''

	def write(self, data):
		if not enabled():
			return self.target.write(data)
		self._buf += data
		if '\n' not in self._buf:
			return len(data)
		while '\n' in self._buf:
			line, self._buf = self._buf.split('\n', 1)
			self.target.write(render(line) + '\n')
		# prompt_toolkit's stdout proxy only shows what was flushed
		self.target.flush()
		return len(data)

	def flush(self):
		if self._buf:
			# a partial line (e.g. a prompt without newline) goes out as it is
			self.target.write(self._buf)
			self._buf = ''
		self.target.flush()

	def isatty(self):
		return self.target.isatty()

	# io.TextIOBase defines these itself (fileno raises), __getattr__ would never see them;
	# prompt_toolkit asks fileno() for the terminal size and fell back to 80x24
	def fileno(self):
		return self.target.fileno()

	@property
	def encoding(self):
		return getattr(self.target, 'encoding', 'utf-8')

	@property
	def errors(self):
		return getattr(self.target, 'errors', None)

	def __getattr__(self, name):
		return getattr(self.target, name)


def emit(lines):
	"""Prints output lines; the StyledStream on stdout colors them."""
	if isinstance(lines, str):
		lines = [lines]
	for line in lines:
		print(line)


def out(line):
	print(line)


_terminal = None


def terminal():
	"""The stream for messages that belong on the screen even while a command's output is
	redirected to a file (opsec queries and questions)."""
	return _terminal or sys.stdout


def set_terminal(stream):
	global _terminal
	_terminal = stream


def short_dn(dn, width):
	"""DN for the prompt: if too long, RDNs between the first one and the domain become '...',
	so the input does not wrap."""
	if len(dn) <= width:
		return dn
	from msldap_ops.navigation import join_dn, split_dn
	rdns = split_dn(dn)
	tail = [r for r in rdns[1:] if r.upper().startswith('DC=')] or rdns[-1:]
	middle = rdns[1:len(rdns) - len(tail)]
	while middle:
		middle = middle[1:]
		short = join_dn(rdns[:1] + ['...'] + middle + tail)
		if len(short) <= width:
			return short
	return join_dn(rdns[:1] + ['...'] + tail) if len(rdns) > 1 + len(tail) else dn


def prompt(dn):
	"""Prompt that stands out from the command output."""
	if not enabled():
		return '[%s]> ' % dn if dn else '> '
	parts = [('ansibrightblack', 'msldap-ops')]
	if dn:
		parts += [('', ' '), ('ansicyan bold', short_dn(dn, _width() - len('msldap-ops  > ') - 20))]
	parts += [('ansigreen bold', ' > ')]
	return FormattedText(parts)
