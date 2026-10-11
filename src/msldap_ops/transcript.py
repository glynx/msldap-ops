"""Session transcript: every command with a timestamp, followed by its output as plain text.

The output is taken from the shell's stdout stream (StyledStream), so it contains what was on the
screen, without colors: command output, the queries shown by opsec and the answers to its
questions. Output redirected to a file (`> file`) is not repeated, only the "Output written to"
note. Commands with secrets (see msldap_ops.history.is_sensitive) are written without arguments.
"""

import datetime
import os
import re
import shlex

DEFAULT_PREFIX = 'msldap-ops-transcript'
ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')


def default_path(directory='.'):
	return os.path.join(directory, '%s_%s.log' % (DEFAULT_PREFIX, datetime.date.today().isoformat()))


def command_line(command, args):
	from msldap_ops.history import is_sensitive
	# redirections stay readable (> file instead of '>' file)
	line = ' '.join(a if a in ('>', '>>') else shlex.quote(a) for a in [command] + list(args))
	if is_sensitive(line):
		return '%s [arguments not recorded]' % command
	return line


class Transcript:
	def __init__(self, path):
		self.path = os.path.abspath(path)
		self._file = open(self.path, 'a', encoding='utf-8')
		self._partial = False
		self.note('transcript started')

	def _stamp(self):
		return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

	def note(self, text):
		self._line_break()
		self._file.write('### %s %s\n' % (self._stamp(), text))
		self._file.flush()

	def command(self, dn, command, args):
		self._line_break()
		self._file.write('\n[%s] msldap-ops %s> %s\n' % (self._stamp(), dn + ' ' if dn else '', command_line(command, args)))
		self._file.flush()

	def output(self, data):
		data = ANSI.sub('', data)
		if not data:
			return
		self._file.write(data)
		self._partial = not data.endswith('\n')
		self._file.flush()

	def answer(self, question, answer):
		self.output('%s%s\n' % (question, answer))

	def _line_break(self):
		if self._partial:
			self._file.write('\n')
			self._partial = False

	def close(self):
		self.note('transcript stopped')
		self._file.close()


_active = None


def active():
	return _active


def start(path):
	global _active
	stop()
	_active = Transcript(path)
	return _active


def stop():
	global _active
	if _active is not None:
		_active.close()
		_active = None
