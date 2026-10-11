"""Command history across sessions and the Ctrl-R search.

The history is kept in ``$XDG_STATE_HOME/msldap-ops/history`` (default
``~/.local/state/msldap-ops/history``), readable by the user only. Commands that carry secrets
(login with a password or hash in the URL, adduser, changeuserpw, addcomputer with a password)
are remembered for the running session but not written to the file.

Ctrl-R opens fzf over the history if fzf is installed, otherwise prompt_toolkit's reverse search.
"""

import os
import re
import shlex
import shutil
import subprocess

from prompt_toolkit.history import FileHistory

# a secret in an msldap URL: scheme://[domain\]user:SECRET@host
URL_SECRET = re.compile(r'://[^/@\s]*:[^@\s]+@')
# commands whose arguments include a password: command -> number of arguments from which on
SECRET_ARGUMENTS = {'adduser': 2, 'changeuserpw': 2, 'addcomputer': 2}


def default_path():
	state = os.environ.get('XDG_STATE_HOME') or os.path.join(os.path.expanduser('~'), '.local', 'state')
	return os.path.join(state, 'msldap-ops', 'history')


def is_sensitive(line):
	if URL_SECRET.search(line):
		return True
	try:
		words = shlex.split(line)
	except ValueError:
		words = line.split()
	if not words:
		return False
	needed = SECRET_ARGUMENTS.get(words[0])
	return needed is not None and len(words) - 1 >= needed


class PrivateFileHistory(FileHistory):
	"""FileHistory that creates its file with mode 0600 and does not store secrets."""

	def __init__(self, filename):
		os.makedirs(os.path.dirname(os.path.abspath(filename)), mode=0o700, exist_ok=True)
		if not os.path.exists(filename):
			os.close(os.open(filename, os.O_WRONLY | os.O_CREAT, 0o600))
		super().__init__(filename)

	def load_history_strings(self):
		# the file keeps every execution, the history shows each command once (newest first)
		return unique_recent(super().load_history_strings())

	def append_string(self, string):
		# a repeated command moves to the top instead of appearing twice
		self._loaded_strings = [s for s in self._loaded_strings if _key(s) != _key(string)]
		super().append_string(string)

	def store_string(self, string):
		if is_sensitive(string):
			return
		super().store_string(string)


def _key(string):
	"""Commands that differ only in whitespace are the same."""
	return ' '.join(string.split())


def unique_recent(strings):
	"""History entries newest first, without duplicates."""
	seen, result = set(), []
	for s in strings:
		if _key(s) and _key(s) not in seen:
			seen.add(_key(s))
			result.append(s)
	return result


def fzf_available():
	return shutil.which('fzf') is not None


def fzf_select(entries, query=''):
	"""Lets the user pick one entry with fzf; None if cancelled."""
	try:
		proc = subprocess.run(
			['fzf', '--no-multi', '--no-sort', '--height=40%', '--reverse', '--prompt=history> ', '--query', query],
			input='\n'.join(entries), stdout=subprocess.PIPE, text=True)
	except OSError:
		return None
	if proc.returncode != 0:
		return None
	return proc.stdout.rstrip('\n') or None


def add_fzf_binding(bindings, history):
	"""Ctrl-R: fzf over the history; the selection replaces the input line."""
	from prompt_toolkit.application import run_in_terminal

	@bindings.add('c-r')
	async def _(event):
		buffer = event.app.current_buffer
		entries = unique_recent(history.get_strings()[::-1])
		choice = await run_in_terminal(lambda: fzf_select(entries, buffer.text), in_executor=True)
		if choice is not None:
			buffer.text = choice
			buffer.cursor_position = len(choice)
