"""Opsec modes: show, confirm or suppress LDAP searches before they are sent.

Works for every command, including the msldap built-ins, through the search hook. Only searches
are covered; the bind and the RootDSE read during login are not searches in msldap's sense.

Modes:
	off      queries are sent without notice
	show     every query is printed before it is sent
	confirm  every query is printed and needs confirmation:
	         y = send, n = skip (the command gets an empty result),
	         a = send this and all further queries of the running command, q = abort the command;
	         the single query of cd, ls and cat is only shown
	dryrun   queries are printed but not sent; commands that build queries on earlier results
	         only show their first stage
"""

from msldap_ops import hooks

MODES = ('off', 'show', 'confirm', 'dryrun')

# navigation commands that send exactly one query: in confirm mode it is only shown; a second
# query of the same command is confirmed as usual
SINGLE_QUERY_COMMANDS = {'cd', 'ls', 'cat'}

CONTROL_NAMES = {
	'1.2.840.113556.1.4.319': 'paged',
	'1.2.840.113556.1.4.801': 'sd-flags',
	'1.2.840.113556.1.4.417': 'show-deleted',
	'1.2.840.113556.1.4.529': 'extended-dn',
	'1.2.840.113556.1.4.1504': 'asq',
	'1.2.840.113556.1.4.2064': 'show-recycled',
}


def format_query(query, prefix='[ldap]'):
	pad = ' ' * len(prefix)
	lines = ['%s %s  scope=%s' % (prefix, query.base, query.scope), '%s filter: %s' % (pad, query.query)]
	details = 'attributes: %s' % (','.join(query.attributes) or '(all)')
	controls = [CONTROL_NAMES.get(c, c) for c in query.controls if CONTROL_NAMES.get(c) != 'paged']
	if controls:
		details += '  controls: %s' % ','.join(controls)
	lines.append('%s %s' % (pad, details))
	return lines


async def default_ask(text):
	from prompt_toolkit import PromptSession
	return await PromptSession().prompt_async(text)


class OpsecGate:
	"""Gate for msldap_ops.hooks, see the module docstring."""

	def __init__(self, mode='off', ask=default_ask, out=print):
		self.mode = mode
		self.ask = ask
		self.out = out
		self.command = None
		self._send_all = False
		self._aborted = False
		self.counter = 0

	def set_mode(self, mode):
		if mode not in MODES:
			raise ValueError("Unknown opsec mode '%s', expected one of: %s" % (mode, ', '.join(MODES)))
		self.mode = mode

	def start_command(self, command):
		self.command = command
		self._send_all = False
		self._aborted = False
		self.counter = 0

	def _single_query_command(self):
		return self.command in SINGLE_QUERY_COMMANDS and self.counter <= 1

	def end_command(self):
		if self.counter and self.mode in ('show', 'confirm', 'dryrun') and not self._single_query_command():
			self.out('[opsec] %s: %d LDAP %s %s' % (
				self.command, self.counter, 'query' if self.counter == 1 else 'queries',
				'shown, none sent' if self.mode == 'dryrun' else 'issued'))
		self.command = None

	async def __call__(self, query):
		if self.mode == 'off' or query.background:
			# background queries (keepalive) cannot be confirmed and would interrupt the prompt
			return hooks.SEND
		if self._aborted:
			raise hooks.QueryAborted('aborted by operator')
		self.counter += 1
		prefix = '[%s #%d]' % ('dryrun' if self.mode == 'dryrun' else 'ldap', self.counter)
		for line in format_query(query, prefix):
			self.out(line)
		if self.mode == 'dryrun':
			return hooks.SKIP
		if self.mode == 'show' or self._send_all or self._single_query_command():
			return hooks.SEND

		while True:
			try:
				answer = (await self.ask('send? [y]es / [n]o, skip / [a]ll for this command / [q]uit command: ')).strip().lower()
			except (EOFError, KeyboardInterrupt):
				answer = 'q'
			if answer in ('y', 'yes'):
				return hooks.SEND
			if answer in ('n', 'no'):
				self.out('skipped')
				return hooks.SKIP
			if answer in ('a', 'all'):
				self._send_all = True
				return hooks.SEND
			if answer in ('q', 'quit'):
				self._aborted = True
				raise hooks.QueryAborted('aborted by operator')
