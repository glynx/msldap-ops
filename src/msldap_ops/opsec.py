"""Opsec modes: show, confirm or suppress LDAP searches before they are sent.

Works for every command, including the msldap built-ins, through the search hook. Only searches
are covered; the bind and the RootDSE read during login are not searches in msldap's sense.

Modes:
	off      queries are sent without notice
	show     every query is printed before it is sent
	confirm  every query is printed and needs confirmation:
	         y = send, n = skip (the command gets an empty result),
	         a = send this and all further queries of the running command, q = abort the command;
	         the queries of cd, ls and cat are only shown
	searches answered from the cache are never confirmed (nothing is sent); they are shown as
	one [cache] line and counted separately in the summary after each command
	dryrun   queries are printed but not sent; commands that build queries on earlier results
	         only show their first stage
"""

from msldap_ops import hooks

MODES = ('off', 'show', 'confirm', 'dryrun')

# navigation commands: in confirm mode their queries are only shown, not confirmed
NAVIGATION_COMMANDS = {'cd', 'ls', 'cat'}

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
		self.counter = 0  # queries shown, numbers them
		self.sent = 0
		self.skipped = 0
		self.aborted_at = None
		self.cached_counter = 0

	def _navigation(self):
		return self.command in NAVIGATION_COMMANDS

	def summary(self):
		"""What actually happened: sent, skipped, aborted, answered from the cache."""
		def queries(n):
			return '%d LDAP %s' % (n, 'query' if n == 1 else 'queries')

		if self.mode == 'dryrun' and self.counter:
			parts = ['%s shown, none sent' % queries(self.counter)]
		else:
			parts = [queries(self.sent) + ' sent' if self.sent else 'no LDAP queries sent']
		if self.skipped:
			parts.append('%d skipped' % self.skipped)
		if self.aborted_at is not None:
			parts.append('aborted at query #%d' % self.aborted_at)
		if self.cached_counter:
			parts.append('%d answered from the cache' % self.cached_counter)
		return ', '.join(parts)

	def end_command(self):
		if (self.counter or self.cached_counter) and self.mode in ('show', 'confirm', 'dryrun') and not self._navigation():
			self.out('[opsec] %s: %s' % (self.command, self.summary()))
		self.command = None

	def cached(self, query):
		"""A search answered from the cache: nothing is sent, so it is not confirmed; shown as a
		single line in show/confirm/dryrun and counted separately."""
		if self.mode == 'off' or query.background:
			return
		self.cached_counter += 1
		self.out('[cache] %s  %s  scope=%s' % (query.query, query.base, query.scope))

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
		if self.mode == 'show' or self._send_all or self._navigation():
			self.sent += 1
			return hooks.SEND

		while True:
			try:
				answer = (await self.ask('send? [y]es / [n]o, skip / [a]ll for this command / [q]uit command: ')).strip().lower()
			except (EOFError, KeyboardInterrupt):
				answer = 'q'
			if answer in ('y', 'yes'):
				self.sent += 1
				return hooks.SEND
			if answer in ('n', 'no'):
				self.skipped += 1
				self.out('skipped')
				return hooks.SKIP
			if answer in ('a', 'all'):
				self._send_all = True
				self.sent += 1
				return hooks.SEND
			if answer in ('q', 'quit'):
				self._aborted = True
				self.aborted_at = self.counter
				raise hooks.QueryAborted('aborted by operator')
