import asyncio

from msldap.examples.msldapclient import MSLDAPClientConsole
from msldap.protocol.constants import SUBTREE
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
from prompt_toolkit.completion import WordCompleter

from msldap_ops import presets


def sd_flags_control():
	# without SD flags non-admin users get no security descriptor (the SACL needs SeSecurityPrivilege)
	flags = SDFlagsRequest.OWNER_SECURITY_INFORMATION | SDFlagsRequest.GROUP_SECURITY_INFORMATION | SDFlagsRequest.DACL_SECURITY_INFORMATION
	return ('1.2.840.113556.1.4.801', True, SDFlagsRequestValue({'Flags': flags}).dump())


class MSLDAPOpsConsole(MSLDAPClientConsole):
	"""msldap shell with additional msldap-ops commands. All msldap commands remain available."""

	def __init__(self, url=None, querylog=None):
		MSLDAPClientConsole.__init__(self, url)
		self.querylog = querylog

	async def do_log(self, action=None):
		"""Shows or switches the bofhound query log.

		Without an argument the current state and the log files are shown.
		'on' and 'off' switch logging of all search results. The log uses the pyldapsearch format,
		import it with: bofhound -i <log directory>
		"""
		if self.querylog is None:
			print('Query logging is not available (started with --no-log)')
			return True
		if action is not None:
			action = action.lower()
			if action not in ('on', 'off'):
				print("Unknown action '%s', expected 'on' or 'off'" % action)
				return False
			self.querylog.enabled = action == 'on'
		print('Query logging: %s' % ('on' if self.querylog.enabled else 'off'))
		print('  results: %s' % self.querylog.path)
		print('  queries: %s' % self.querylog.query_path)
		return True

	def _log_completions(self):
		return WordCompleter(['on', 'off'])

	async def do_collect(self, names=None, delay='0'):
		"""Collects data for bofhound, split into one query per object type.

		names: comma separated presets, e.g. 'users,groups', or 'all'.
		       Without names the presets and their queries are listed.
		delay: seconds to wait between two queries (default 0).

		'all' runs every preset except 'dns', which can be large. Results are not printed,
		they go to the query log (see 'log'). All queries request *,nTSecurityDescriptor
		with the SD flags control, so unprivileged users get the DACLs as well.
		"""
		if names is None:
			self._print_presets()
			return True
		try:
			delay = float(delay)
			if delay < 0:
				raise ValueError
		except ValueError:
			print("Invalid delay '%s', expected seconds" % delay)
			return False
		if self.connection is None:
			print('Not connected, run login first')
			return False
		try:
			queries = presets.resolve([n.strip() for n in names.split(',') if n.strip()], self.connection._serverinfo, self.connection._tree)
		except ValueError as e:
			print(e)
			return False

		if self.querylog is None or not self.querylog.enabled:
			print('WARNING: query logging is off, the results are not saved')

		total, failed = 0, 0
		width = max(len('%s/%s' % (q.preset, q.label)) for q in queries)
		for i, query in enumerate(queries):
			if i > 0 and delay > 0:
				await asyncio.sleep(delay)
			name = ('%s/%s' % (query.preset, query.label)).ljust(width)
			count, err = await self._run_preset_query(query)
			total += count
			if err is not None:
				failed += 1
				print('  %s  %5d  error: %s' % (name, count, err))
			else:
				print('  %s  %5d' % (name, count))

		print('%d objects from %d queries, %d failed' % (total, len(queries), failed))
		if self.querylog is not None and self.querylog.enabled:
			print('Logged to %s' % self.querylog.path)
		return True

	async def _run_preset_query(self, query):
		controls = [sd_flags_control()] if query.wants_sd else None
		count = 0
		async for entry, err in self.connection.pagedsearch(query.filter, query.attributes, controls=controls, tree=query.base, search_scope=SUBTREE):
			if err is not None:
				return count, err
			count += 1
		return count, None

	def _print_presets(self):
		print('Presets (collect <name>[,<name>...] [delay]):')
		for name, (description, queries) in presets.PRESETS.items():
			marker = '' if name in presets.ALL else '  (not in all)'
			print('  %-11s %s%s' % (name, description, marker))
			for q in queries:
				print('  %-11s   %s  base=%s  attributes=%s' % ('', q.filter, q.base, ','.join(q.attributes)))

	def _collect_completions(self):
		return WordCompleter(['all'] + list(presets.PRESETS))
