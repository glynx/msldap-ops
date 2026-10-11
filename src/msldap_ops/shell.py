import asyncio

from msldap.examples.msldapclient import MSLDAPClientConsole
from msldap.protocol.constants import SUBTREE
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
from prompt_toolkit.completion import WordCompleter

from msldap_ops import hooks, opsec, presets, privileged, templates


def sd_flags_control():
	# without SD flags non-admin users get no security descriptor (the SACL needs SeSecurityPrivilege)
	flags = SDFlagsRequest.OWNER_SECURITY_INFORMATION | SDFlagsRequest.GROUP_SECURITY_INFORMATION | SDFlagsRequest.DACL_SECURITY_INFORMATION
	return ('1.2.840.113556.1.4.801', True, SDFlagsRequestValue({'Flags': flags}).dump())


class MSLDAPOpsConsole(MSLDAPClientConsole):
	"""msldap shell with additional msldap-ops commands. All msldap commands remain available."""

	def __init__(self, url=None, querylog=None, gate=None, keepalive=300, cache=None):
		MSLDAPClientConsole.__init__(self, url)
		self.querylog = querylog
		self.cache = cache
		self.gate = gate if gate is not None else opsec.OpsecGate()
		self.keepalive = keepalive

	async def _run_single_command(self, command, args):
		# the task running the command; queries from other tasks (keepalive) are background
		hooks.set_foreground(asyncio.current_task())
		self.gate.start_command(command)
		try:
			return await MSLDAPClientConsole._run_single_command(self, command, args)
		finally:
			self.gate.end_command()
			hooks.set_foreground(None)
			if self.cache is not None:
				try:
					self.cache.save()
				except OSError as e:
					print('Could not save the cache: %s' % e)

	async def do_login(self, url=None):
		"""Performs connection and login"""
		res = await MSLDAPClientConsole.do_login(self, url)
		if self.connection is not None:
			self._apply_keepalive()
		return res

	def _apply_keepalive(self):
		# msldap's shell sends a keepalive search on the domain object every 10 seconds
		if self.keepalive and self.keepalive > 0:
			self.connection.keepalive_period = self.keepalive
			return
		task = getattr(self.connection, '_MSLDAPClient__keepalive_task', None)
		if task is not None:
			task.cancel()

	async def do_cache(self, action=None, value=None):
		"""Shows or controls the query cache.

		cache                  state, size, hits/misses and the cache file
		cache list             cached queries with age and number of results
		cache flush [text]     drops all cached queries and the DN index, or only the queries
		                       whose base DN or filter contains text
		cache ttl <seconds>    how long results are reused (default 1800)
		cache on | off         answer repeated searches from the cache or always ask the server

		Repeated searches within the TTL are answered from the cache without contacting the
		server; opsec show marks them with [cache]. Background queries (keepalive), searches
		stopped early and failed ones are not cached; add/modify/delete drop the cached queries.
		The cache is kept per server and account in ./msldap-ops-cache/.
		"""
		if self.cache is None:
			print('The cache is not available (started with --no-cache)')
			return True
		action = (action or '').lower()
		if action == 'flush':
			dropped = self.cache.flush(value)
			print('Dropped %d cached %s%s' % (dropped, 'query' if dropped == 1 else 'queries', '' if value else ' and the DN index'))
			return True
		if action == 'ttl':
			try:
				self.cache.ttl = int(value)
			except (TypeError, ValueError):
				print('Usage: cache ttl <seconds>')
				return False
			self.cache.expire()
		elif action in ('on', 'off'):
			self.cache.enabled = action == 'on'
		elif action == 'list':
			rows = [['age', 'results', 'base', 'filter']] + [['%ds' % a, str(n), b, f] for a, n, b, f in self.cache.list_queries()]
			for line in privileged.table(rows, 2):
				print(line)
			return True
		elif action:
			print("Unknown action '%s', see 'help cache'" % action)
			return False
		stats = self.cache.stats()
		print('Query cache: %s, ttl %ds' % ('on' if self.cache.enabled else 'off', self.cache.ttl))
		print('  %d queries (%d results), %d DNs known, %d hits / %d misses this session' % (
			stats['queries'], stats['entries'], stats['dns'], stats['hits'], stats['misses']))
		if stats['oldest']:
			print('  oldest entry from %s' % stats['oldest'])
		print('  file: %s' % (self.cache.path or '(not bound yet, log in first)' if self.cache.persist else 'not persisted'))
		return True

	def _cache_completions(self):
		return WordCompleter(['list', 'flush', 'ttl', 'on', 'off'])

	async def do_opsec(self, mode=None):
		"""Shows or sets the opsec mode for LDAP searches.

		off      queries are sent without notice (default)
		show     every query is printed before it is sent
		confirm  every query is printed and needs confirmation:
		         y = send, n = skip (the command gets an empty result),
		         a = send all further queries of this command, q = abort the command;
		         the queries of cd, ls and cat are only shown
		dryrun   queries are printed but not sent; commands that build queries on the
		         results of earlier ones (e.g. find_admins) only show their first stage

		Covers every command, including the msldap built-ins. Searches answered from the query
		cache send nothing and are never confirmed; they are shown as one [cache] line and
		counted separately. Background queries (keepalive) are not shown or confirmed. All of
		them are recorded in the query journal.
		"""
		if mode is not None:
			try:
				self.gate.set_mode(mode.lower())
			except ValueError as e:
				print(e)
				return False
		print('opsec mode: %s' % self.gate.mode)
		if self.keepalive and self.keepalive > 0:
			print('keepalive: every %d seconds' % self.keepalive)
		else:
			print('keepalive: off')
		return True

	def _opsec_completions(self):
		return WordCompleter(list(opsec.MODES))

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

	async def do_bofhound_collect(self, names=None, delay='0'):
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
		print('Presets (bofhound_collect <name>[,<name>...] [delay]):')
		for name, (description, queries) in presets.PRESETS.items():
			marker = '' if name in presets.ALL else '  (not in all)'
			print('  %-11s %s%s' % (name, description, marker))
			for q in queries:
				print('  %-11s   %s  base=%s  attributes=%s' % ('', q.filter, q.base, ','.join(q.attributes)))

	def _bofhound_collect_completions(self):
		return WordCompleter(['all'] + list(presets.PRESETS))

	async def do_find_admins(self, pattern=privileged.DEFAULT_NAME_PATTERN):
		"""Lists the privileged accounts of the connected domain.

		Shows the recursive members of the protected groups (Domain/Enterprise/Schema Admins,
		Administrators, the operator groups, Key Admins, GPO creators, DnsAdmins, ...), found by
		SID so that localized group names work, together with settings that make them easier
		to attack: kerberoastable, AS-REP roastable, password never expires, unconstrained
		delegation, 'delegable' (neither "sensitive and cannot be delegated" nor in Protected
		Users), disabled. Also lists adminCount=1 users that are no longer in any of the groups
		(krbtgt is left out, it has adminCount=1 by design).

		pattern: additionally lists users, computers and groups outside the privileged groups
		whose sAMAccountName, displayName or description contains it (default: adm, which
		also matches 'admin' and 'Administrator'). Groups without members are left out.
		Use '-' to skip the name search.

		Groups of the forest root (Enterprise/Schema Admins) can only be listed on a DC of the
		forest root; on a child domain they are reported with a hint.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		report = await privileged.collect(self.connection, None if pattern == '-' else pattern)
		for line in privileged.format_report(report):
			print(line)
		return not report.errors

	async def do_templates(self, selection=None):
		"""Certificate templates in a certipy-like layout.

		templates             table of all templates: CAs, client authentication, enrollee
		                      supplies subject, manager approval, vulnerabilities
		templates <name>      details of one template (name or display name)
		templates vulnerable  details of all published templates with vulnerabilities
		templates enabled     details of all published templates

		Details show the decoded flags one per line (security relevant bits marked with [!]),
		EKUs, validity, key size and the principals of the permissions. Vulnerabilities (ESC1-4,
		ESC9) are checked for the token of the bound user; accounts bound through a trust are
		checked as low privileged users.

		LDAP queries: the bound user and its tokenGroups, the enrollment services, the templates
		(with the SD flags control); details additionally resolve the SIDs of the permissions
		that are not cached yet.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		mode = (selection or '').lower()
		name = None if mode in ('', 'vulnerable', 'enabled') else selection
		report = await templates.collect(self.connection, name)
		if report.note:
			print('Note: %s' % report.note)
		if mode == '':
			for line in templates.summary_lines(report):
				print(line)
			print('Vulnerabilities checked for %s. Details: templates <name>' % report.principal)
			return True

		selected = report.templates
		if mode == 'vulnerable':
			selected = [t for t in selected if t.enabled and t.vulns]
		elif mode == 'enabled':
			selected = [t for t in selected if t.enabled]
		if not selected:
			print('No templates found' if name else 'No matching templates')
			return name is None
		for info in selected:
			principals = await templates.resolve_principals(self.connection, info)
			for line in templates.detail_lines(info, principals, report.principal):
				print(line)
			print()
		return True

	def _templates_completions(self):
		return WordCompleter(['vulnerable', 'enabled'])
