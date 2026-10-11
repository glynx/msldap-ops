import asyncio
import re
import signal
import sys

from msldap.examples.msldapclient import MSLDAPClientConsole
from msldap.protocol.constants import SUBTREE
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

from msldap_ops import hooks, navigation, opsec, presets, privileged, templates, ui


def sd_flags_control():
	# without SD flags non-admin users get no security descriptor (the SACL needs SeSecurityPrivilege)
	flags = SDFlagsRequest.OWNER_SECURITY_INFORMATION | SDFlagsRequest.GROUP_SECURITY_INFORMATION | SDFlagsRequest.DACL_SECURITY_INFORMATION
	return ('1.2.840.113556.1.4.801', True, SDFlagsRequestValue({'Flags': flags}).dump())


class MSLDAPOpsConsole(MSLDAPClientConsole):
	"""msldap shell with additional msldap-ops commands. All msldap commands remain available."""

	_prompt_dn = ''

	@property
	def prompt(self):
		return ui.prompt(self._prompt_dn)

	@prompt.setter
	def prompt(self, value):
		# msldap sets '[<DN>]> ' in several places
		m = re.match(r'^\[(.*)\]> $', value or '')
		self._prompt_dn = m.group(1) if m else (value or '').strip().rstrip('>').strip()

	async def run(self):
		"""aiocmd's run(), with patch_stdout(raw=True) so that colors reach the terminal."""
		if self._ignore_sigint and sys.platform != 'win32':
			asyncio.get_event_loop().add_signal_handler(signal.SIGINT, self._sigint_handler)
		self.session = PromptSession(enable_history_search=True, key_bindings=self._get_bindings())
		try:
			with patch_stdout(raw=True):
				await self._run_prompt_forever()
		finally:
			if self._ignore_sigint and sys.platform != 'win32':
				asyncio.get_event_loop().remove_signal_handler(signal.SIGINT)
			self._on_close()

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
			ui.emit(privileged.table(rows, 2))
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
			ui.out('WARNING: query logging is off, the results are not saved')

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
				ui.out('  %s  %5d  error: %s' % (name, count, err))
			else:
				ui.out('  %s  %5d' % (name, count))

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
		ui.emit(privileged.format_report(report))
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
			ui.out('Note: %s' % report.note)
		if mode == '':
			ui.emit(templates.summary_lines(report))
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
			ui.emit(templates.detail_lines(info, principals, report.principal))
			print()
		return True

	def _templates_completions(self):
		return WordCompleter(['vulnerable', 'enabled'])

	# --- navigation ---------------------------------------------------------
	def _naming_contexts(self):
		info = getattr(self.connection, '_serverinfo', None) or {}
		ncs = info.get('namingContexts') or []
		return [ncs] if isinstance(ncs, str) else list(ncs)

	def _known_dns(self):
		if self.cache is None:
			return []
		return [value[0] for value in self.cache.dns.values()]

	async def do_cd(self, path):
		"""Changes the current DN.

		cd ..                  parent (not above the naming context of this DC)
		cd ../..               two levels up
		cd CN=Computers        relative to the current DN, also deeper: OU=Servers,OU=Tier0
		cd <DN>                absolute, e.g. CN=Configuration,DC=... (any naming context of the DC)

		Escaped commas in DNs (CN=Doe\\, John) are handled. Completion offers the children of the
		current DN, every DN below it seen so far (query cache) and the naming contexts.
		Lists the children of the new DN with one LDAP search (cached).
		"""
		if self.connection is None:
			return await MSLDAPClientConsole.do_cd(self, path)
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		return await MSLDAPClientConsole.do_cd(self, target)

	def _cd_completions(self):
		return navigation.DNCompleter(
			get_current=lambda: self._current_dn,
			get_known_dns=self._known_dns,
			get_naming_contexts=self._naming_contexts,
			get_children=lambda: [d.strip("'") for d in self.get_current_dirs()],
		)

	async def do_tree(self, dn=None, level=1):
		"""Tree below a DN, queried live from the DC (default: the domain root, 1 level).

		Sends one one-level search per container down to the given level; on the domain root,
		level 3 means a search for every container of the first two levels. Repeated calls are
		answered from the query cache, and everything found also shows up in 'map'.
		To see what is already known without asking the DC, use 'map'.
		"""
		return await MSLDAPClientConsole.do_tree(self, dn, level)

	async def do_map(self, dn=None, depth='3'):
		"""Tree of the DNs seen so far below a DN, without asking the DC (default: current DN).

		map                    below the current DN, 3 levels
		map <DN|path> [depth]  below another DN (relative paths and .. as for cd), depth 0 = all

		Sends no LDAP query: it draws what the query cache has seen (every result of every
		command), so it grows while you work and may be incomplete. Nodes cut off by the depth
		show (+n) children. To explore the current structure live, use 'tree <DN> <level>'.
		"""
		if self.connection is None or self._current_dn is None:
			print('Not connected, run login first')
			return False
		if self.cache is None:
			print('The DN index is part of the query cache, which is disabled (--no-cache)')
			return False
		try:
			depth = int(depth)
		except ValueError:
			print("Invalid depth '%s'" % depth)
			return False
		try:
			root = navigation.resolve(dn, self._current_dn, self._naming_contexts()) if dn else self._current_dn
		except ValueError as e:
			print(e)
			return False
		lines = navigation.tree_lines(self._known_dns(), root, depth or None)
		ui.emit(lines)
		if len(lines) == 1:
			print("(nothing seen below this DN yet; 'tree' asks the DC)")
		else:
			print("(known from the cache, may be incomplete; 'tree' asks the DC)")
		return True

	def _map_completions(self):
		return self._cd_completions()
