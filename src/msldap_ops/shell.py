import asyncio
import contextlib
import os
import re
import shlex
import signal
import sys

from msldap.examples.msldapclient import MSLDAPClientConsole
from msldap.external.aiocmd.aiocmd.aiocmd import ExitPromptException
from msldap.protocol.constants import BASE, LEVEL, SUBTREE
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout

from msldap_ops import acl, hooks, navigation, opsec, presets, privileged, records, templates, ui
from msldap_ops import history as command_history


def split_redirect(args):
	"""(args, file, append) for '<command> [args] > file' and '>> file' (also '>file')."""
	for i, arg in enumerate(args):
		if not arg.startswith('>'):
			continue
		append = arg.startswith('>>')
		target = arg[2:] if append else arg[1:]
		rest = args[i + 1:]
		if target and not rest:
			return args[:i], target, append
		if not target and len(rest) == 1:
			return args[:i], rest[0], append
		raise ValueError('Usage: <command> [args] > file  (or >> file to append)')
	return args, None, False


def sd_flags_control():
	# without SD flags non-admin users get no security descriptor (the SACL needs SeSecurityPrivilege)
	flags = SDFlagsRequest.OWNER_SECURITY_INFORMATION | SDFlagsRequest.GROUP_SECURITY_INFORMATION | SDFlagsRequest.DACL_SECURITY_INFORMATION
	return ('1.2.840.113556.1.4.801', True, SDFlagsRequestValue({'Flags': flags}).dump())


# _run_line: the line was exit
EXIT = object()



class SearchWatch:
	"""Hook listener that notes whether the search of a command came from the query cache."""

	def __init__(self):
		self.cached_at = None

	def query_start(self, query):
		if not query.background:
			self.cached_at = query.cached_at if query.cached else None

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
		bindings = self._get_bindings()
		if self.history_file:
			history = command_history.PrivateFileHistory(self.history_file)
		else:
			history = InMemoryHistory()
		if command_history.fzf_available():
			command_history.add_fzf_binding(bindings, history)
		self.session = PromptSession(enable_history_search=True, key_bindings=bindings, history=history)
		try:
			with patch_stdout(raw=True):
				proxy = sys.stdout
				sys.stdout = ui.StyledStream(proxy)
				try:
					await self._run_prompt_forever()
				finally:
					sys.stdout = proxy
		finally:
			if self._ignore_sigint and sys.platform != 'win32':
				asyncio.get_event_loop().remove_signal_handler(signal.SIGINT)
			self._on_close()

	async def _run_prompt_forever(self):
		"""aiocmd's prompt loop; a pasted block of several lines runs as one command per line, a
		line that cannot be split (unclosed quote) is reported instead of ending the shell."""
		while True:
			try:
				result = await self.session.prompt_async(self.prompt, completer=self.completer)
			except EOFError:
				return
			for line in result.splitlines():
				try:
					if await self._run_line(line) is EXIT:
						return
				except asyncio.CancelledError:
					print()
					break

	async def _run_line(self, line):
		try:
			args = shlex.split(line)
		except ValueError as e:
			print('Cannot parse %r: %s' % (line, e))
			return None
		if not args:
			return None
		if args[0] not in self.command_list:
			print('Command %s not found!' % args[0])
			return None
		self._currently_running_task = asyncio.ensure_future(self._run_single_command(args[0], args[1:]))
		try:
			await self._currently_running_task
		except ExitPromptException:
			return EXIT
		return None

	def __init__(self, url=None, querylog=None, gate=None, keepalive=300, cache=None, history_file=None):
		MSLDAPClientConsole.__init__(self, url)
		self.history_file = history_file
		self.querylog = querylog
		self.cache = cache
		self.gate = gate if gate is not None else opsec.OpsecGate()
		self.keepalive = keepalive

	async def _run_single_command(self, command, args):
		try:
			args, path, append = split_redirect(args)
		except ValueError as e:
			print(e)
			return False
		if path is None:
			return await self._run_command(command, args)
		path = os.path.expanduser(path)
		try:
			f = open(path, 'a' if append else 'w', encoding='utf-8')
		except OSError as e:
			print('Cannot write %s: %s' % (path, e))
			return False
		screen = sys.stdout
		# opsec queries and questions stay on the screen, the file gets plain text
		ui.set_terminal(screen)
		try:
			with f, contextlib.redirect_stdout(f):
				res = await self._run_command(command, args)
		finally:
			ui.set_terminal(None)
		print('Output %s %s' % ('appended to' if append else 'written to', path))
		return res

	async def _run_command(self, command, args):
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
		if res is False:
			# msldap keeps the unconnected client, the other commands would fail on it
			self.connection = None
		elif self.connection is not None:
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

	async def do_ls(self, path='', full=''):
		"""Children of the current DN or of a path, like ls in a shell.

		ls [path] [full]
		  path   nothing or '.': the current DN (known from cd, no query); a DN or path as for cd;
		         a pattern in the last element: Domain*, CN=Domain*, ../OU=*
		  full   any value: full DNs instead of the names relative to the listed DN
		msldap's ls <anything> (full DNs of the current DN) works as well.
		A path is listed with the same one level search as cd (cached).
		"""
		if path and not navigation.looks_like_path(path) and '*' not in path:
			path, full = '', path  # msldap: ls <fullpath>
		split = navigation.split_pattern(path) if path else None
		parent, pattern = split if split else (path or '.', None)
		if parent == '.':
			children = self._MSLDAPClientConsole__current_dirs or {}
		else:
			if self.connection is None:
				print('Not connected, run login first')
				return False
			try:
				target = navigation.resolve(parent, self._current_dn, self._naming_contexts())
				tree = await self.connection.get_tree_plot(target, level=1)
			except ValueError as e:
				print(e)
				return False
			except Exception as e:
				print(records.search_error(e, target))
				return False
			children = {navigation.join_dn(navigation.split_dn(dn)[:-len(navigation.split_dn(target))]): dn
				for dn in tree.get(target, {})}
		shown = 0
		for name, dn in children.items():
			if pattern is None or navigation.rdn_matches(name, pattern):
				print(dn if full else name)
				shown += 1
		if pattern is not None and shown == 0:
			print('No match for %s' % pattern)
		return True

	def _ls_completions(self):
		return self._cd_completions()

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

	# --- objects --------------------------------------------------------------
	async def do_query(self, query, attributes='*', tree=None, scope='sub'):
		"""Raw LDAP search.

		query <filter> [attributes] [base] [scope]
		  attributes  comma separated, default *; nTSecurityDescriptor is requested with the
		              SD flags control, so unprivileged users get owner, group and DACL
		  base        DN or path relative to the current DN (as for cd), default: domain root;
		              '-' for the default
		  scope       base | one | sub (default)

		Every object starts with a separator line and its DN, multi-valued attributes are listed
		below each other; the number of objects is shown at the end.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		attrs = [a.strip() for a in (attributes or '*').split(',') if a.strip()] or ['*']
		scopes = {'base': BASE, 'one': LEVEL, 'sub': SUBTREE, '0': BASE, '1': LEVEL, '2': SUBTREE}
		if str(scope).lower() not in scopes:
			print('Unknown scope "%s", use base, one or sub' % scope)
			return False
		base = None
		if tree not in (None, '', '-'):
			try:
				base = navigation.resolve(tree, self._current_dn, self._naming_contexts())
			except ValueError as e:
				print(e)
				return False
		return await self._print_objects(query, attrs, base, scopes[str(scope).lower()])

	async def do_cat(self, path='', attributes=''):
		"""Attributes of objects, like cat in a shell.

		cat [path] [attributes]
		  path        '.' or nothing: the current object; '*': every child of the current DN;
		              a pattern in the last element: CN=Domain*, OU=*, ../CN=*;
		              otherwise a DN or path as for cd (CN=Users, .., ../CN=Builtin)
		  attributes  comma separated, default *; nTSecurityDescriptor is requested with the
		              SD flags control
		msldap's order (cat [attributes] [path], e.g. cat cn,description CN=Users) works as well.
		One search: base scope for an object, one level for '*' and patterns.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		path, attributes = navigation.cat_arguments([path, attributes])
		attrs = [a.strip() for a in attributes.split(',') if a.strip()] or ['*']
		glob = navigation.split_glob(path)
		try:
			target = navigation.resolve(glob[0] if glob else path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		if glob:
			return await self._print_objects(glob[1], attrs, target, LEVEL)
		return await self._print_objects('(objectClass=*)', attrs, target, BASE, count=False)

	def _cat_completions(self):
		return self._cd_completions()

	async def do_find(self, pattern, path=''):
		"""Finds objects by account name or name and prints their DNs.

		find <name|pattern> [path]
		  name     matched against sAMAccountName and name (the RDN value), case-insensitive;
		           '*' is a wildcard: jaime*, *admin*, kingslanding$
		  path     where to search (as for cd); default: the naming context of the current DN,
		           so in CN=Configuration templates and other configuration objects are found
		One subtree search. A leading '*' makes the DC scan more and stands out in its logs.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		ncs = self._naming_contexts()
		try:
			if path:
				base = navigation.resolve(path, self._current_dn, ncs)
			else:
				base = navigation.naming_context_of(self._current_dn, ncs) or self.connection._tree
		except ValueError as e:
			print(e)
			return False
		value = navigation.escape_glob(pattern)
		query = '(|(sAMAccountName=%s)(name=%s))' % (value, value)
		rows = []
		async for entry, err in self.connection.pagedsearch(query, ['objectClass', 'sAMAccountName'], tree=base):
			if err is not None:
				print(records.search_error(err, base))
				return False
			classes = entry['attributes'].get('objectClass') or []
			classes = classes if isinstance(classes, list) else [classes]
			rows.append((classes[-1] if classes else '-', entry['attributes'].get('sAMAccountName') or '-', entry['objectName']))
		rows.sort(key=lambda r: r[2].lower())
		widths = [max((len(r[i]) for r in rows), default=0) for i in range(2)]
		for kind, sam, dn in rows:
			line = '%s  %s  %s' % (kind.ljust(widths[0]), sam.ljust(widths[1]), dn)
			# where the pattern matched: the account name and the name (value of the first RDN)
			sam_at = widths[0] + 2
			dn_at = sam_at + widths[1] + 2
			first = navigation.split_dn(dn)[0] if dn else ''
			name_at = dn_at + first.find('=') + 1
			spans = [(sam_at + a, sam_at + b) for a, b in navigation.match_spans(sam, pattern) if sam != '-']
			spans += [(name_at + a, name_at + b) for a, b in navigation.match_spans(first.partition('=')[2], pattern)]
			print(ui.highlighted(line.rstrip(), spans))
		ui.out(records.count_line(len(rows)))
		return True

	def _find_completions(self):
		return WordCompleter([])

	async def do_acl(self, path='.', show='all'):
		"""Readable ACL of one object: owner, DACL with decoded rights, object types and scope.

		acl [path] [all|explicit|risky]
		  path      the object as for cd (default: the current DN)
		  explicit  only entries set on the object itself (not inherited)
		  risky     only entries that let a non-privileged principal take over the object [!]
		[!] marks full control, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, reset
		password, DCSync rights, writing member/servicePrincipalName/msDS-KeyCredentialLink/
		msDS-AllowedToActOnBehalfOfOtherIdentity and similar, adding oneself to a group, held by a
		principal outside the privileged groups; and a non-privileged owner.
		LDAP queries: the security descriptor (one base search with the SD flags control) and one
		cached search per SID that is not well-known.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		if path in acl.SCOPE_FILTERS and show == 'all':
			path, show = '.', path
		if show not in acl.SCOPE_FILTERS:
			print("Unknown filter '%s', expected one of: %s" % (show, ', '.join(acl.SCOPE_FILTERS)))
			return False
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		try:
			result = await acl.collect(self.connection, target, self.cache)
		except Exception as e:
			print(records.search_error(e, target))
			return False
		if result is None:
			print('No security descriptor returned for %s (no read access?)' % target)
			return False
		ui.emit(acl.format_acl(target, *result, show=show, width=ui.output_width()))
		return True

	def _acl_completions(self):
		return self._cd_completions()

	async def do_getsd(self, dn='.', opts=' '):
		"""msldap's getsd (raw SDDL; opts p or g: per-ACE tables), with paths as for cd.
		'acl' shows the same data decoded."""
		if self.connection is not None:
			try:
				dn = navigation.resolve(dn, self._current_dn, self._naming_contexts())
			except ValueError as e:
				print(e)
				return False
		return await MSLDAPClientConsole.do_getsd(self, dn, opts)

	def _getsd_completions(self):
		return self._cd_completions()

	async def _print_objects(self, query, attrs, base, scope, count=True):
		controls = [sd_flags_control()] if any(a.lower() == 'ntsecuritydescriptor' for a in attrs) else None
		n, error = 0, None
		search = SearchWatch()
		hooks.add_listener(search)
		try:
			async for entry, err in self.connection.pagedsearch(query, attrs, controls=controls, tree=base, search_scope=scope):
				if err is not None:
					error = err
					break
				n += 1
				# a single object (cat) gets the cache note at its DN, several at the count line
				ui.emit(records.record_lines(entry['objectName'], entry['attributes'], None if count else search.cached_at))
		finally:
			hooks.remove_listener(search)
		if error is not None:
			print(records.search_error(error, base))
			if scope == BASE and self._current_dn and navigation.is_under(base, self._current_dn) and base.lower() != self._current_dn.lower():
				print('  (relative names are resolved below the current DN, use .. or an absolute DN)')
			return False
		if count:
			ui.out(records.count_line(n, search.cached_at))
		else:
			ui.out('')
		return True
