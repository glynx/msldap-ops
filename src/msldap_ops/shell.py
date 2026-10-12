import asyncio
import contextlib
import inspect
import os
import random
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

from msldap_ops import __version__
from msldap_ops import aces, acl, changes as changelog, delegations, hooks, laps, navigation, opsec, presets, privileged, records, templates, ui
from msldap_ops import history as command_history
from msldap_ops import transcript


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

# help categories: msldap-ops commands and the most used msldap built-ins, grouped. Commands not
# listed here (the long tail of msldap built-ins) are shown under "Other" at the end. '*' marks a
# command that changes the directory.
HELP_CATEGORIES = [
	('Session', ['login', 'opsec', 'log', 'transcript', 'cache', 'changes', 'undo', 'whoami', 'help', 'exit']),
	('Navigation', ['cd', 'ls', 'cat', 'tree', 'map', 'find', 'query']),
	('Enumeration', ['bofhound_collect', 'find_admins', 'delegations', 'acl', 'getsd', 'laps',
		'groupmembership', 'trusts', 'spns', 'asrep', 'pre2000', 'gmsa']),
	('Lookup', ['sam2dn', 'sid2dn', 'dn2sid', 'dn2sam', 'sidresolv', 'user', 'machine']),
	('ADCS', ['templates', 'certtemplates', 'enrollmentservices', 'rootcas', 'ntcas', 'aiacas',
		'certify', 'certify2', 'addenrollmentright', 'addcerttemplatenameflagaltname']),
	('DNS', ['dnsquery', 'dnsqueryall', 'dnsdump', 'dnszones', 'dnssoa', 'dnsgetserial',
		'dnsadd', 'dnsremove', 'dnsdelete', 'dnsmodify', 'dnsrestore']),
	('Writing (changes the directory)', ['grant', 'revoke', 'chown', 'rbcd', 'keycred', 'setattr', 'addattr', 'delattr', 'uac',
		'addusertogroup', 'deluserfromgroup', 'adduser', 'deluser',
		'addcomputer', 'changeuserpw', 'enableuser', 'disableuser', 'unlockuser', 'addspn', 'delspn',
		'addhostname', 'changesamaccountname', 'setsd', 'changeowner', 'addprivdcsync',
		'addprivaddmember', 'add_genericwrite', 'addallowedtoactonbehalfofotheridentity', 'shadowcred',
		'modify', 'delete', 'rm']),
]
# commands that change the directory, marked with '*' in help (across all categories)
WRITING_COMMANDS = set(HELP_CATEGORIES[-1][1]) | {
	'addenrollmentright', 'addcerttemplatenameflagaltname',
	'dnsadd', 'dnsremove', 'dnsdelete', 'dnsmodify', 'dnsrestore',
}


def parse_delay(value):
	"""(low, high) seconds for the delay between queries: 'N' is fixed, 'MIN-MAX' is a random
	jitter per query. Raises ValueError on a bad value."""
	value = str(value).strip()
	if '-' in value[1:]:  # a range (not a leading minus)
		low_s, high_s = value.split('-', 1)
		low, high = float(low_s), float(high_s)
	else:
		low = high = float(value)
	if low < 0 or high < low:
		raise ValueError('bad delay range')
	return low, high


def _uac_flag(name):
	"""The MSLDAP_UAC flag for a name or hex value, or raises ValueError."""
	from msldap.ldap_objects.common import MSLDAP_UAC
	key = name.strip().upper()
	if key in MSLDAP_UAC.__members__:
		return int(MSLDAP_UAC[key])
	try:
		return int(name, 16)
	except ValueError:
		raise ValueError('Unknown userAccountControl flag %r (name or hex)' % name)


def uac_flag_names(value):
	"""Names of the flags set in a userAccountControl value."""
	from msldap.ldap_objects.common import MSLDAP_UAC
	return [flag.name for flag in MSLDAP_UAC if value & int(flag)]


def apply_uac_flags(value, changes):
	"""Applies +FLAG/-FLAG changes to a userAccountControl value."""
	for change in changes:
		if change[:1] not in ('+', '-') or len(change) < 2:
			raise ValueError('Each flag must be +NAME or -NAME, got %r' % change)
		bit = _uac_flag(change[1:])
		if change[0] == '+':
			value |= bit
		else:
			value &= ~bit
	return value


def _uac_flag_names_all():
	from msldap.ldap_objects.common import MSLDAP_UAC
	return [flag.name for flag in MSLDAP_UAC]


UAC_FLAG_NAMES = _uac_flag_names_all()


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

	def do_help(self, command=None):
		"""Lists the commands grouped by category, or shows one command in detail.

		help             commands by category (Session, Navigation, Enumeration, Lookup, Writing)
		help <command>   usage and full description of one command
		"""
		if command is not None:
			return MSLDAPClientConsole.do_help(self, command)
		commands = set(self.command_list)
		listed = set()

		def usage(name):
			text = self._get_command_usage(name, *self._get_command_args(name))
			return text + ' *' if name in WRITING_COMMANDS else text

		def first_line(name):
			return (inspect.getdoc(self._get_command(name)) or '').split('\n')[0]

		groups = []
		for title, names in HELP_CATEGORIES:
			present = [n for n in names if n in commands]
			listed.update(present)
			if present:
				groups.append((title, present))
		other = sorted(commands - listed - {'?'})
		if other:
			groups.append(('Other msldap commands', other))

		print()
		print('msldap-ops %s - commands' % __version__)
		for title, names in groups:
			# align the description column within each category
			width = max(len(usage(n)) for n in names) + 2
			print()
			print('%s:' % title)
			for name in names:
				print(('  %-' + str(width) + 's%s') % (usage(name), first_line(name)))
		print()
		print("Use 'help <command>' or '<command> -h' for details. '*' in a usage means it changes the directory.")
		return True

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
		# the stream below prompt_toolkit's proxy (set up by the CLI) must not copy to the transcript
		# again, the stream on top of the proxy does
		inner = sys.stdout if isinstance(sys.stdout, ui.StyledStream) else None
		if inner is not None:
			inner.tee = False
		try:
			with patch_stdout(raw=True):
				proxy = sys.stdout
				sys.stdout = ui.StyledStream(proxy)
				try:
					await self._run_prompt_forever()
				finally:
					sys.stdout = proxy
		finally:
			if inner is not None:
				inner.tee = True
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

	def __init__(self, url=None, querylog=None, gate=None, keepalive=300, cache=None, history_file=None, changes_log=None):
		MSLDAPClientConsole.__init__(self, url)
		self.history_file = history_file
		self.changes_log = changes_log
		self.querylog = querylog
		self.cache = cache
		self.gate = gate if gate is not None else opsec.OpsecGate()
		self.keepalive = keepalive

	async def _run_single_command(self, command, args):
		if transcript.active() is not None:
			transcript.active().command(self._current_dn, command, args)
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

	async def do_transcript(self, action=None, path=None):
		"""Writes the session to a file: every command with a timestamp and its output (plain text).

		transcript                 state and file
		transcript on [file]       start (default: ./msldap-ops-transcript_<date>.log, appended)
		transcript off             stop
		Commands with secrets (login with a password in the URL, changeuserpw, ...) are recorded
		without arguments. Output redirected with '> file' is not repeated in the transcript.
		Also --transcript [file] on the command line.
		"""
		current = transcript.active()
		if action is None:
			print('transcript: %s' % ('on, %s' % current.path if current else 'off'))
			return True
		if action == 'on':
			try:
				started = transcript.start(os.path.expanduser(path) if path else transcript.default_path())
			except OSError as e:
				print('Cannot write the transcript: %s' % e)
				return False
			print('transcript: on, %s' % started.path)
			return True
		if action == 'off':
			if current is None:
				print('transcript: off')
				return True
			path = current.path
			transcript.stop()
			print('transcript: off (written to %s)' % path)
			return True
		print("Unknown action '%s', expected on or off" % action)
		return False

	def _transcript_completions(self):
		return WordCompleter(['on', 'off'])

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
		delay: seconds between queries (default 0), or a MIN-MAX range for random jitter (e.g. 2-8).

		'all' runs every preset except 'dns', which can be large. Results are not printed,
		they go to the query log (see 'log'). All queries request *,nTSecurityDescriptor
		with the SD flags control, so unprivileged users get the DACLs as well.
		"""
		if names is None:
			self._print_presets()
			return True
		try:
			low, high = parse_delay(delay)
		except ValueError:
			print("Invalid delay '%s', expected seconds or a min-max range (e.g. 3 or 2-8)" % delay)
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
			if i > 0 and high > 0:
				await asyncio.sleep(low if low == high else random.uniform(low, high))
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

	async def do_delegations(self, kind='all'):
		"""Lists accounts configured for Kerberos delegation.

		delegations [kind]   kind: unconstrained, constrained, rbcd, or all (default)
		  unconstrained  TRUSTED_FOR_DELEGATION (domain controllers excluded)
		  constrained    msDS-AllowedToDelegateTo set (shows protocol transition vs Kerberos only)
		  rbcd           msDS-AllowedToActOnBehalfOfOtherIdentity set (who may act on the object)
		One LDAP query per kind.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		kind = (kind or 'all').lower()
		kinds = delegations.KINDS if kind == 'all' else (kind,)
		if kind != 'all' and kind not in delegations.KINDS:
			print("Unknown kind '%s', expected one of: %s, all" % (kind, ', '.join(delegations.KINDS)))
			return False
		base = self.connection._tree
		total = 0
		for k in kinds:
			query, attributes = delegations.QUERIES[k]
			rows = []
			async for entry, err in self.connection.pagedsearch(query, attributes, tree=base):
				if err is not None:
					print(records.search_error(err, base))
					return False
				rows.append(delegations.ROW[k](entry))
			total += len(rows)
			if k == 'rbcd':
				sids = sorted({s for r in rows for s in r['allowed']})
				names = await acl.resolve(self.connection, sids) if sids else {}
				ui.emit(delegations.format_rbcd(rows, names))
			else:
				ui.emit(delegations.FORMAT[k](rows))
		if total == 0:
			print('No delegation configured')
		return True

	def _delegations_completions(self):
		return WordCompleter(list(delegations.KINDS) + ['all'])

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

	async def do_laps(self, target='.'):
		"""Reads the LAPS local administrator password of a computer (both LAPS versions).

		laps                     the current object (when it is a computer); same as laps .
		laps <computer|pattern>  by sAMAccountName or name, '*' as wildcard (kingslanding$, *srv*)
		laps all                 every computer with LAPS in the domain (reads many passwords!)
		Shows the version, the password where readable (Windows LAPS encrypted blobs need an RPC
		call to the DC), and the expiration. Reading LAPS is sensitive and privileged.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		scope = SUBTREE
		if target in ('', '.'):
			# the object we are standing on, one base search
			base, query, scope = self._current_dn, laps.COMPUTER_FILTER, BASE
		elif target == 'all':
			base, query = self.connection._tree, laps.COMPUTER_FILTER
		else:
			value = navigation.escape_glob(target if target.endswith('$') or '*' in target else target + '$')
			name = navigation.escape_glob(target)
			base = self.connection._tree
			query = '(&%s(|(sAMAccountName=%s)(name=%s)))' % (laps.COMPUTER_FILTER, value, name)
		entries = []
		async for entry, err in self.connection.pagedsearch(query, laps.ATTRIBUTES, tree=base, search_scope=scope):
			if err is not None:
				print(records.search_error(err, base))
				return False
			item = laps.LapsEntry(entry)
			if item.configured:
				entries.append(item)
		if not entries:
			if target in ('', '.'):
				print('%s is not a computer with LAPS' % (self._current_dn or 'the current object'))
			elif target == 'all':
				print('No computer with LAPS found')
			else:
				print('No computer with LAPS matched %r' % target)
			return True
		for item in sorted(entries, key=lambda e: e.name.lower()):
			ui.emit(laps.format_entry(item))
		ui.out(laps.summary(entries))
		return True

	def _laps_completions(self):
		return WordCompleter(['.', 'all'])

	async def do_groupmembers(self, path='.', recursive='1'):
		"""Members of a group, like msldap's groupmembers but with paths as for cd.

		groupmembers [path] [recursive]   path: group DN or path (default: current object)
		                                  recursive 0: direct members only (default: nested too)
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		try:
			dn = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		recurse = str(recursive).lower() not in ('0', 'false', 'no')
		n = 0
		async for obj, err in self.connection.get_group_members(dn, recursive=recurse):
			if err is not None:
				print(records.search_error(err, dn))
				return False
			print(obj.distinguishedName)
			n += 1
		ui.out(records.count_line(n))
		return True

	def _groupmembers_completions(self):
		return self._cd_completions()

	async def _resolve_principal(self, principal):
		"""SID string for a principal given as a SID or an account name (sAMAccountName/name)."""
		if principal.upper().startswith('S-1-'):
			return principal.upper()
		value = navigation.escape_glob(principal)
		found = []
		async for entry, err in self.connection.pagedsearch('(|(sAMAccountName=%s)(name=%s))' % (value, value),
				['objectSid', 'sAMAccountName'], tree=self.connection._tree):
			if err is not None:
				raise err
			sid = privileged.sid_string(privileged.attr(entry, 'objectSid'))
			if sid:
				found.append((privileged.attr(entry, 'sAMAccountName') or entry['objectName'], sid))
		if not found:
			print('No principal found for %r (use a SID or an exact account name)' % principal)
			return None
		if len(found) > 1:
			print('%r is ambiguous:' % principal)
			for name, sid in found:
				print('  %s  %s' % (sid, name))
			return None
		return found[0][1]

	async def _read_sd(self, dn):
		"""The security descriptor bytes of an object (owner, group, DACL), or None."""
		async for entry, err in self.connection.pagedsearch('(objectClass=*)', ['nTSecurityDescriptor'],
				controls=[sd_flags_control()], tree=dn, search_scope=BASE):
			if err is not None:
				print(records.search_error(err, dn))
				return None
			sd = entry['attributes'].get('nTSecurityDescriptor')
			if sd is None:
				print('No security descriptor returned for %s (no read access?)' % dn)
				return None
			return sd.to_bytes() if hasattr(sd, 'to_bytes') else sd
		print('%s not found' % dn)
		return None

	async def _grant_revoke(self, action, principal, right, path):
		if self.connection is None:
			print('Not connected, run login first')
			return False
		if right.lower() not in aces.RIGHTS:
			print("Unknown right '%s'. Known: %s" % (right, ', '.join(aces.RIGHT_NAMES)))
			return False
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		sid = await self._resolve_principal(principal)
		if sid is None:
			return False
		sd_bytes = await self._read_sd(target)
		if sd_bytes is None:
			return False
		new_bytes, changed = (aces.grant if action == 'grant' else aces.revoke)(sd_bytes, sid, right)
		if changed == 0:
			print('Nothing to %s: %s %s for %s is %s' % (action, right, 'on', target,
				'already present' if action == 'grant' else 'not present'))
			return True
		# write back only the DACL, so WriteDacl alone is enough (writing owner/group would need
		# WriteOwner and the DC rejects it with constraintViolation); routes through the wrapped
		# connection.modify, so opsec and undo apply
		from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest
		verb = 'grant' if action == 'grant' else 'revoke'
		label = '%s %s for %s on %s (%d ACE%s)' % (verb, right, sid, target, changed, '' if changed == 1 else 's')
		with hooks.labeled(label):
			ok, err = await self.connection.set_objectacl_by_dn(target, new_bytes, flags=SDFlagsRequest.DACL_SECURITY_INFORMATION)
		if err is not None:
			print('%s failed: %s' % (action, err))
			return False
		print('%s: %s %s %s on %s (%d ACE%s)' % (verb, right, 'for' if action == 'grant' else 'revoked from',
			sid, target, changed, '' if changed == 1 else 's'))
		return bool(ok)

	async def _modify(self, path, changes, description):
		"""Resolves the path, sends one modify and reports the outcome; the change is gated and
		undoable through the hook."""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		ok, err = await self.connection.modify(target, changes)
		if err is not None:
			print('%s failed: %s' % (description, err))
			return False
		print('%s on %s' % (description, target))
		return bool(ok)

	async def do_setattr(self, path, attribute, *values):
		"""Replaces an attribute's value(s) (no value clears it).

		setattr <path> <attribute> [value ...]
		Writes the values as given; attributes with a non-string syntax may be rejected by the
		server. Undoable.
		"""
		return await self._modify(path, {attribute: [('replace', list(values))]},
			'setattr %s=%s' % (attribute, ', '.join(values) if values else '(cleared)'))

	async def do_addattr(self, path, attribute, value):
		"""Adds one value to a multi-valued attribute. addattr <path> <attribute> <value>  Undoable."""
		return await self._modify(path, {attribute: [('add', [value])]}, 'addattr %s+=%s' % (attribute, value))

	async def do_delattr(self, path, attribute, value):
		"""Removes one value from a multi-valued attribute. delattr <path> <attribute> <value>  Undoable."""
		return await self._modify(path, {attribute: [('delete', [value])]}, 'delattr %s-=%s' % (attribute, value))

	def _setattr_completions(self):
		return navigation.PositionalCompleter([self._cd_completions()])

	_addattr_completions = _setattr_completions
	_delattr_completions = _setattr_completions

	async def do_uac(self, path='.', *flags):
		"""Shows or changes the userAccountControl flags of an object.

		uac [path]                 shows the flags that are set
		uac <path> +FLAG -FLAG     sets (+) or clears (-) flags, e.g. +DONT_REQUIRE_PREAUTH,
		                           +TRUSTED_FOR_DELEGATION, -ACCOUNTDISABLE
		Flag names are those of userAccountControl (case-insensitive); a hex value also works.
		Changing the flags is undoable.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		current = None
		async for entry, err in self.connection.pagedsearch('(objectClass=*)', ['userAccountControl'],
				tree=target, search_scope=BASE):
			if err is not None:
				print(records.search_error(err, target))
				return False
			current = entry['attributes'].get('userAccountControl')
		if current is None:
			print('%s has no userAccountControl' % target)
			return False
		current = int(current)
		if not flags:
			print('userAccountControl of %s: 0x%x' % (target, current))
			ui.emit(['  ' + name for name in uac_flag_names(current)] or ['  (no flags)'])
			return True
		try:
			new = apply_uac_flags(current, flags)
		except ValueError as e:
			print(e)
			return False
		if new == current:
			print('userAccountControl unchanged (0x%x)' % current)
			return True
		ok, err = await self.connection.modify(target, {'userAccountControl': [('replace', new)]})
		if err is not None:
			print('uac failed: %s' % err)
			return False
		print('uac on %s: 0x%x -> 0x%x' % (target, current, new))
		return bool(ok)

	def _uac_completions(self):
		signed = ['+%s' % n for n in UAC_FLAG_NAMES] + ['-%s' % n for n in UAC_FLAG_NAMES]
		return navigation.PositionalCompleter([self._cd_completions(), WordCompleter(signed)])

	async def do_grant(self, principal, right, path='.'):
		"""Grants a right on an object to a principal by adding an ACE to its DACL.

		grant <principal> <right> [path]
		  principal  a SID or an exact account name (sAMAccountName/name)
		  right      fullcontrol, genericwrite, writedacl, writeowner, resetpassword, dcsync,
		             writemembers, writespn, writekeycredential, rbcd, allextendedrights
		  path       the object (as for cd, default: the current object)
		Reads the security descriptor, adds the ACE(s) and writes it back; 'undo' restores it.
		"""
		return await self._grant_revoke('grant', principal, right, path)

	async def do_revoke(self, principal, right, path='.'):
		"""Removes a right granted to a principal on an object (the allow ACEs matching it).

		revoke <principal> <right> [path]   see 'help grant' for the arguments and rights
		"""
		return await self._grant_revoke('revoke', principal, right, path)

	def _grant_completions(self):
		# principal (no suggestions), then the right, then the target path
		return navigation.PositionalCompleter([None, WordCompleter(aces.RIGHT_NAMES), self._cd_completions()])

	def _revoke_completions(self):
		return self._grant_completions()

	async def do_chown(self, path, principal):
		"""Changes the owner of an object's security descriptor to a principal.

		chown <path> <principal>   principal: a SID or an exact account name
		Owning an object lets you rewrite its DACL. Needs WriteOwner (or the SeRestore right).
		Undoable (the owner is restored).
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		sid = await self._resolve_principal(principal)
		if sid is None:
			return False
		with hooks.labeled('chown %s to %s' % (target, sid)):
			ok, err = await self.connection.change_priv_owner(sid, target)
		if err is not None:
			print('chown failed: %s' % err)
			return False
		print('chown: owner of %s set to %s' % (target, sid))
		return bool(ok)

	def _chown_completions(self):
		return navigation.PositionalCompleter([self._cd_completions()])

	async def do_rbcd(self, path='.', action=None, principal=None):
		"""Resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity).

		rbcd [path]                  lists the principals allowed to act on behalf of the object
		rbcd <path> add <principal>  allows a principal (SID or account name)
		rbcd <path> clear            removes the attribute (revokes all RBCD)
		Changes are undoable.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		sd = None
		async for entry, err in self.connection.pagedsearch('(objectClass=*)',
				['msDS-AllowedToActOnBehalfOfOtherIdentity'], tree=target, search_scope=BASE):
			if err is not None:
				print(records.search_error(err, target))
				return False
			sd = entry['attributes'].get('msDS-AllowedToActOnBehalfOfOtherIdentity')
		if action is None:
			sids = [str(ace.Sid) for ace in sd.Dacl.aces] if sd is not None and sd.Dacl else []
			if not sids:
				print('%s: no RBCD configured' % target)
				return True
			names = await acl.resolve(self.connection, sids)
			print('RBCD on %s - allowed to act on its behalf:' % target)
			ui.emit(['  %s  (%s)' % (names.get(s, s), s) for s in sids])
			return True
		if action == 'clear':
			with hooks.labeled('rbcd clear on %s' % target):
				ok, err = await self.connection.modify(target, {'msDS-AllowedToActOnBehalfOfOtherIdentity': [('replace', [])]})
			return self._report(err, ok, 'rbcd clear on %s' % target)
		if action == 'add':
			if not principal:
				print('Usage: rbcd <path> add <principal>')
				return False
			sid = await self._resolve_principal(principal)
			if sid is None:
				return False
			new_bytes = aces.rbcd_with(sd.to_bytes() if sd is not None else None, sid)
			with hooks.labeled('rbcd add %s on %s' % (sid, target)):
				ok, err = await self.connection.modify(target, {'msDS-AllowedToActOnBehalfOfOtherIdentity': [('replace', new_bytes)]})
			return self._report(err, ok, 'rbcd add %s on %s' % (sid, target))
		print("Unknown action '%s', expected add or clear" % action)
		return False

	def _rbcd_completions(self):
		return navigation.PositionalCompleter([self._cd_completions(), WordCompleter(['add', 'clear'])])

	async def do_keycred(self, path='.', action=None):
		"""Key credentials (msDS-KeyCredentialLink), used for shadow-credentials attacks.

		keycred [path]        lists the key credentials on the object
		keycred <path> clear  removes all of them
		Adding one is msldap's 'shadowcred'. Clearing is undoable.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		try:
			target = navigation.resolve(path, self._current_dn, self._naming_contexts())
		except ValueError as e:
			print(e)
			return False
		values = None
		async for entry, err in self.connection.pagedsearch('(objectClass=*)', ['msDS-KeyCredentialLink'],
				tree=target, search_scope=BASE):
			if err is not None:
				print(records.search_error(err, target))
				return False
			values = entry['attributes'].get('msDS-KeyCredentialLink')
		values = values if isinstance(values, list) else ([values] if values else [])
		if action is None:
			if not values:
				print('%s: no key credentials' % target)
				return True
			print('%s: %d key credential%s' % (target, len(values), '' if len(values) == 1 else 's'))
			ui.emit(['  %s' % (v if len(str(v)) <= 80 else str(v)[:80] + '...') for v in values])
			return True
		if action == 'clear':
			with hooks.labeled('keycred clear on %s' % target):
				ok, err = await self.connection.modify(target, {'msDS-KeyCredentialLink': [('replace', [])]})
			return self._report(err, ok, 'keycred clear on %s' % target)
		print("Unknown action '%s', expected clear" % action)
		return False

	def _keycred_completions(self):
		return navigation.PositionalCompleter([self._cd_completions(), WordCompleter(['clear'])])

	def _report(self, err, ok, description):
		if err is not None:
			print('%s failed: %s' % (description.split(' on ')[0], err))
			return False
		print(description)
		return bool(ok)

	async def do_changes(self):
		"""Lists the directory changes made in this session and whether they can be undone.

		changes          every add/modify/delete, newest last, with an index for undo
		Use 'undo' to reverse the last undoable change, or 'undo <n>' for change #n.
		"""
		log = self.changes_log
		if log is None or not len(log):
			print('No changes in this session')
			return True
		width = len(str(len(log)))
		for i, change in enumerate(log.changes, 1):
			state = 'undoable' if change.undoable else 'no undo: %s' % change.reason
			print('%s  %s  %s  [%s]' % (str(i).rjust(width), change.when.strftime('%H:%M:%S'), change.summary, state))
		print("'undo' reverses the last undoable change, 'undo <n>' change #n (then it drops from this list)")
		return True

	async def do_undo(self, which=None):
		"""Reverses a directory change made in this session.

		undo        the last change that can be undone
		undo <n>    change number #n (see 'changes')
		The undo is itself an LDAP change: opsec shows/confirms it and it is recorded.
		"""
		if self.connection is None:
			print('Not connected, run login first')
			return False
		log = self.changes_log
		if log is None or not len(log):
			print('No changes to undo')
			return True
		if which is None:
			change = log.last_undoable()
			if change is None:
				print('No change that can be undone')
				return True
		else:
			try:
				change = log.changes[int(which) - 1]
			except (ValueError, IndexError):
				print('No change #%s (see changes)' % which)
				return False
			if not change.undoable:
				print('Change #%s cannot be undone: %s' % (which, change.reason))
				return False
		print('Undoing: %s' % change.summary)
		ok, err = await log.undo(self.connection, change)
		if err is not None:
			print('Undo failed: %s' % err)
			return False
		print('Undone' if ok else 'Undo was not applied')
		return bool(ok)

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
