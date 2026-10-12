import argparse
import asyncio
import logging
import os
import shlex
import sys

from asyauth import logger as authlogger
from asysocks import logger as sockslogger
from msldap import logger as msldaplogger

from msldap_ops import __version__, changes, hooks, transcript, ui
from msldap_ops.cache import DEFAULT_CACHE_DIR, DEFAULT_TTL, QueryCache
from msldap_ops.history import default_path as default_history_path
from msldap_ops.opsec import OpsecGate
from msldap_ops.querylog import DEFAULT_LOG_DIR, QueryLog
from msldap_ops.shell import MSLDAPOpsConsole
from msldap_ops.transcript import DEFAULT_PREFIX as TRANSCRIPT_PREFIX
from msldap_ops.transcript import default_path as default_transcript_path


async def amain(args):
	if args.no_color:
		ui.set_enabled(False)
	# colors (if enabled) and the session transcript
	sys.stdout = ui.StyledStream(sys.stdout)
	if args.transcript:
		transcript.start(args.transcript)
	hooks.install()
	querylog = None
	if not args.no_log:
		querylog = QueryLog(args.log_dir)
		hooks.add_listener(querylog)
	cache = None
	if not args.no_cache:
		cache = QueryCache(args.cache_dir, ttl=args.cache_ttl, persist=not args.cache_memory_only)
		hooks.set_cache(cache)
		hooks.add_listener(cache)
	gate = OpsecGate(args.opsec)
	hooks.set_gate(gate)
	changelog = changes.ChangeLog()
	hooks.add_listener(changelog)
	# from here on the console tracks which task runs a command
	hooks.set_foreground(None)
	console = MSLDAPOpsConsole(args.url, querylog=querylog, gate=gate, keepalive=args.keepalive, cache=cache,
		history_file=None if args.no_history else os.path.expanduser(args.history_file),
		changes_log=changelog, ntlm_bind=args.ntlm_bind,
		no_signing=args.no_signing, no_channel_binding=args.no_channel_binding)
	if len(args.commands) == 0:
		res = await console._run_single_command('login', [])
		if res is False:
			return 1
		await console.run()
		return 0

	# same semantics as msldap: run the commands in order, 'i' drops into the shell
	for command in args.commands:
		if command == 'i':
			await console.run()
			return 0
		cmd = shlex.split(command)
		res = await console._run_single_command(cmd[0], cmd[1:])
		if res is False:
			return 1
	return 0


def main():
	parser = argparse.ArgumentParser(
		description='msldap-ops %s - operator toolkit on top of msldap' % __version__,
		epilog='The URL format is the same as for msldap, e.g. ldap+ntlm-password://DOMAIN\\user:pass@10.0.0.1',
	)
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('--ntlm-bind', choices=['sasl', 'sicily'],
		help='Override NTLM bind framing: sasl (GSS-SPNEGO) or sicily (e.g. ntlmrelayx LDAP SOCKS). Default: authentication mode from URL')
	parser.add_argument('--no-signing', action='store_true',
		help='Disable NTLM/Kerberos signing and sealing on LDAP. LDAPS already uses TLS instead')
	parser.add_argument('--no-channel-binding', action='store_true',
		help='Disable TLS channel binding on LDAPS; has no effect on plain LDAP')
	parser.add_argument('--log-dir', default=DEFAULT_LOG_DIR, help='Directory for the bofhound compatible query log, relative to the current directory. Default: %(default)s')
	parser.add_argument('--no-log', action='store_true', help='Do not log search results')
	parser.add_argument('--opsec', choices=['off', 'show', 'confirm', 'confirm-write'], default='off', help="Show or confirm LDAP operations; confirm-write asks only for changes (see 'help opsec'). Default: %(default)s")
	parser.add_argument('--keepalive', type=int, default=300, metavar='SECONDS', help='Interval of the keepalive search on the domain object, 0 disables it (msldap: 10). Default: %(default)s')
	parser.add_argument('--cache-dir', default=DEFAULT_CACHE_DIR, help='Project directory for query caches and retained identities. Default: %(default)s')
	parser.add_argument('--cache-ttl', type=int, default=DEFAULT_TTL, metavar='SECONDS', help='How long cached search results are reused. Default: %(default)s')
	parser.add_argument('--cache-memory-only', action='store_true', help='Keep queries and identities in memory; do not read or write cache files')
	parser.add_argument('--no-cache', action='store_true', help='Disable query caching and retained identity lookups')
	parser.add_argument('--history-file', default=default_history_path(), help='Command history across sessions. Default: %(default)s')
	parser.add_argument('--no-history', action='store_true', help='Keep the command history for this session only')
	parser.add_argument('--transcript', nargs='?', const=default_transcript_path(), metavar='FILE',
		help='Write the session (commands and output) to FILE. Default file: ./%s_<date>.log' % TRANSCRIPT_PREFIX)
	parser.add_argument('--no-color', action='store_true', help='Plain output without colors (also: NO_COLOR environment variable)')
	parser.add_argument('url', help='Connection string in msldap URL format')
	parser.add_argument('commands', nargs='*', help="Commands to run in order. 'i' drops into the interactive shell. Without commands the shell starts after login.")
	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		for lg in (msldaplogger, authlogger, sockslogger):
			lg.setLevel(logging.DEBUG)
		logging.basicConfig(level=logging.DEBUG)

	try:
		code = asyncio.run(amain(args))
	finally:
		transcript.stop()
	raise SystemExit(code)


if __name__ == '__main__':
	main()
