import argparse
import asyncio
import logging
import shlex

from asyauth import logger as authlogger
from asysocks import logger as sockslogger
from msldap import logger as msldaplogger

from msldap_ops import __version__
from msldap_ops.shell import MSLDAPOpsConsole


async def amain(args):
	console = MSLDAPOpsConsole(args.url)
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
	parser.add_argument('url', help='Connection string in msldap URL format')
	parser.add_argument('commands', nargs='*', help="Commands to run in order. 'i' drops into the interactive shell. Without commands the shell starts after login.")
	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		for lg in (msldaplogger, authlogger, sockslogger):
			lg.setLevel(logging.DEBUG)
		logging.basicConfig(level=logging.DEBUG)

	raise SystemExit(asyncio.run(amain(args)))


if __name__ == '__main__':
	main()
