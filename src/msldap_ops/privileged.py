"""Privileged accounts: recursive members of the protected groups and their risky settings.

Groups are looked up by SID (domain SID + RID, or builtin SID), not by name, so localized
installations ("Domänen-Admins") work as well.
"""

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# (name, SID template); {domain} is the SID of the connected domain, {root} the forest root's
PRIVILEGED_GROUPS = [
	('Domain Admins', '{domain}-512'),
	('Enterprise Admins', '{root}-519'),
	('Schema Admins', '{root}-518'),
	('Enterprise Key Admins', '{root}-527'),
	('Administrators', 'S-1-5-32-544'),
	('Account Operators', 'S-1-5-32-548'),
	('Server Operators', 'S-1-5-32-549'),
	('Print Operators', 'S-1-5-32-550'),
	('Backup Operators', 'S-1-5-32-551'),
	('Key Admins', '{domain}-526'),
	('Group Policy Creator Owners', '{domain}-520'),
	('Domain Controllers', '{domain}-516'),
]
# no well-known RID, looked up by name
NAMED_GROUPS = ['DnsAdmins']
PROTECTED_USERS = '{domain}-525'

USER_ATTRIBUTES = [
	'sAMAccountName', 'distinguishedName', 'objectSid', 'objectClass', 'sAMAccountType',
	'userAccountControl', 'adminCount', 'servicePrincipalName', 'pwdLastSet', 'lastLogonTimestamp',
]
GROUP_ATTRIBUTES = ['sAMAccountName', 'distinguishedName', 'objectSid', 'member']

IN_CHAIN = '1.2.840.113556.1.4.1941'

UAC_ACCOUNTDISABLE = 0x2
UAC_PASSWD_NOTREQD = 0x20
UAC_SERVER_TRUST_ACCOUNT = 0x2000
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_DONT_REQ_PREAUTH = 0x400000

SAM_USER = 805306368


def attr(entry, name, default=None):
	"""Case-insensitive attribute access on an msldap search result."""
	attributes = entry.get('attributes', {})
	if name in attributes:
		return attributes[name]
	lname = name.lower()
	for key, value in attributes.items():
		if key.lower() == lname:
			return value
	return default


def as_list(value):
	if value is None:
		return []
	if isinstance(value, (list, tuple)):
		return list(value)
	return [value]


@dataclass
class Account:
	dn: str
	name: str
	sid: str
	kind: str
	uac: int
	admincount: bool
	spns: List[str]
	pwdlastset: Optional[datetime.datetime]
	lastlogon: Optional[datetime.datetime]
	groups: Dict[str, str] = field(default_factory=dict)  # group name -> 'direct' | 'nested'
	protected_user: bool = False

	@classmethod
	def from_entry(cls, entry):
		classes = [c.lower() for c in as_list(attr(entry, 'objectClass'))]
		if 'computer' in classes:
			kind = 'computer'
		elif 'group' in classes:
			kind = 'group'
		else:
			kind = 'user'
		return cls(
			dn=attr(entry, 'distinguishedName') or entry.get('objectName'),
			name=attr(entry, 'sAMAccountName') or entry.get('objectName'),
			sid=str(attr(entry, 'objectSid', '')),
			kind=kind,
			uac=int(attr(entry, 'userAccountControl', 0) or 0),
			admincount=int(attr(entry, 'adminCount', 0) or 0) == 1,
			spns=as_list(attr(entry, 'servicePrincipalName')),
			pwdlastset=_date(attr(entry, 'pwdLastSet')),
			lastlogon=_date(attr(entry, 'lastLogonTimestamp')),
		)

	@property
	def enabled(self):
		return not self.uac & UAC_ACCOUNTDISABLE

	def findings(self):
		"""Settings that make a privileged account easier to attack."""
		if self.kind == 'group':
			return []
		dc = bool(self.uac & UAC_SERVER_TRUST_ACCOUNT)
		result = []
		if not self.enabled:
			result.append('disabled')
		if self.spns and self.kind == 'user':
			result.append('kerberoastable')
		if self.uac & UAC_DONT_REQ_PREAUTH:
			result.append('asrep-roastable')
		if self.uac & UAC_PASSWD_NOTREQD:
			result.append('password-not-required')
		if self.uac & UAC_DONT_EXPIRE_PASSWORD:
			result.append('password-never-expires')
		if self.uac & UAC_TRUSTED_FOR_DELEGATION and not dc:
			result.append('unconstrained-delegation')
		if self.kind == 'user' and not self.uac & UAC_NOT_DELEGATED and not self.protected_user:
			result.append('delegable')
		return result


def _date(value):
	if isinstance(value, datetime.datetime) and value.year > 1601:
		return value
	return None


@dataclass
class GroupResult:
	name: str
	sid: str
	dn: Optional[str] = None
	members: List[Account] = field(default_factory=list)
	foreign: List[str] = field(default_factory=list)  # direct members outside the connected domain
	note: Optional[str] = None


@dataclass
class Report:
	domain_dn: str
	groups: List[GroupResult]
	accounts: Dict[str, Account]  # by DN
	orphaned: List[Account]  # adminCount=1 but not in any privileged group
	errors: List[str] = field(default_factory=list)


def group_sids(domain_sid, root_sid):
	result = []
	for name, template in PRIVILEGED_GROUPS:
		if '{root}' in template and root_sid is None:
			result.append((name, None))
			continue
		result.append((name, template.format(domain=domain_sid, root=root_sid)))
	return result


async def _search(client, query, attributes, errors, tree=None):
	results = []
	async for entry, err in client.pagedsearch(query, attributes, tree=tree):
		if err is not None:
			errors.append('%s: %s' % (query, err))
			break
		results.append(entry)
	return results


async def _root_domain_sid(client, errors):
	"""SID of the forest root domain: the connected domain itself or a trustedDomain object."""
	info = client._serverinfo or {}
	domain_dn = info.get('defaultNamingContext') or client._tree
	root_dn = info.get('rootDomainNamingContext') or domain_dn
	if root_dn.lower() == domain_dn.lower():
		return client.domainsid, None
	root_dns = root_dn.replace('DC=', '').replace('dc=', '').replace(',', '.')
	trusts = await _search(client, '(&(objectClass=trustedDomain)(trustPartner=%s))' % root_dns, ['securityIdentifier', 'flatName'], errors)
	for trust in trusts:
		sid = attr(trust, 'securityIdentifier')
		if sid:
			return str(sid), root_dns
	return None, root_dns


async def collect(client):
	"""Gathers the privileged group memberships of the connected domain."""
	errors = []
	info = client._serverinfo or {}
	domain_dn = info.get('defaultNamingContext') or client._tree
	domain_sid = client.domainsid
	root_sid, root_dns = await _root_domain_sid(client, errors)
	root_is_remote = root_dns is not None

	accounts = {}

	def account_for(entry):
		account = Account.from_entry(entry)
		return accounts.setdefault(account.dn.lower(), account)

	protected = set()
	for entry in await _search(client, '(objectSid=%s)' % PROTECTED_USERS.format(domain=domain_sid), ['distinguishedName'], errors):
		pu_dn = attr(entry, 'distinguishedName') or entry['objectName']
		for member in await _search(client, '(memberOf:%s:=%s)' % (IN_CHAIN, pu_dn), ['objectSid'], errors):
			protected.add(str(attr(member, 'objectSid', '')))

	lookups = [(name, sid, '(objectSid=%s)' % sid if sid else None) for name, sid in group_sids(domain_sid, root_sid)]
	lookups += [(name, None, '(&(objectCategory=group)(sAMAccountName=%s))' % name) for name in NAMED_GROUPS]

	groups = []
	for name, sid, query in lookups:
		result = GroupResult(name, sid or '')
		groups.append(result)
		if query is None:
			result.note = 'forest root SID unknown'
			continue
		found = await _search(client, query, GROUP_ATTRIBUTES, errors)
		if not found:
			if root_is_remote and sid and root_sid and sid.startswith(root_sid + '-'):
				result.note = 'lives in the forest root %s, connect to its DC to list the members' % root_dns
			else:
				result.note = 'not found'
			continue
		group = found[0]
		result.dn = attr(group, 'distinguishedName') or group['objectName']
		result.name = attr(group, 'sAMAccountName') or name
		result.sid = str(attr(group, 'objectSid', sid or ''))
		direct = {m.lower() for m in as_list(attr(group, 'member'))}
		result.foreign = sorted(m for m in as_list(attr(group, 'member')) if _is_foreign(m, domain_dn))

		for entry in await _search(client, '(memberOf:%s:=%s)' % (IN_CHAIN, result.dn), USER_ATTRIBUTES, errors):
			account = account_for(entry)
			account.protected_user = account.sid in protected
			account.groups[result.name] = 'direct' if account.dn.lower() in direct else 'nested'
			result.members.append(account)

	orphaned = []
	for entry in await _search(client, '(&(adminCount=1)(sAMAccountType=%d))' % SAM_USER, USER_ATTRIBUTES, errors):
		account = Account.from_entry(entry)
		if account.dn.lower() not in accounts:
			account.protected_user = account.sid in protected
			orphaned.append(account)

	return Report(domain_dn, groups, accounts, orphaned, errors)


def _is_foreign(dn, domain_dn):
	ldn = dn.lower()
	return 'cn=foreignsecurityprincipals,' in ldn or not ldn.endswith(domain_dn.lower())


def _when(value):
	return value.strftime('%Y-%m-%d') if value else 'never'


def format_report(report):
	lines = ['Privileged groups in %s' % report.domain_dn]
	for group in report.groups:
		header = '  %s' % group.name
		if group.sid:
			header += ' (%s)' % group.sid
		if group.note:
			lines.append('%s: %s' % (header, group.note))
			continue
		members = [m for m in group.members if m.kind != 'group']
		lines.append('%s: %d accounts' % (header, len(members)))
		for member in sorted(group.members, key=lambda m: (m.kind == 'group', m.name.lower())):
			lines.append('    %-24s %-8s %-6s %s' % (member.name, member.kind, member.groups[group.name], ', '.join(member.findings())))
		for dn in group.foreign:
			lines.append('    %-24s %-8s %-6s %s' % ('(other domain)', '', 'direct', dn))

	people = sorted((a for a in report.accounts.values() if a.kind != 'group'), key=lambda a: a.name.lower())
	lines.append('')
	lines.append('Privileged accounts: %d' % len(people))
	for account in people:
		lines.append('  %-24s %-8s pwdLastSet %-10s lastLogon %-10s %s' % (
			account.name, account.kind, _when(account.pwdlastset), _when(account.lastlogon), ', '.join(account.findings())))
		lines.append('    in: %s' % ', '.join(sorted(account.groups)))

	lines.append('')
	lines.append('adminCount=1 users outside the privileged groups: %d' % len(report.orphaned))
	for account in sorted(report.orphaned, key=lambda a: a.name.lower()):
		lines.append('  %-24s %s' % (account.name, ', '.join(account.findings())))

	if report.errors:
		lines.append('')
		lines.append('Errors:')
		lines.extend('  %s' % e for e in report.errors)
	return lines
