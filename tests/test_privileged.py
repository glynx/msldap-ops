import datetime
import re

from winacl.dtyp.sid import SID

from msldap_ops import privileged
from msldap_ops.shell import MSLDAPOpsConsole

DOM = 'S-1-5-21-1-2-3'
ROOT = 'S-1-5-21-9-9-9'
BASE = 'DC=north,DC=sevenkingdoms,DC=local'


def obj(dn, **attrs):
	attrs.setdefault('distinguishedName', dn)
	if dn.startswith(('CN=Domain Admins', 'CN=Administrators', 'CN=Domain Controllers,CN=Users', 'CN=Protected Users')):
		attrs.setdefault('objectClass', ['top', 'group'])
	return {'objectName': dn, 'attributes': attrs}


def user(name, rid, uac=0x200, classes=('top', 'person', 'organizationalPerson', 'user'), **extra):
	return obj('CN=%s,CN=Users,%s' % (name, BASE), sAMAccountName=name, objectSid='%s-%d' % (DOM, rid),
		objectClass=list(classes), userAccountControl=uac, **extra)


EDDARD = user('eddard.stark', 1111, servicePrincipalName=['HTTP/x'], adminCount=1,
	pwdLastSet=datetime.datetime(2026, 4, 21, tzinfo=datetime.timezone.utc))
ROBERT = user('robert.baratheon', 1112, uac=0x200 | 0x10000, adminCount=1)
CATELYN = user('catelyn.stark', 1113, uac=0x200 | 0x100000)
OLD = user('old.admin', 1120, adminCount=1)
KRBTGT = user('krbtgt', 502, uac=0x202, adminCount=1, servicePrincipalName=['kadmin/changepw'])
EMPTY = obj('CN=Storage Replica Administrators,CN=Builtin,' + BASE, sAMAccountName='Storage Replica Administrators',
	objectSid='S-1-5-32-582', objectClass=['top', 'group'])
SVC = user('svc-sql', 1130, servicePrincipalName=['MSSQLSvc/db'], description='SQL admin service account')
SQLADMINS = obj('CN=SQL Admins,CN=Users,' + BASE, sAMAccountName='SQL Admins', objectSid='%s-1131' % DOM,
	objectClass=['top', 'group'], member=[SVC['objectName'], CATELYN['objectName']])
ADMWKS = obj('CN=ADMWKS01,CN=Computers,' + BASE, sAMAccountName='ADMWKS01$', objectSid='%s-1132' % DOM,
	objectClass=['top', 'computer'], userAccountControl=0x1000)
# DCs are in Domain Controllers through their primary group only, not through 'member'
DC = obj('CN=WINTERFELL,OU=Domain Controllers,' + BASE, sAMAccountName='WINTERFELL$', objectSid='%s-1001' % DOM,
	objectClass=['top', 'computer'], userAccountControl=0x2000 | 0x80000, primaryGroupID=516)

GROUPS = {
	'%s-512' % DOM: obj('CN=Domain Admins,CN=Users,' + BASE, sAMAccountName='Domänen-Admins', objectSid='%s-512' % DOM,
		member=[EDDARD['objectName'], 'CN=S-1-5-21-7-7-7-1104,CN=ForeignSecurityPrincipals,' + BASE]),
	'S-1-5-32-544': obj('CN=Administrators,CN=Builtin,' + BASE, sAMAccountName='Administrators', objectSid='S-1-5-32-544',
		member=['CN=Domain Admins,CN=Users,' + BASE, CATELYN['objectName'], 'CN=Enterprise Admins,CN=Users,DC=sevenkingdoms,DC=local']),
	'%s-516' % DOM: obj('CN=Domain Controllers,CN=Users,' + BASE, sAMAccountName='Domain Controllers', objectSid='%s-516' % DOM),
	'%s-525' % DOM: obj('CN=Protected Users,CN=Users,' + BASE, objectSid='%s-525' % DOM, member=[ROBERT['objectName']]),
	# exists, but has no members: no member query needed
	'S-1-5-32-548': obj('CN=Account Operators,CN=Builtin,' + BASE, sAMAccountName='Account Operators', objectSid='S-1-5-32-548'),
}
MEMBERS = {
	'CN=Domain Admins,CN=Users,' + BASE: [EDDARD, ROBERT],
	'CN=Administrators,CN=Builtin,' + BASE: [GROUPS['%s-512' % DOM], EDDARD, ROBERT, CATELYN],
	'CN=Protected Users,CN=Users,' + BASE: [ROBERT],
}


class FakeClient:
	def __init__(self):
		self._serverinfo = {
			'defaultNamingContext': BASE,
			'rootDomainNamingContext': 'DC=sevenkingdoms,DC=local',
		}
		self._tree = BASE
		self.domainsid = DOM
		self.queries = []

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		self.queries.append(query)
		results = []
		if query.startswith('(|(objectSid='):
			results = [GROUPS[sid] for sid in re.findall(r'\(objectSid=([^)]+)\)', query) if sid in GROUPS]
		elif 'memberOf:1.2.840.113556.1.4.1941:=' in query:
			dn = re.search(r':=([^)]+)\)', query).group(1)
			results = list(MEMBERS.get(dn, []))
			pg = re.search(r'\(primaryGroupID=(\d+)\)', query)
			if pg:
				results += [e for e in (EDDARD, ROBERT, CATELYN, DC) if str(e['attributes'].get('primaryGroupID')) == pg.group(1)]
		elif 'trustedDomain' in query:
			assert 'trustPartner=sevenkingdoms.local' in query
			# msldap returns securityIdentifier as raw bytes
			results = [obj('CN=sevenkingdoms.local,CN=System,' + BASE, securityIdentifier=SID.from_string(ROOT).to_bytes())]
		elif query.startswith('(&(adminCount=1)'):
			results = [EDDARD, ROBERT, OLD, KRBTGT]
		elif '(sAMAccountName=*adm*)' in query:
			# already listed objects come back as well and must be skipped
			results = [SVC, SQLADMINS, ADMWKS, OLD, GROUPS['%s-512' % DOM], EMPTY]
		for r in results:
			yield r, None


async def test_collect_privileged_accounts():
	report = await privileged.collect(FakeClient())
	groups = {g.name: g for g in report.groups}

	# found by SID, shown with the localized name
	da = groups['Domänen-Admins']
	assert {m.name for m in da.members} == {'eddard.stark', 'robert.baratheon'}
	assert da.members[0].groups['Domänen-Admins'] == 'direct'
	assert da.foreign == ['CN=S-1-5-21-7-7-7-1104,CN=ForeignSecurityPrincipals,' + BASE]

	admins = groups['Administrators']
	assert admins.foreign == ['CN=Enterprise Admins,CN=Users,DC=sevenkingdoms,DC=local']
	assert {m.name: m.groups['Administrators'] for m in admins.members}['eddard.stark'] == 'nested'
	assert {m.name: m.kind for m in admins.members}['Domänen-Admins'] == 'group'

	# forest root groups are looked up with the root SID from the trust and explained on a child DC
	assert groups['Enterprise Admins'].sid == ROOT + '-519'
	assert 'forest root sevenkingdoms.local' in groups['Enterprise Admins'].note
	assert groups['Account Operators'].note is None and groups['Account Operators'].members == []
	assert groups['Server Operators'].note == 'not found'
	assert {m.name: m.groups['Domain Controllers'] for m in groups['Domain Controllers'].members} == {'WINTERFELL$': 'primary'}

	accounts = {a.name: a for a in report.accounts.values()}
	assert accounts['eddard.stark'].findings() == ['kerberoastable', 'delegable']
	assert accounts['robert.baratheon'].findings() == ['password-never-expires']  # Protected Users
	assert accounts['catelyn.stark'].findings() == []  # sensitive, cannot be delegated
	assert accounts['WINTERFELL$'].findings() == []  # DCs have unconstrained delegation by design
	# krbtgt has adminCount=1 by design
	assert [a.name for a in report.orphaned] == ['old.admin']

	matches = {m.account.name: m for m in report.name_matches}
	# groups without members are left out
	assert set(matches) == {'svc-sql', 'SQL Admins', 'ADMWKS01$'}
	assert matches['svc-sql'].fields == ['description']
	assert matches['svc-sql'].account.findings() == ['kerberoastable', 'delegable']
	assert matches['SQL Admins'].members == 2
	assert matches['ADMWKS01$'].account.kind == 'computer'
	assert report.errors == []


async def test_query_count():
	client = FakeClient()
	await privileged.collect(client)
	# trust, one lookup for all groups, Protected Users members, members of the 3 groups that
	# can have members (Account Operators is empty), adminCount, name search
	assert len(client.queries) == 8, client.queries
	# the forest root groups are not looked up on a child domain
	assert not any(ROOT in q for q in client.queries)
	lookup = client.queries[1]
	assert '(objectSid=%s-525)' % DOM in lookup and '(sAMAccountName=DnsAdmins)' in lookup


async def test_name_search_can_be_skipped():
	client = FakeClient()
	report = await privileged.collect(client, None)
	assert report.name_matches == []
	assert not any('*adm*' in q for q in client.queries)


def test_name_search_filter_escapes_the_pattern():
	flt = privileged.name_search_filter('a*(b)')
	assert '(sAMAccountName=*a\\2a\\28b\\29*)' in flt
	assert '(sAMAccountType=805306369)' in flt


async def test_report_and_command(capsys):
	console = MSLDAPOpsConsole(None)
	assert await console.do_find_admins() is False
	console.connection = FakeClient()
	assert await console.do_find_admins() is True
	out = capsys.readouterr().out
	assert 'Domänen-Admins (S-1-5-21-1-2-3-512): 2 accounts' in out
	assert 'Administrators (S-1-5-32-544): 3 accounts' in out
	assert 'Domain Controllers (S-1-5-21-1-2-3-516): 1 account\n' in out
	assert 'Privileged accounts: 4' in out
	assert 'eddard.stark' in out and 'kerberoastable, delegable' in out
	assert 'pwdLastSet 2026-04-21' in out
	assert 'adminCount=1 users outside the privileged groups: 1' in out
	assert '(other domain)' in out
	assert "Name or description contains 'adm', outside the privileged groups: 3" in out
	assert 'SQL Admins' in out and '2 members' in out


def test_root_groups_without_root_sid():
	sids = dict(privileged.group_sids(DOM, None))
	assert sids['Enterprise Admins'] is None
	assert sids['Domain Admins'] == DOM + '-512'


def test_table_aligns_long_names():
	lines = privileged.table([['Network Configuration Operators', 'group', 'description', '3 members'], ['svc', 'user', 'sAMAccountName', '']], 2)
	assert lines[0].index('group') == lines[1].index('user')
	assert lines[0].index('description') == lines[1].index('sAMAccountName')
	assert lines[1] == lines[1].rstrip()
