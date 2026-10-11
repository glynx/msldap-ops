import datetime

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
DC = obj('CN=WINTERFELL,OU=Domain Controllers,' + BASE, sAMAccountName='WINTERFELL$', objectSid='%s-1001' % DOM,
	objectClass=['top', 'computer'], userAccountControl=0x2000 | 0x80000)

GROUPS = {
	'%s-512' % DOM: obj('CN=Domain Admins,CN=Users,' + BASE, sAMAccountName='Domänen-Admins', objectSid='%s-512' % DOM,
		member=[EDDARD['objectName'], 'CN=S-1-5-21-7-7-7-1104,CN=ForeignSecurityPrincipals,' + BASE]),
	'S-1-5-32-544': obj('CN=Administrators,CN=Builtin,' + BASE, sAMAccountName='Administrators', objectSid='S-1-5-32-544',
		member=['CN=Domain Admins,CN=Users,' + BASE, CATELYN['objectName'], 'CN=Enterprise Admins,CN=Users,DC=sevenkingdoms,DC=local']),
	'%s-516' % DOM: obj('CN=Domain Controllers,CN=Users,' + BASE, sAMAccountName='Domain Controllers', objectSid='%s-516' % DOM, member=[DC['objectName']]),
	'%s-525' % DOM: obj('CN=Protected Users,CN=Users,' + BASE, objectSid='%s-525' % DOM),
}
MEMBERS = {
	'CN=Domain Admins,CN=Users,' + BASE: [EDDARD, ROBERT],
	'CN=Administrators,CN=Builtin,' + BASE: [GROUPS['%s-512' % DOM], EDDARD, ROBERT, CATELYN],
	'CN=Domain Controllers,CN=Users,' + BASE: [DC],
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
		if query.startswith('(objectSid='):
			sid = query[len('(objectSid='):-1]
			results = [GROUPS[sid]] if sid in GROUPS else []
		elif query.startswith('(memberOf:1.2.840.113556.1.4.1941:='):
			results = MEMBERS.get(query.split(':=', 1)[1][:-1], [])
		elif 'trustedDomain' in query:
			assert 'trustPartner=sevenkingdoms.local' in query
			results = [obj('CN=sevenkingdoms.local,CN=System,' + BASE, securityIdentifier=ROOT)]
		elif query.startswith('(&(adminCount=1)'):
			results = [EDDARD, ROBERT, OLD]
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
	assert groups['Account Operators'].note == 'not found'

	accounts = {a.name: a for a in report.accounts.values()}
	assert accounts['eddard.stark'].findings() == ['kerberoastable', 'delegable']
	assert accounts['robert.baratheon'].findings() == ['password-never-expires']  # Protected Users
	assert accounts['catelyn.stark'].findings() == []  # sensitive, cannot be delegated
	assert accounts['WINTERFELL$'].findings() == []  # DCs have unconstrained delegation by design
	assert [a.name for a in report.orphaned] == ['old.admin']
	assert report.errors == []


async def test_report_and_command(capsys):
	console = MSLDAPOpsConsole(None)
	assert await console.do_admins() is False
	console.connection = FakeClient()
	assert await console.do_admins() is True
	out = capsys.readouterr().out
	assert 'Domänen-Admins (S-1-5-21-1-2-3-512): 2 accounts' in out
	assert 'Administrators (S-1-5-32-544): 3 accounts' in out
	assert 'Privileged accounts: 4' in out
	assert 'eddard.stark' in out and 'kerberoastable, delegable' in out
	assert 'pwdLastSet 2026-04-21' in out
	assert 'adminCount=1 users outside the privileged groups: 1' in out
	assert '(other domain)' in out


def test_root_groups_without_root_sid():
	sids = dict(privileged.group_sids(DOM, None))
	assert sids['Enterprise Admins'] is None
	assert sids['Domain Admins'] == DOM + '-512'
