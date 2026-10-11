import datetime

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap.ldap_objects.adcertificatetemplate import CertificateNameFlag, EnrollmentFlag

from msldap_ops import templates
from msldap_ops.shell import MSLDAPOpsConsole

DOM = 'S-1-5-21-1-2-3'
CONFIG = 'CN=Configuration,DC=sevenkingdoms,DC=local'
ENROLL = '0e10c968-78fb-11d2-90d4-00c04f79dc55'


def sd(sddl):
	return SECURITY_DESCRIPTOR.from_sddl(sddl).to_bytes()


def template(name, name_flag=0, enroll_flag=0, ekus=('1.3.6.1.5.5.7.3.2',), sddl=None, **extra):
	attrs = {
		'name': name, 'cn': name, 'distinguishedName': 'CN=%s,CN=Certificate Templates,%s' % (name, CONFIG),
		'msPKI-Certificate-Name-Flag': name_flag, 'msPKI-Enrollment-Flag': enroll_flag,
		'msPKI-Private-Key-Flag': 0x10, 'msPKI-RA-Signature': 0, 'msPKI-Template-Schema-Version': 2,
		'pKIExtendedKeyUsage': list(ekus),
		'pKIExpirationPeriod': -datetime.timedelta(days=365), 'pKIOverlapPeriod': -datetime.timedelta(weeks=6),
		'msPKI-Minimal-Key-Size': 2048,
		# owner/group Domain Admins, Domain Users may enroll
		'nTSecurityDescriptor': sd(sddl or 'O:%s-512G:%s-512D:(OA;;CR;%s;;%s-513)(A;;0xf01ff;;;%s-512)' % (DOM, DOM, ENROLL, DOM, DOM)),
	}
	attrs.update(extra)
	return {'objectName': attrs['distinguishedName'], 'attributes': attrs}


ESC1 = template('ESC1', name_flag=CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT, displayName='ESC1 display')
USER = template('User', name_flag=CertificateNameFlag.SUBJECT_ALT_REQUIRE_UPN | CertificateNameFlag.SUBJECT_REQUIRE_DIRECTORY_PATH,
	enroll_flag=EnrollmentFlag.PUBLISH_TO_DS | EnrollmentFlag.AUTO_ENROLLMENT)
UNPUBLISHED = template('Unpublished', name_flag=CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT)
APPROVAL = template('Approval', name_flag=CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT, enroll_flag=EnrollmentFlag.PEND_ALL_REQUESTS)
CA = {'objectName': 'CN=SEVENKINGDOMS-CA', 'attributes': {
	'name': 'SEVENKINGDOMS-CA', 'dNSHostName': 'kingslanding.sevenkingdoms.local',
	'certificateTemplates': ['ESC1', 'User', 'Approval'],
}}


class FakeClient:
	def __init__(self, whoami='u:NORTH\\jon.snow', user_found=True):
		self.domainsid = DOM
		self._tree = 'DC=north,DC=sevenkingdoms,DC=local'
		self._whoami = whoami
		self.user_found = user_found
		self.queries = []

	def _get_configuration_nc(self):
		return CONFIG

	async def whoami(self):
		return self._whoami, None

	async def resolv_sd(self, sd):
		return {'%s-513' % DOM: ('NORTH', 'Domain Users'), '%s-512' % DOM: ('NORTH', 'Domain Admins')}, None

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		self.queries.append((query, tree, search_scope, controls))
		results = []
		if query.startswith('(sAMAccountName=') and self.user_found:
			results = [{'objectName': 'CN=jon.snow', 'attributes': {'distinguishedName': 'CN=jon.snow'}}]
		elif tree == 'CN=jon.snow':
			results = [{'objectName': 'CN=jon.snow', 'attributes': {'objectSid': DOM + '-1118', 'tokenGroups': [DOM + '-513']}}]
		elif 'pKIEnrollmentService' in query:
			results = [CA]
		elif 'pKICertificateTemplate' in query:
			results = [ESC1, USER, UNPUBLISHED, APPROVAL]
			if 'name=' in query:
				results = [t for t in results if '(name=%s)' % t['attributes']['name'] in query]
		for r in results:
			yield r, None


async def test_collect_evaluates_templates_for_the_bound_user():
	client = FakeClient()
	report = await templates.collect(client)
	assert report.principal == 'NORTH\\jon.snow'
	by_name = {t.name: t for t in report.templates}
	assert by_name['ESC1'].cas == ['SEVENKINGDOMS-CA (kingslanding.sevenkingdoms.local)']
	assert set(by_name['ESC1'].vulns) == {'ESC1'}
	assert by_name['User'].vulns == {}
	assert not by_name['Unpublished'].enabled
	# whoami is an extended operation; searches: user, tokenGroups, CAs, templates
	assert len(client.queries) == 4
	templates_query = client.queries[-1]
	assert templates_query[1] == 'CN=Certificate Templates,CN=Public Key Services,CN=Services,' + CONFIG
	assert templates_query[3][0][0] == '1.2.840.113556.1.4.801'
	assert client.queries[1][2] == 0  # tokenGroups needs a base search


async def test_foreign_user_is_checked_as_low_privileged():
	report = await templates.collect(FakeClient(user_found=False))
	assert 'not in the connected domain' in report.note
	assert '%s-513' % DOM in report.tokengroups
	assert set({t.name: t for t in report.templates}['ESC1'].vulns) == {'ESC1'}


def test_flag_lines_mark_risky_bits():
	assert templates.flag_lines(CertificateNameFlag, CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT) == ['ENROLLEE_SUPPLIES_SUBJECT [!]']
	assert templates.flag_lines(EnrollmentFlag, 0) == ['None']
	assert templates.flag_lines(EnrollmentFlag, EnrollmentFlag.NO_SECURITY_EXTENSION | 0x40000000) == ['NO_SECURITY_EXTENSION [!]', '0x40000000']
	# msPKI-Certificate-Name-Flag is stored as a signed 32 bit value
	assert templates.flag_lines(CertificateNameFlag, -2113929216) == ['SUBJECT_ALT_REQUIRE_UPN', 'SUBJECT_REQUIRE_DIRECTORY_PATH']


def test_format_period():
	assert templates.format_period(-datetime.timedelta(days=365)) == '1 year'
	assert templates.format_period(-datetime.timedelta(weeks=6)) == '6 weeks'
	assert templates.format_period(-datetime.timedelta(days=2 * 365)) == '2 years'
	assert templates.format_period(datetime.timedelta(hours=8)) == '8 hours'
	assert templates.format_period(None) is None


async def test_summary_and_details(capsys):
	console = MSLDAPOpsConsole(None)
	assert await console.do_templates() is False
	console.connection = FakeClient()
	assert await console.do_templates() is True
	out = capsys.readouterr().out
	lines = {line.split()[0]: line for line in out.splitlines() if line.startswith('  ') and line.split()}
	assert 'ESC1' in lines['ESC1'] and 'SEVENKINGDOMS-CA' in lines['ESC1']
	assert lines['Unpublished'].split()[1] == '(not'
	assert lines['Unpublished'].rstrip().endswith('-')
	assert lines['Approval'].split()[-2:] == ['yes', 'none']

	assert await console.do_templates('ESC1') is True
	out = capsys.readouterr().out
	assert 'Display Name                    : ESC1 display' in out
	assert 'Enrollee Supplies Subject       : True [!]' in out
	assert 'Certificate Name Flag           : ENROLLEE_SUPPLIES_SUBJECT [!]' in out
	assert 'Validity Period                 : 1 year' in out
	assert 'Enrollment Rights             : NORTH\\Domain Users' in out
	assert '[!] Vulnerabilities for NORTH\\jon.snow' in out
	assert 'ESC1                          : ' in out

	assert await console.do_templates('User') is True
	out = capsys.readouterr().out
	assert 'Certificate Name Flag           : SUBJECT_ALT_REQUIRE_UPN\n' in out
	assert '                                  SUBJECT_REQUIRE_DIRECTORY_PATH\n' in out
	assert 'Vulnerabilities' not in out


async def test_vulnerable_shows_only_published_vulnerable_templates(capsys):
	console = MSLDAPOpsConsole(None)
	console.connection = FakeClient()
	assert await console.do_templates('vulnerable') is True
	out = capsys.readouterr().out
	assert 'Template ESC1' in out
	assert 'Template Unpublished' not in out and 'Template User' not in out
