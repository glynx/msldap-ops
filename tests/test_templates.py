import datetime

import pytest

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
			results = [{'objectName': 'CN=jon.snow', 'attributes': {
				'distinguishedName': 'CN=jon.snow', 'msDS-PrincipalName': 'NORTH\\jon.snow'}}]
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


async def test_foreign_account_with_same_sam_cannot_use_local_token():
	client = FakeClient(whoami='u:ESSOS\\jon.snow')
	report = await templates.collect(client)
	assert report.principal == 'low privileged users'
	assert 'could not verify ESSOS\\jon.snow' in report.note
	assert not any(base == 'CN=jon.snow' for _, base, _, _ in client.queries)
	assert DOM + '-1118' not in report.tokengroups


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


POLICY_OID = '1.2.3.4.5'
LINKED_GROUP = 'CN=Linked Group,CN=Users,DC=sevenkingdoms,DC=local'
POLICY = {'objectName': 'CN=Policy,CN=OID,' + templates.pki_base(CONFIG), 'attributes': {
	'msPKI-Cert-Template-OID': POLICY_OID, 'msDS-OIDToGroupLink': LINKED_GROUP,
}}


class PolicyClient(FakeClient):
	def __init__(self, entries, policies=(POLICY,), policy_error=None, **kwargs):
		super().__init__(**kwargs)
		self.entries = entries
		self.policies = policies
		self.policy_error = policy_error

	async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
		if query in ('(objectClass=pKICertificateTemplate)', '(objectClass=msPKI-Enterprise-Oid)') or 'pKIEnrollmentService' in query:
			self.queries.append((query, tree, search_scope, controls))
			if 'msPKI-Enterprise-Oid' in query:
				assert attributes == templates.POLICY_ATTRIBUTES
				if self.policy_error:
					yield None, self.policy_error
					return
				results = self.policies
			elif 'pKIEnrollmentService' in query:
				results = [{'objectName': 'CN=CA', 'attributes': {'name': 'CA', 'dNSHostName': 'ca.example',
					'certificateTemplates': [e['attributes']['name'] for e in self.entries]}}]
			else:
				results = self.entries
			for entry in results:
				yield entry, None
		else:
			async for item in super().pagedsearch(query, attributes, controls=controls, tree=tree, search_scope=search_scope):
				yield item


@pytest.mark.parametrize('version,signatures,policies,approval,expected', [
	(2, 1, [templates.AGENT_OID], False, True),
	(1, 0, [], False, True),
	(2, 0, [], False, False),
	(2, 2, [templates.AGENT_OID], False, False),
	(2, 1, [templates.AGENT_OID], True, False),
	(2, 1, ['1.2.3'], False, False),
])
async def test_agent_targets_are_review_points_not_standalone_findings(version, signatures, policies, approval, expected):
	entry = template('Target', enroll_flag=EnrollmentFlag.PEND_ALL_REQUESTS if approval else 0, **{
		'msPKI-Template-Schema-Version': version, 'msPKI-RA-Signature': signatures,
		'msPKI-RA-Application-Policies': policies,
	})
	report = await templates.collect(PolicyClient([entry]))
	info = report.templates[0]
	assert ('ESC3 target' in info.reviews) is expected
	assert 'ESC3' not in info.vulns
	assert len(info.reviews) == int(expected)


async def test_agent_issuer_remains_a_finding_and_review_only_target_is_filtered(capsys):
	agent = template('Agent', ekus=[templates.AGENT_OID])
	target = template('Target', **{'msPKI-RA-Signature': 1, 'msPKI-RA-Application-Policies': [templates.AGENT_OID]})
	client = PolicyClient([agent, target])
	report = await templates.collect(client)
	assert report.templates[0].vulns.keys() == {'ESC3'}
	console = MSLDAPOpsConsole(None)
	console.connection = client
	assert await console.do_templates('vulnerable')
	out = capsys.readouterr().out
	assert 'Template Agent' in out and 'Template Target' not in out


async def test_other_principals_template_control_is_reviewed_and_current_token_still_gets_esc4():
	controller = DOM + '-1105'
	entry = template('Controlled', enroll_flag=EnrollmentFlag.PEND_ALL_REQUESTS, ekus=['1.3.6.1.5.5.7.3.3'],
		sddl='O:%s-519G:%s-512D:(A;;0xf01ff;;;%s)(A;;0xf01ff;;;%s-512)' % (DOM, DOM, controller, DOM),
		**{'msPKI-RA-Signature': 1})
	report = await templates.collect(PolicyClient([entry], user_found=False))
	info = report.templates[0]
	assert 'not in the connected domain' in report.note
	assert not info.vulns
	assert info.reviews['ESC4 ACL']['SIDs'] == [controller]
	out = '\n'.join(templates.detail_lines(info, {controller: 'ESSOS\\khal.drogo'}, report.principal))
	assert '[review] ESC4 ACL' in out and 'Principal: ESSOS\\khal.drogo' in out
	assert 'ESC4' in info.template.is_vulnerable2([controller])


@pytest.mark.parametrize('ace', ['(D;;WD;;;%s-1105)', '(A;CIIO;WD;;;%s-1105)', '(A;;WD;;;%s-512)'])
async def test_acl_reviews_ignore_denies_inherit_only_and_privileged_principals(ace):
	entry = template('Control', sddl='O:%s-512G:%s-512D:%s' % (DOM, DOM, ace % DOM))
	info = (await templates.collect(PolicyClient([entry]))).templates[0]
	assert not info.reviews


async def test_esc13_correlates_issuance_policy_and_reuses_implicit_token_sids():
	entry = template('Custom name', sddl='O:%s-512G:%s-512D:(OA;;CR;%s;;AU)' % (DOM, DOM, ENROLL),
		**{'msPKI-Certificate-Policy': [POLICY_OID]})
	client = PolicyClient([entry])
	report = await templates.collect(client)
	info = report.templates[0]
	assert info.vulns.keys() == {'ESC13'}
	assert info.vulns['ESC13']['SIDs'] == ['S-1-5-11']
	assert info.linked_groups == [LINKED_GROUP]
	assert not info.reviews
	assert len(client.queries) == 5
	assert client.queries[-1][1] == 'CN=OID,' + templates.pki_base(CONFIG)
	assert 'Linked Groups                   : ' + LINKED_GROUP in '\n'.join(templates.detail_lines(info, {}, report.principal))
	assert info.policy_objects == [POLICY['objectName']]


@pytest.mark.parametrize('extra', [
	{'msPKI-Enrollment-Flag': EnrollmentFlag.PEND_ALL_REQUESTS},
	{'msPKI-RA-Signature': 1},
	{'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.3']},
	{'nTSecurityDescriptor': None},
	{'nTSecurityDescriptor': sd('O:%s-512G:%s-512D:(OA;;CR;%s;;%s-1105)' % (DOM, DOM, ENROLL, DOM))},
	{'nTSecurityDescriptor': sd('O:%s-512G:%s-512D:(OA;CIIO;CR;%s;;%s-513)' % (DOM, DOM, ENROLL, DOM))},
	{'nTSecurityDescriptor': sd('O:%s-512G:%s-512D:(D;;CR;;;AU)(OA;;CR;%s;;%s-513)' % (DOM, DOM, ENROLL, DOM))},
])
async def test_esc13_prerequisites_and_complex_acls_are_not_reported_as_findings(extra):
	entry = template('Policy', **{'msPKI-Certificate-Policy': [POLICY_OID], **extra})
	info = (await templates.collect(PolicyClient([entry]))).templates[0]
	assert 'ESC13' not in info.vulns
	assert 'ESC13 policy' in info.reviews
	assert info.linked_groups == [LINKED_GROUP]


@pytest.mark.parametrize('policies,unassessed', [([], True), ([{'attributes': {'msPKI-Cert-Template-OID': POLICY_OID}}], False)])
async def test_policy_oid_alone_does_not_imply_esc13(policies, unassessed):
	entry = template('ESC13', **{'msPKI-Certificate-Policy': [POLICY_OID]})
	info = (await templates.collect(PolicyClient([entry], policies=policies))).templates[0]
	assert not info.vulns and not info.linked_groups
	assert ('ESC13 unassessed' in info.reviews) is unassessed
	if unassessed:
		assert info.policy_status.startswith('Unassessed:')
	else:
		assert 'No msDS-OIDToGroupLink returned by LDAP' in info.policy_status
		out = '\n'.join(templates.detail_lines(info, {}, 'low privileged users'))
		assert 'ESC13 Check                     : ' + info.policy_status in out


async def test_policy_read_failure_retains_other_findings_and_opsec_abort_propagates():
	from msldap_ops.hooks import QueryAborted
	entry = template('Policy', name_flag=CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT,
		**{'msPKI-Certificate-Policy': [POLICY_OID]})
	info = (await templates.collect(PolicyClient([entry], policy_error=PermissionError('access denied')))).templates[0]
	assert info.vulns.keys() == {'ESC1'}
	assert 'access denied' in info.reviews['ESC13 unassessed']['Reason']
	with pytest.raises(QueryAborted):
		await templates.collect(PolicyClient([entry], policy_error=QueryAborted('skipped')))


async def test_summary_fits_120_columns_with_reviews_kept_in_details():
	import re
	from msldap_ops import ui
	target = template('DomainControllerAuthentication', **{
		'msPKI-RA-Signature': 1, 'msPKI-RA-Application-Policies': [templates.AGENT_OID],
	})
	report = await templates.collect(PolicyClient([ESC1, target]))
	for info in report.templates:
		info.cas = ['ESSOS-CA (braavos.essos.local)']
	lines = templates.summary_lines(report)
	assert 'Review' not in lines[0]
	assert not any('[review]' in line for line in lines)
	assert any(line.rstrip().endswith('ESC3 [?]') for line in lines)
	for line in lines:
		rendered = re.sub(r'\x1b\[[0-9;]*m', '', ui.render(line, width=120))
		assert rendered == line
	info = next(info for info in report.templates if info.name == target['attributes']['name'])
	assert '[review] ESC3 target' in '\n'.join(templates.detail_lines(info, {}, report.principal))


def test_summary_distinguishes_reviews_from_findings_and_hides_unpublished_checks():
	info = templates.TemplateInfo(templates.MSADCertificateTemplate.from_ldap(USER), USER, ['ESSOS-CA'])
	info.reviews = {'ESC4 ACL': {}, 'ESC13 policy': {}, 'ESC13 unassessed': {}}
	report = templates.TemplateReport([info], 'low privileged users', [])
	assert templates.summary_lines(report)[-1].endswith('ESC13 [?], ESC4 [?]')
	info.vulns = {'ESC13': {}, 'ESC1': {}}
	assert templates.summary_lines(report)[-1].endswith('ESC1, ESC13, ESC4 [?]')
	info.cas = []
	assert templates.summary_lines(report)[-1].endswith('  -')
