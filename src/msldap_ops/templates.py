"""Certificate templates in a certipy-like layout.

The flags and ACEs are evaluated by msldap's MSADCertificateTemplate; this module adds the
queries for the extra attributes (validity, key size, ...), the token groups of the current user
and the output: decoded flags one per line, security relevant bits marked with [!].
"""

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from msldap.ldap_objects.adcertificatetemplate import (
	EKUS_NAMES, MSADCertificateTemplate, MSADCertificateTemplate_ATTRS, CertificateNameFlag,
	EnrollmentFlag, PrivateKeyFlag,
)
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue

from msldap_ops.privileged import as_list, attr, escape_filter_value, sid_string, table

TEMPLATE_ATTRIBUTES = MSADCertificateTemplate_ATTRS + [
	'displayName', 'pKIExpirationPeriod', 'pKIOverlapPeriod', 'msPKI-Minimal-Key-Size',
	'msPKI-Certificate-Policy', 'whenCreated', 'whenChanged',
]
CA_ATTRIBUTES = ['name', 'dNSHostName', 'certificateTemplates']

# bits that make a template easier to abuse
RISKY_BITS = {
	CertificateNameFlag: {CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT, CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME},
	EnrollmentFlag: {EnrollmentFlag.NO_SECURITY_EXTENSION, EnrollmentFlag.ISSUANCE_POLICIES_FROM_REQUEST},
	PrivateKeyFlag: set(),
}
MARK = '[!]'


def pki_base(config_nc):
	return 'CN=Public Key Services,CN=Services,%s' % config_nc


def sd_flags_control():
	flags = SDFlagsRequest.OWNER_SECURITY_INFORMATION | SDFlagsRequest.GROUP_SECURITY_INFORMATION | SDFlagsRequest.DACL_SECURITY_INFORMATION
	return ('1.2.840.113556.1.4.801', True, SDFlagsRequestValue({'Flags': flags}).dump())


def flag_lines(flagtype, value):
	"""Decoded flags, one per entry, risky ones marked; unknown bits as hex."""
	value = int(value or 0) & 0xFFFFFFFF
	if value == 0:
		return ['None']
	lines, known = [], 0
	for member in flagtype:
		if member.value and value & member.value == member.value:
			known |= member.value
			lines.append('%s %s' % (member.name, MARK) if member in RISKY_BITS.get(flagtype, ()) else member.name)
	if value & ~known:
		lines.append('0x%08x' % (value & ~known))
	return lines


def format_period(value):
	"""certipy style: '1 year', '6 weeks', ..."""
	if value is None:
		return None
	if isinstance(value, datetime.timedelta):
		if value == datetime.timedelta.max:
			return 'never'
		seconds = abs(value.total_seconds())
	else:
		seconds = abs(int(value)) / 10_000_000
	units = [('year', 365 * 86400), ('month', 30 * 86400), ('week', 7 * 86400), ('day', 86400), ('hour', 3600)]
	for name, size in units:
		if seconds >= size and seconds % size == 0:
			n = int(seconds // size)
			return '%d %s%s' % (n, name, '' if n == 1 else 's')
	return '%d seconds' % seconds


def low_priv_sids(domain_sid):
	return {'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', '%s-513' % domain_sid, '%s-515' % domain_sid}


@dataclass
class TemplateInfo:
	template: MSADCertificateTemplate
	entry: dict
	cas: List[str] = field(default_factory=list)  # 'name (host)'
	vulns: Dict[str, dict] = field(default_factory=dict)

	@property
	def name(self):
		return self.template.name

	@property
	def enabled(self):
		return bool(self.cas)


@dataclass
class TemplateReport:
	templates: List[TemplateInfo]
	principal: str  # whose token was used for the vulnerability checks
	tokengroups: List[str]
	note: Optional[str] = None


async def _search(client, query, attributes, base, controls=None):
	results = []
	async for entry, err in client.pagedsearch(query, attributes, controls=controls, tree=base):
		if err is not None:
			raise err
		results.append(entry)
	return results


async def current_token(client):
	"""(principal, token SIDs) of the bound user; falls back to the low privileged groups when
	the account is not in the connected domain (e.g. bound through a trust)."""
	res, err = await client.whoami()
	if err is not None:
		raise err
	fallback = sorted(low_priv_sids(client.domainsid))
	if not res or not res.startswith('u:') or '\\' not in res:
		return 'low privileged users (whoami: %s)' % res, fallback, 'could not determine the bound user'
	domain, sam = res[2:].split('\\', 1)
	found = await _search(client, '(sAMAccountName=%s)' % escape_filter_value(sam), ['distinguishedName'], client._tree)
	if not found:
		note = '%s\\%s is not in the connected domain, checked as a low privileged user' % (domain, sam)
		return 'low privileged users', fallback, note
	dn = attr(found[0], 'distinguishedName') or found[0]['objectName']
	token = []
	async for entry, err in client.pagedsearch('(objectClass=*)', ['objectSid', 'tokenGroups'], tree=dn, search_scope=0):
		if err is not None:
			raise err
		token.append(sid_string(attr(entry, 'objectSid')))
		token.extend(sid_string(s) for s in as_list(attr(entry, 'tokenGroups')))
	return '%s\\%s' % (domain, sam), token, None


async def collect(client, name=None):
	"""Queries: whoami (extended operation), the user and its tokenGroups, the enrollment
	services and the templates (with the SD flags control)."""
	config = client._get_configuration_nc()
	principal, tokengroups, note = await current_token(client)

	services = await _search(client, '(objectClass=pKIEnrollmentService)', CA_ATTRIBUTES, 'CN=Enrollment Services,%s' % pki_base(config))
	published = {}
	for ca in services:
		label = '%s (%s)' % (attr(ca, 'name'), attr(ca, 'dNSHostName'))
		for template_name in as_list(attr(ca, 'certificateTemplates')):
			published.setdefault(template_name.lower(), []).append(label)

	query = '(objectClass=pKICertificateTemplate)'
	if name:
		query = '(&(objectClass=pKICertificateTemplate)(|(name=%s)(displayName=%s)))' % (escape_filter_value(name), escape_filter_value(name))
	entries = await _search(client, query, TEMPLATE_ATTRIBUTES, 'CN=Certificate Templates,%s' % pki_base(config), controls=[sd_flags_control()])

	templates = []
	for entry in entries:
		template = MSADCertificateTemplate.from_ldap(entry)
		info = TemplateInfo(template, entry, published.get((template.name or '').lower(), []))
		# schema version 1 templates may lack some msPKI-* attributes
		for attribute in ('Certificate_Name_Flag', 'Enrollment_Flag', 'Private_Key_Flag', 'RA_Signature'):
			if getattr(template, attribute) is None:
				setattr(template, attribute, 0)
		if template.nTSecurityDescriptor is not None:
			info.vulns = template.is_vulnerable2(tokengroups)
		templates.append(info)
	templates.sort(key=lambda t: (t.name or '').lower())
	return TemplateReport(templates, principal, tokengroups, note)


async def resolve_principals(client, info):
	"""SID -> 'DOMAIN\\name' for the SIDs in the template's security descriptor."""
	if info.template.nTSecurityDescriptor is None:
		return {}
	table, err = await client.resolv_sd(info.template.nTSecurityDescriptor)
	if err is not None:
		return {}
	return {sid: '%s\\%s' % value for sid, value in table.items()}


def _ekus(oids):
	return [EKUS_NAMES.get(oid, oid) for oid in as_list(oids)] or ['None']


def summary_lines(report):
	rows = [['Name', 'CAs', 'Client Auth', 'Enrollee Subject', 'Approval', 'Vulnerabilities']]
	for info in report.templates:
		t = info.template
		vulns = ', '.join(sorted(info.vulns)) if info.enabled else '-'
		rows.append([
			info.name, ', '.join(ca.split(' ')[0] for ca in info.cas) or '(not published)',
			'yes' if t.allows_authentication() else 'no',
			'yes' if t.allows_to_specify_san() else 'no',
			'yes' if t.requires_manager_approval() else 'no',
			vulns or 'none',
		])
	lines = table(rows, 2)
	lines.insert(1, '  ' + '-' * (max(len(line) for line in lines) - 2))
	return lines


def detail_lines(info, principals, principal):
	t = info.template
	e = info.entry
	sd = t.nTSecurityDescriptor
	rows = []

	def add(key, values):
		values = values if isinstance(values, list) else [values]
		for i, value in enumerate(values or ['None']):
			rows.append(('%-32s: ' % key if i == 0 else ' ' * 34) + str(value))

	def yes(value, risky=False):
		return ('True %s' % MARK) if value and risky else str(bool(value))

	def names(sids):
		return sorted(principals.get(s, s) for s in sids) or ['None']

	add('Template Name', t.name)
	add('Display Name', attr(e, 'displayName') or t.name)
	add('Certificate Authorities', info.cas or ['None (not published, cannot be requested)'])
	add('Enabled', yes(info.enabled))
	add('Client Authentication', yes(t.allows_authentication()))
	add('Enrollment Agent', yes(t.allows_to_request_agent_certificate()))
	add('Any Purpose', yes(t.can_be_used_for_any_purpose(), risky=True))
	add('Enrollee Supplies Subject', yes(t.allows_to_specify_san(), risky=True))
	add('Certificate Name Flag', flag_lines(CertificateNameFlag, t.Certificate_Name_Flag))
	add('Enrollment Flag', flag_lines(EnrollmentFlag, t.Enrollment_Flag))
	add('Private Key Flag', flag_lines(PrivateKeyFlag, t.Private_Key_Flag))
	add('Extended Key Usage', _ekus(t.pKIExtendedKeyUsage))
	if t.Certificate_Application_Policy:
		add('Application Policies', _ekus(t.Certificate_Application_Policy))
	add('Requires Manager Approval', yes(t.requires_manager_approval()))
	add('Requires Key Archival', yes(int(t.Private_Key_Flag or 0) & PrivateKeyFlag.REQUIRE_PRIVATE_KEY_ARCHIVAL))
	add('Authorized Signatures Required', int(t.RA_Signature or 0))
	if t.RA_Application_Policies:
		add('RA Application Policies', _ekus(t.RA_Application_Policies))
	if attr(e, 'msPKI-Certificate-Policy'):
		add('Issuance Policies', as_list(attr(e, 'msPKI-Certificate-Policy')))
	add('Schema Version', t.Template_Schema_Version)
	add('Validity Period', format_period(attr(e, 'pKIExpirationPeriod')))
	add('Renewal Period', format_period(attr(e, 'pKIOverlapPeriod')))
	add('Minimum RSA Key Length', attr(e, 'msPKI-Minimal-Key-Size'))
	for key, attribute in (('Created', 'whenCreated'), ('Modified', 'whenChanged')):
		if attr(e, attribute) is not None:
			add(key, _date(attr(e, attribute)))

	lines = ['Template %s' % t.name] + ['  ' + r for r in rows]
	if sd is not None:
		lines.append('  Permissions')
		perms = [
			('Enrollment Rights', t.enroll_sids),
			('Autoenrollment Rights', t.autoenroll_sids),
			('All Extended Rights', t.allextendedrights_sids),
			('Owner', [str(sd.Owner)]),
			('Full Control', t.fullcontrol_sids),
			('Write Owner', t.write_owner_sids),
			('Write DACL', t.write_dacl_sids),
			('Write Property', t.write_property_sids),
		]
		for key, sids in perms:
			for i, value in enumerate(names(sids)):
				lines.append('    ' + ('%-30s: ' % key if i == 0 else ' ' * 32) + value)

	if info.vulns:
		lines.append('  %s Vulnerabilities for %s%s' % (MARK, principal, '' if info.enabled else ' (template not published, not exploitable yet)'))
		for esc in sorted(info.vulns):
			lines.append('    %-30s: %s' % (esc, info.vulns[esc]['Reason']))
	return lines


def _date(value):
	if isinstance(value, datetime.datetime):
		return value.strftime('%Y-%m-%d %H:%M:%S')
	return value
