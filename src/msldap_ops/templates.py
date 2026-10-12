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
	EnrollmentFlag, PrivateKeyFlag, IMPLICIT_TOKEN_SIDS,
)
from winacl.dtyp.ace import AceFlags, ACEType
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue

from msldap_ops.privileged import as_list, attr, escape_filter_value, sid_string, table

TEMPLATE_ATTRIBUTES = MSADCertificateTemplate_ATTRS + [
	'displayName', 'pKIExpirationPeriod', 'pKIOverlapPeriod', 'msPKI-Minimal-Key-Size',
	'msPKI-Certificate-Policy', 'whenCreated', 'whenChanged',
]
CA_ATTRIBUTES = ['name', 'dNSHostName', 'certificateTemplates']
POLICY_ATTRIBUTES = ['msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink']
AGENT_OID = '1.3.6.1.4.1.311.20.2.1'
ENROLLMENT_RIGHT = '0e10c968-78fb-11d2-90d4-00c04f79dc55'

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
	reviews: Dict[str, dict] = field(default_factory=dict)
	linked_groups: List[str] = field(default_factory=list)
	policy_objects: List[str] = field(default_factory=list)
	policy_status: Optional[str] = None

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
	found = await _search(client, '(sAMAccountName=%s)' % escape_filter_value(sam), ['distinguishedName', 'msDS-PrincipalName'], client._tree)
	if not found:
		note = '%s\\%s is not in the connected domain, checked as a low privileged user' % (domain, sam)
		return 'low privileged users', fallback, note
	# sAMAccountName alone is only unique within a domain. A same-named local
	# account must never supply the token of a user bound through a trust.
	resolved_name = attr(found[0], 'msDS-PrincipalName')
	if len(found) != 1 or not isinstance(resolved_name, str) or resolved_name.casefold() != res[2:].casefold():
		note = 'could not verify %s in the connected domain, checked as a low privileged user' % res[2:]
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
	for info in templates:
		add_reviews(info)
	await check_issuance_policies(client, config, templates, tokengroups)
	return TemplateReport(templates, principal, tokengroups, note)


def add_reviews(info):
	"""Structural observations, kept apart from findings for the evaluated token."""
	from msldap_ops import acl
	t = info.template
	if t.allows_authentication() and not t.requires_manager_approval():
		version = int(t.Template_Schema_Version or 0)
		policies = as_list(t.RA_Application_Policies)
		if version == 1 or (version > 1 and t.RA_Signature == 1 and AGENT_OID in policies):
			info.reviews['ESC3 target'] = {'Reason': 'Accepts enrollment-agent requests; an agent certificate and suitable CA restrictions are still required.'}
	if t.nTSecurityDescriptor is None or 'ESC4' in info.vulns:
		return
	controls = set()
	owner = t.nTSecurityDescriptor.Owner
	if owner and not acl.is_privileged(str(owner)):
		controls.add(str(owner))
	for ace in (t.nTSecurityDescriptor.Dacl.aces if t.nTSecurityDescriptor.Dacl else []):
		if ace.AceFlags & AceFlags.INHERIT_ONLY_ACE:
			continue
		entry = acl.Entry(ace, str(ace.Sid), acl.GuidNames())
		if not entry.allow or acl.is_privileged(entry.sid):
			continue
		if {'FullControl', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner'} & set(entry.rights) or (
			'WriteProperty' in entry.rights and entry.object is None):
			controls.add(entry.sid)
	if controls:
		info.reviews['ESC4 ACL'] = {'Reason': 'Principals outside known privileged SID groups own or have allow ACEs for template control; denies, group membership and effective access need review.',
			'SIDs': sorted(controls)}


def enrollment_sids(sd):
	"""Applicable enrollment allow ACEs; return None if the DACL needs manual review.

	A deny or an unsupported ACE prevents a positive ESC13 finding. This deliberately
	avoids claiming effective access from an allow ACE in a more complex DACL.
	"""
	if sd is None or sd.Dacl is None:
		return None
	sids = set()
	for ace in sd.Dacl.aces:
		if ace.AceFlags & AceFlags.INHERIT_ONLY_ACE:
			continue
		if ace.AceType not in (ACEType.ACCESS_ALLOWED_ACE_TYPE, ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE):
			return None
		mask = int(ace.Mask)
		guid = getattr(ace, 'ObjectType', None)
		if (mask & 0x10000000 and guid is None) or (mask & 0x100 and (guid is None or str(guid).lower() == ENROLLMENT_RIGHT)):
			sids.add(str(ace.Sid))
	return sids


async def check_issuance_policies(client, config, infos, tokengroups):
	"""Resolve template issuance-policy OIDs to their LDAP group links (ESC13).

	The filter matches the bofhound preset, allowing its broader cached search to
	answer this read. No group memberships or CA endpoints are queried.
	"""
	from msldap_ops.hooks import QueryAborted
	wanted = [info for info in infos if attr(info.entry, 'msPKI-Certificate-Policy')]
	if not wanted:
		return
	try:
		entries = await _search(client, '(objectClass=msPKI-Enterprise-Oid)', POLICY_ATTRIBUTES, 'CN=OID,%s' % pki_base(config))
	except QueryAborted:
		raise
	except Exception as err:
		for info in wanted:
			info.policy_status = 'Unassessed: issuance-policy search failed.'
			info.reviews['ESC13 unassessed'] = {'Reason': 'Could not read issuance policy group links: %s' % err}
		return
	policies = {}
	objects = {}
	for entry in entries:
		for oid in as_list(attr(entry, 'msPKI-Cert-Template-OID')):
			policies.setdefault(oid, set()).update(as_list(attr(entry, 'msDS-OIDToGroupLink')))
			dn = entry.get('objectName') or attr(entry, 'distinguishedName')
			if dn:
				objects.setdefault(oid, set()).add(dn)
	token = set(tokengroups) | IMPLICIT_TOKEN_SIDS
	for info in wanted:
		oids = as_list(attr(info.entry, 'msPKI-Certificate-Policy'))
		missing = [oid for oid in oids if oid not in policies]
		if missing:
			info.reviews['ESC13 unassessed'] = {'Reason': 'Issuance policy OIDs were not returned; group links unassessed: %s' % ', '.join(missing)}
		info.policy_objects = sorted({dn for oid in oids for dn in objects.get(oid, ())})
		info.linked_groups = sorted({group for oid in oids for group in policies.get(oid, ())})
		if not info.linked_groups:
			info.policy_status = ('Unassessed: referenced issuance-policy objects were not returned.' if missing else
				'No msDS-OIDToGroupLink returned by LDAP for the referenced policies; ESC13 not established.')
			continue
		t = info.template
		enrollers = enrollment_sids(t.nTSecurityDescriptor)
		can_enroll = bool(token & enrollers) if enrollers is not None else False
		unrestricted = not t.requires_manager_approval() and not t.requires_authorized_signatures()
		if t.allows_authentication() and can_enroll and unrestricted:
			info.policy_status = 'Enrollment and linked-group prerequisites met for the evaluated token.'
			info.vulns['ESC13'] = {'SIDs': sorted(token & enrollers),
				'Reason': 'Users can enroll for client authentication and issuance policies link to groups: %s' % ', '.join(info.linked_groups)}
		else:
			reasons = []
			if t.nTSecurityDescriptor is None or t.nTSecurityDescriptor.Dacl is None:
				reasons.append('security descriptor or DACL not returned')
			elif enrollers is None:
				reasons.append('deny or unsupported ACEs require manual access review')
			elif not can_enroll:
				reasons.append('no applicable enrollment allow ACE for the evaluated token')
			if not t.allows_authentication():
				reasons.append('template does not allow client authentication')
			if t.requires_manager_approval():
				reasons.append('manager approval required')
			if t.requires_authorized_signatures():
				reasons.append('authorized signatures required')
			info.policy_status = 'ESC13 not established: %s.' % '; '.join(reasons)
			info.reviews['ESC13 policy'] = {'Reason': info.policy_status}


async def resolve_principals(client, info, cache=None):
	"""SID -> 'DOMAIN\\name' for the SIDs in the template's security descriptor."""
	if info.template.nTSecurityDescriptor is None:
		return {}
	if cache is not None:
		from msldap_ops import acl
		from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
		sd = info.template.nTSecurityDescriptor
		sd = SECURITY_DESCRIPTOR.from_bytes(sd) if isinstance(sd, bytes) else sd
		sids = [sd.Owner, sd.Group] + [ace.Sid for aces in (sd.Dacl, sd.Sacl) if aces for ace in aces.aces]
		return await acl.resolve(client, list(dict.fromkeys(str(sid) for sid in sids if sid is not None)), cache)
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
		reviews = {key.split(' ', 1)[0] for key in info.reviews} - info.vulns.keys()
		findings = [esc if esc in info.vulns else '%s [?]' % esc for esc in sorted(set(info.vulns) | reviews)]
		vulns = ', '.join(findings) if info.enabled else '-'
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
		add('Policy Objects', info.policy_objects or ['None returned'])
		add('Linked Groups', info.linked_groups or ['None returned'])
		if info.policy_status:
			add('ESC13 Check', info.policy_status)
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
	if info.reviews:
		lines.append('  Review points')
		for key, review in sorted(info.reviews.items()):
			lines.append('    [review] %-21s: %s' % (key, review['Reason']))
			for name in sorted(principals.get(sid, sid) for sid in review.get('SIDs', [])):
				lines.append('      Principal: %s' % name)
	return lines


def _date(value):
	if isinstance(value, datetime.datetime):
		return value.strftime('%Y-%m-%d %H:%M:%S')
	return value
