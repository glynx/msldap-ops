"""CA discovery and directory-object ACL review using LDAP only.

The enrollment-service object's AD security descriptor is distinct from the CA service security
retrieved through RPC/registry. It cannot establish ManageCA/ManageCertificates or ESC7.
See https://github.com/ly4k/Certipy/blob/master/certipy/commands/ca.py (get_config).
"""

from msldap_ops import acl, templates
from msldap_ops.privileged import as_list, attr, escape_filter_value

ATTRIBUTES = templates.CA_ATTRIBUTES + ['nTSecurityDescriptor', 'msPKI-Enrollment-Servers']
REVIEW_MARK = '[review]'
DIRECT_CHECKS = [
	'  Not checked (requires direct CA access)',
	'    ESC6: CA policy/EditFlags (EDITF_ATTRIBUTESUBJECTALTNAME2); query CA RPC/registry.',
	'    ESC7: CA service ManageCA/ManageCertificates permissions; query CA RPC/registry.',
	'    ESC8: Web Enrollment and NTLM/EPA settings; check the actual HTTP(S) endpoint.',
	'    ESC11: RPC request encryption settings; query the CA.',
]


async def collect(client, name=None):
	base = 'CN=Enrollment Services,%s' % templates.pki_base(client._get_configuration_nc())
	query = '(objectClass=pKIEnrollmentService)'
	if name:
		value = escape_filter_value(name)
		query = '(&(objectClass=pKIEnrollmentService)(|(name=%s)(dNSHostName=%s)))' % (value, value)
	entries = await templates._search(client, query, ATTRIBUTES, base, controls=[templates.sd_flags_control()])
	return sorted(entries, key=lambda e: str(attr(e, 'name') or e['objectName']).lower())


async def detail_lines(client, entry, cache=None, width=None):
	name = attr(entry, 'name') or entry['objectName']
	lines = ['CA %s' % name]
	def add(label, values):
		for index, value in enumerate(as_list(values) or ['(not returned)']):
			lines.append('  %-28s: %s' % (label if index == 0 else '', value))

	add('DNS Host Name', attr(entry, 'dNSHostName'))
	add('LDAP Object', entry['objectName'])
	add('Published Templates', sorted(as_list(attr(entry, 'certificateTemplates')), key=str.lower))
	urls = attr(entry, 'msPKI-Enrollment-Servers')
	if urls:
		add('Advertised Enrollment Servers', urls)
		lines.append('  Note: advertised enrollment URLs are LDAP metadata; reachability and authentication are not checked.')
	lines.append('  Permissions (AD enrollment-service object)')
	try:
		result = await acl.decode(client, attr(entry, 'nTSecurityDescriptor'), cache)
	except Exception as e:
		lines.append('    Cannot decode the security descriptor: %s' % e)
		result = None
	if result is None:
		lines.append('    Security descriptor unavailable; permissions not assessed.')
	else:
		# Reuse the directory ACL decoder: CA-service access masks have different meanings.
		acl_lines = acl.format_acl(entry['objectName'], *result, width=width - 2 if width else None,
			finding_marker=REVIEW_MARK)
		lines.extend('  ' + line for line in acl_lines[1:])
		lines.append('  Note: %s marks directory ACL review points, not confirmed effective access or ESC7.' % REVIEW_MARK)
	lines.extend(DIRECT_CHECKS)
	return lines
