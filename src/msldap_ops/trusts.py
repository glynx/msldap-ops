"""Readable domain trust records, keeping the configured attributes explicit."""

from msldap.ldap_objects.adtrust import TrustAttributes, TrustDirection, TrustType

TYPE_NAMES = {'DOWNLEVEL': 'Windows NT', 'UPLEVEL': 'Active Directory', 'MIT': 'MIT Kerberos',
	'DCE': 'DCE', 'AAD': 'Azure AD'}


def enum_name(value, enum_type):
	if value is None:
		return '(not returned)'
	try:
		return enum_type(value).name
	except (ValueError, TypeError):
		return str(value)


def attributes(value):
	if value is None:
		return '(not returned)'
	value = int(value)
	names = [flag.name for flag in TrustAttributes if value & flag.value]
	known = sum(flag.value for flag in TrustAttributes)
	if value & ~known:
		names.append('0x%x' % (value & ~known))
	return ', '.join(names) or '(none)'


def format_trusts(entries, source):
	lines = ['Trusts from %s (%d)' % (source, len(entries))]
	if not entries:
		return lines + ['  (none)']
	for index, entry in enumerate(sorted(entries, key=lambda e: (e.trustPartner or e.name or '').lower())):
		if index:
			lines.append('')
		kind = enum_name(entry.trustType, TrustType)
		direction = enum_name(entry.trustDirection, TrustDirection)
		lines.append('  %s' % (entry.trustPartner or entry.name or '(unknown domain)'))
		lines.extend([
			'    NetBIOS:    %s' % (entry.flatName or '(not returned)'),
			'    Direction:  %s' % direction.capitalize(),
			'    Type:       %s' % TYPE_NAMES.get(kind, kind),
			'    Attributes: %s' % attributes(entry.trustAttributes),
			'    SID:        %s' % (entry.securityIdentifier or '(not returned)'),
		])
	return lines
