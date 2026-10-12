"""LDAP-only review of LAPS read-related ACEs, without reading password attributes."""

import uuid
from dataclasses import dataclass
from typing import Optional

from winacl.dtyp.ace import ACEType, AceFlags

from msldap_ops import acl, laps, presets

SECTIONS = (
	('Legacy LAPS', ('ms-Mcs-AdmPwd',)),
	('Windows LAPS (clear text)', ('msLAPS-Password',)),
	('Windows LAPS (encrypted values)', (
		'msLAPS-EncryptedPassword', 'msLAPS-EncryptedPasswordHistory',
		'msLAPS-EncryptedDSRMPassword', 'msLAPS-EncryptedDSRMPasswordHistory',
	)),
)
PASSWORD_ATTRIBUTES = tuple(name for _, names in SECTIONS for name in names)
SCHEMA_ATTRIBUTES = ['lDAPDisplayName', 'schemaIDGUID', 'attributeSecurityGUID', 'searchFlags']
COMPUTER_ATTRIBUTES = ['cn', 'sAMAccountName', 'nTSecurityDescriptor']
SUPPORTED_ACES = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE, ACEType.ACCESS_DENIED_ACE_TYPE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
}


def guid(value):
	if isinstance(value, bytes):
		return str(uuid.UUID(bytes_le=value))
	return str(uuid.UUID(str(value)))


@dataclass(frozen=True)
class Attribute:
	name: str
	guid: str
	property_set: Optional[str]
	confidential: Optional[bool]


async def schema(client):
	"""Resolve schema GUIDs; a None value marks a found object with unusable metadata."""
	base = presets.naming_contexts(client._serverinfo, client._tree)['schema']
	query = '(&(objectClass=attributeSchema)(|%s))' % ''.join(
		'(lDAPDisplayName=%s)' % name for name in PASSWORD_ATTRIBUTES)
	attributes = {}
	async for entry, err in client.pagedsearch(query, SCHEMA_ATTRIBUTES, tree=base):
		if err is not None:
			raise err
		name = laps._attr(entry, 'lDAPDisplayName')
		if not isinstance(name, str) or name.lower() not in {n.lower() for n in PASSWORD_ATTRIBUTES}:
			continue
		attributes[name.lower()] = None
		try:
			attribute_guid = guid(laps._attr(entry, 'schemaIDGUID'))
			property_set = laps._attr(entry, 'attributeSecurityGUID')
			property_set = guid(property_set) if property_set else None
			flags = laps._attr(entry, 'searchFlags')
			confidential = bool(int(flags) & 0x80) if flags is not None else None
		except (ValueError, TypeError, AttributeError):
			continue  # Keep the object distinct from a schema attribute not returned at all.
		attributes[name.lower()] = Attribute(name, attribute_guid, property_set, confidential)
	return attributes


def schema_status(attributes):
	"""One forest-wide explanation when there is no usable LAPS schema metadata."""
	if attributes:
		return [
			'LAPS schema objects were found, but their required metadata is unreadable or invalid.',
			'Permissions unassessed.',
		]
	return [
		'No LAPS password schema attributes were returned by LDAP.',
		'Without these schema extensions, neither legacy nor Windows LAPS can store passwords',
		'in Active Directory anywhere in this forest.',
		'An empty search can also mean limited schema visibility; permissions unassessed.',
	]


def components(entry, attribute):
	"""Read-related components of one applicable ACE; this is not an access check."""
	ace = entry.ace
	if ace.AceType not in SUPPORTED_ACES or ace.AceFlags & AceFlags.INHERIT_ONLY_ACE:
		return []
	object_type = getattr(ace, 'ObjectType', None)
	if object_type is not None and str(object_type).lower() not in (attribute.guid, attribute.property_set):
		return []
	mask = int(ace.Mask)
	parts = []
	if mask & (0x10 | 0x80000000 | 0x10000000):
		parts.append('ReadProperty')
	if attribute.confidential is not False and mask & (0x100 | 0x10000000):
		parts.append('ControlAccess')
	return parts


async def detail_lines(client, entry, attributes, cache=None, width=None):
	dn = entry['objectName']
	lines = ['LAPS permissions of %s' % dn]
	if not any(attributes.values()):
		return lines + ['  ' + line for line in schema_status(attributes)], False
	try:
		result = await acl.decode(client, laps._attr(entry, 'nTSecurityDescriptor'), cache)
	except Exception as err:
		return lines + ['  Permissions unassessed: %s' % err], False
	if result is None or result[0].Dacl is None:
		return lines + ['  DACL missing or unavailable; permissions unassessed.'], False
	sd, entries, principals, _ = result
	if sd.Owner is not None:
		owner = str(sd.Owner)
		lines.append('  Owner: %s' % principals.get(owner, owner))
	lines.append('  ACL review only; allows and denies are shown separately, in DACL order.')
	lines.append('  Confidential attributes require ReadProperty AND ControlAccess.')
	lines.append('  Group membership and effective access are not evaluated; LAPS use is not inferred.')
	lines.append('  Encrypted-value read access does not establish decryption permission.')
	if any(e.ace.AceType not in SUPPORTED_ACES for e in entries):
		lines.append('  Unsupported ACE types are not assessed.')
	assessed = bool(attributes) and all(e.ace.AceType in SUPPORTED_ACES for e in entries)
	for title, names in SECTIONS:
		lines.extend(['', '  %s' % title])
		if not any(name.lower() in attributes for name in names):
			lines.append('    No schema attributes returned; this forest may lack this LAPS schema extension.')
			continue
		for name in names:
			attribute = attributes.get(name.lower())
			if attribute is None:
				status = ('schema object found, but metadata unreadable or invalid' if name.lower() in attributes
					else 'schema attribute not returned')
				lines.append('    %s: %s; unassessed' % (name, status))
				if name.lower() in attributes:
					assessed = False
				continue
			lines.append('    %s' % name)
			if attribute.confidential is None:
				lines.append('      Confidential flag unavailable; requirements unassessed.')
				assessed = False
			elif not attribute.confidential:
				lines.append('      Not confidential in this schema; ControlAccess is not required.')
			rows = []
			for e in entries:
				parts = components(e, attribute)
				if not parts:
					continue
				access = ('allow' if e.allow else 'deny') + (' (inh.)' if e.inherited else '')
				object_type = getattr(e.ace, 'ObjectType', None)
				restriction = ('all attributes' if object_type is None else
					'property set' if str(object_type).lower() == attribute.property_set else attribute.name)
				rows.append((access, e.principal, ', '.join(parts), restriction, e.scope, ''))
			if not rows:
				lines.append('      (no matching read-related ACEs)')
			else:
				table = [('Access', 'Principal', 'Components', 'Restriction', 'Applies to', '')] + rows
				widths = acl.fit_widths(table, '      ', width, wrap_columns=(1, 2, 3, 4, 5))
				lines.extend(acl.blocks(rows, indent='      ', width=width) if widths is None else
					acl.table(table, indent='      ', widths=widths))
	return lines, assessed


async def collect_computers(client, target, current_dn):
	from msldap_ops.templates import sd_flags_control
	base, query, scope = laps.search_target(target, current_dn, client._tree)
	entries = []
	async for entry, err in client.pagedsearch(query, COMPUTER_ATTRIBUTES,
		controls=[sd_flags_control()], tree=base, search_scope=scope):
		if err is not None:
			raise err
		entries.append(entry)
	return sorted(entries, key=lambda e: e['objectName'].lower())
