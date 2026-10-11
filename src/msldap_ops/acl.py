"""Readable ACLs: owner, DACL entries with decoded rights, object types and scope.

Rights that allow taking over the object are marked [!] when a principal outside the privileged
groups holds them: full control, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, reset
password, DCSync rights, writing member, servicePrincipalName, msDS-KeyCredentialLink,
msDS-AllowedToActOnBehalfOfOtherIdentity and similar attributes, adding oneself to a group. A non
privileged owner is marked as well (the owner can always rewrite the DACL).

Names of schema GUIDs come from winacl's tables, a built-in table of the attributes and classes that
matter for attacks and, for anything else (e.g. LAPS, whose GUIDs differ per forest), the schema
GUIDs that bofhound_collect stored in the query cache.
"""

import base64
import textwrap
import uuid

from winacl.dtyp.ace import (ADS_ACCESS_MASK, ACEType, AceFlags, ExtendedRightsGUID, MoreGUID, PropertySets,
	ValidatedWrites)
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

MARK = '[!]'

# attributes and classes (lDAPDisplayName) whose GUIDs are the same in every forest
SCHEMA_GUIDS = {
	'bf9679c0-0de6-11d0-a285-00aa003049e2': 'member',
	'f3a64788-5306-11d1-a9c5-0000f80367c1': 'servicePrincipalName',
	'5b47d60f-6090-40b2-9f37-2a4de88f3063': 'msDS-KeyCredentialLink',
	'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
	'800d94d7-b7a1-42a1-b14d-7cae1423d07f': 'msDS-AllowedToDelegateTo',
	'888eedd6-ce04-df40-b462-b8a50e41ba38': 'msDS-GroupMSAMembership',
	'e362ed86-b728-0842-b27d-2dea7a9df218': 'msDS-ManagedPassword',
	'bf967a68-0de6-11d0-a285-00aa003049e2': 'userAccountControl',
	'bf9679a8-0de6-11d0-a285-00aa003049e2': 'scriptPath',
	'bf967a0a-0de6-11d0-a285-00aa003049e2': 'pwdLastSet',
	'28630ebf-41d5-11d1-a9c1-0000f80367c1': 'lockoutTime',
	'bf967950-0de6-11d0-a285-00aa003049e2': 'description',
	'bf967a7f-0de6-11d0-a285-00aa003049e2': 'userCertificate',
	'00fbf30c-91fe-11d1-aebc-0000f80367c1': 'altSecurityIdentities',
	'f30e3bbe-9ff0-11d1-b603-0000f80367c1': 'gPLink',
	'f30e3bc1-9ff0-11d1-b603-0000f80367c1': 'gPOptions',
	'ea1dddc4-60ff-416e-8cc0-17cee534bce7': 'msPKI-Certificate-Name-Flag',
	'bf967aba-0de6-11d0-a285-00aa003049e2': 'user',
	'bf967a86-0de6-11d0-a285-00aa003049e2': 'computer',
	'bf967a9c-0de6-11d0-a285-00aa003049e2': 'group',
	'bf967aa5-0de6-11d0-a285-00aa003049e2': 'organizationalUnit',
	'bf967a8b-0de6-11d0-a285-00aa003049e2': 'container',
	'4828cc14-1437-45bc-9b07-ad6f015e5f28': 'inetOrgPerson',
	'5cb41ed0-0e4c-11d0-a286-00aa003049e2': 'contact',
	'7b8b558a-93a5-4af7-adca-e017e67f1057': 'msDS-GroupManagedServiceAccount',
	'ce206244-5827-4a86-ba1c-1c0c386c1b64': 'msDS-ManagedServiceAccount',
	'f30e3bc2-9ff0-11d1-b603-0000f80367c1': 'groupPolicyContainer',
}

# writing these attributes leads to code execution, credentials or delegation
RISKY_ATTRIBUTES = {
	'member', 'servicePrincipalName', 'msDS-KeyCredentialLink', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
	'msDS-AllowedToDelegateTo', 'msDS-GroupMSAMembership', 'userAccountControl', 'scriptPath',
	'altSecurityIdentities', 'gPLink', 'msPKI-Certificate-Name-Flag', 'Group Membership',
}
RISKY_EXTENDED_RIGHTS = {
	'Reset Password', 'Replicating Directory Changes', 'Replicating Directory Changes All',
	'Replicating Directory Changes In Filtered Set',
}
RISKY_VALIDATED_WRITES = {'Self-Membership'}

# principals that hold such rights by design: SYSTEM, Enterprise DCs, Administrators, Account
# Operators, and the domain groups Domain Admins, DCs, Schema/Enterprise Admins, (Enterprise) Key
# Admins, Enterprise read-only DCs (of any domain of the forest)
PRIVILEGED_SIDS = {'S-1-5-18', 'S-1-5-9', 'S-1-5-32-544', 'S-1-5-32-548'}
PRIVILEGED_RIDS = {'498', '512', '516', '518', '519', '526', '527'}
# SELF and CREATOR OWNER: rights of the object on itself / of its creator
SELF_SIDS = {'S-1-5-10', 'S-1-3-0'}

SCOPE_FILTERS = ('all', 'explicit', 'risky')


def is_privileged(sid):
	sid = str(sid).upper()
	if sid in PRIVILEGED_SIDS or sid in SELF_SIDS:
		return True
	return sid.startswith('S-1-5-21-') and sid.rsplit('-', 1)[1] in PRIVILEGED_RIDS


def schema_names_from_cache(cache):
	"""GUID -> name from cached searches that returned schemaIDGUID (bofhound_collect schema)."""
	names = {}
	if cache is None:
		return names
	for item in cache.queries.values():
		for entry in item['entries']:
			values = {t.lower(): v for t, v in entry['a']}
			guid, name = values.get('schemaidguid'), values.get('name') or values.get('ldapdisplayname')
			if guid and name:
				try:
					key = str(uuid.UUID(bytes_le=base64.b64decode(guid[0])))
					names[key] = base64.b64decode(name[0]).decode('utf-8', 'replace')
				except ValueError:
					continue
	return names


class GuidNames:
	def __init__(self, extra=None):
		self.extra = extra or {}

	def object_type(self, guid, right):
		"""Name of an ACE's ObjectType for the given kind of right."""
		if guid is None:
			return None
		guid = str(guid).lower()
		if right == 'extended':
			return ExtendedRightsGUID.get(guid) or MoreGUID.get(guid) or self.extra.get(guid) or guid
		if right == 'validated':
			return MoreGUID.get(guid) or ValidatedWrites.get(guid) or guid
		return SCHEMA_GUIDS.get(guid) or PropertySets.get(guid) or self.extra.get(guid) or MoreGUID.get(guid) or guid

	def class_name(self, guid):
		if guid is None:
			return None
		guid = str(guid).lower()
		return SCHEMA_GUIDS.get(guid) or self.extra.get(guid) or MoreGUID.get(guid) or guid


FULL_CONTROL = int(ADS_ACCESS_MASK.GENERIC_ALL)
GENERIC_WRITE = int(ADS_ACCESS_MASK.GENERIC_WRITE)
GENERIC_READ = int(ADS_ACCESS_MASK.GENERIC_READ)
GENERIC_EXECUTE = int(ADS_ACCESS_MASK.GENERIC_EXECUTE)

# single bits in display order: (bit, name)
BITS = [
	(0x00040000, 'WriteDacl'), (0x00080000, 'WriteOwner'), (0x00010000, 'Delete'), (0x00000040, 'DeleteTree'),
	(0x00000001, 'CreateChild'), (0x00000002, 'DeleteChild'), (0x00000020, 'WriteProperty'),
	(0x00000008, 'Self'), (0x00000100, 'ExtendedRight'), (0x00000010, 'ReadProperty'),
	(0x00000004, 'ListChildren'), (0x00000080, 'ListObject'), (0x00020000, 'ReadControl'),
	(0x01000000, 'AccessSystemSecurity'),
]
# generic rights as stored in the ACE (rare in AD, mapped by the DC)
GENERIC_BITS = [(0x10000000, 'GenericAll'), (0x40000000, 'GenericWrite'), (0x80000000, 'GenericRead'), (0x20000000, 'GenericExecute')]


def rights(mask):
	"""Names of the rights in an access mask, combined where AD has a name for the combination."""
	names = [name for bit, name in GENERIC_BITS if mask & bit]
	rest = mask & ~sum(bit for bit, _ in GENERIC_BITS)
	if rest & FULL_CONTROL == FULL_CONTROL:
		names.append('FullControl')
		rest &= ~FULL_CONTROL
	for combined, name in ((GENERIC_WRITE, 'GenericWrite'), (GENERIC_READ, 'GenericRead')):
		if rest & combined == combined:
			names.append(name)
			rest &= ~combined
	rest &= ~0x00100000  # SYNCHRONIZE, meaningless for directory objects
	names.extend(name for bit, name in BITS if rest & bit)
	return names


class Entry:
	"""One ACE, decoded."""

	def __init__(self, ace, principal, names):
		self.ace = ace
		self.sid = str(ace.Sid)
		self.principal = principal
		self.allow = ace.AceType in (ACEType.ACCESS_ALLOWED_ACE_TYPE, ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
		self.inherited = bool(ace.AceFlags & AceFlags.INHERITED_ACE)
		mask = int(ace.Mask)
		object_type = getattr(ace, 'ObjectType', None)
		inherited_type = getattr(ace, 'InheritedObjectType', None)
		self.rights = rights(mask)
		# what the ObjectType restricts: an extended right, a validated write or a property/class
		if object_type is not None:
			if mask & 0x100:
				kind = 'extended'
			elif mask & 0x8:
				kind = 'validated'
			else:
				kind = 'property'
			self.object = names.object_type(object_type, kind)
		else:
			self.object = None
		self.applies_to = names.class_name(inherited_type)
		self.scope = self._scope(ace.AceFlags)
		self.findings = self._findings(mask, object_type)

	def _scope(self, flags):
		this = not flags & AceFlags.INHERIT_ONLY_ACE
		children = bool(flags & AceFlags.CONTAINER_INHERIT_ACE)
		target = '%s objects' % self.applies_to if self.applies_to else 'descendants'
		if this and children:
			return 'this object and %s' % target if self.applies_to else 'this object and descendants'
		if children:
			return target
		return 'this object'

	def _findings(self, mask, object_type):
		"""Dangerous rights in this ACE (only allow ACEs)."""
		if not self.allow:
			return []
		found = []
		has = set(self.rights)
		if {'FullControl', 'GenericAll'} & has:
			found.append('FullControl')
		if 'GenericWrite' in has:
			found.append('GenericWrite')
		for right in ('WriteDacl', 'WriteOwner'):
			if right in has:
				found.append(right)
		if 'WriteProperty' in has and 'GenericWrite' not in has and 'FullControl' not in has:
			if object_type is None:
				found.append('WriteProperty (all)')
			elif self.object in RISKY_ATTRIBUTES:
				found.append('Write %s' % self.object)
		if 'ExtendedRight' in has and 'FullControl' not in has:
			if object_type is None:
				found.append('AllExtendedRights')
			elif self.object in RISKY_EXTENDED_RIGHTS:
				found.append(self.object)
		if 'Self' in has and object_type is not None and self.object in RISKY_VALIDATED_WRITES:
			found.append('AddSelf')
		return found

	@property
	def risky(self):
		return bool(self.findings) and not is_privileged(self.sid)


async def resolve(client, sids):
	"""SID -> 'DOMAIN\\name' (msldap's resolv_sid: well-known SIDs without a query, others with
	one cached search each)."""
	names = {}
	for sid in sids:
		try:
			domain, user, err = await client.resolv_sid(sid)
		except Exception:
			domain, user, err = None, None, True
		if err is None and user not in (None, '???'):
			names[sid] = '%s\\%s' % (domain, user) if domain else user
		else:
			names[sid] = sid
	return names


async def collect(client, dn, cache=None):
	"""(security descriptor, entries, principal names) of one object; one base search with the
	SD flags control (owner, group, DACL) plus the SID lookups."""
	from msldap_ops.templates import sd_flags_control
	raw = None
	async for entry, err in client.pagedsearch('(objectClass=*)', ['nTSecurityDescriptor'], controls=[sd_flags_control()], tree=dn, search_scope=0):
		if err is not None:
			raise err
		raw = entry['attributes'].get('nTSecurityDescriptor')
	if raw is None:
		return None
	sd = raw if isinstance(raw, SECURITY_DESCRIPTOR) else SECURITY_DESCRIPTOR.from_bytes(raw)
	sids = []
	for sid in [sd.Owner, sd.Group] + [ace.Sid for ace in (sd.Dacl.aces if sd.Dacl else [])]:
		if sid is not None and str(sid) not in sids:
			sids.append(str(sid))
	principals = await resolve(client, sids)
	names = GuidNames(schema_names_from_cache(cache))
	entries = [Entry(ace, principals.get(str(ace.Sid), str(ace.Sid)), names) for ace in (sd.Dacl.aces if sd.Dacl else [])]
	return sd, entries, principals


def fit_widths(rows, indent, width, wrap_columns):
	"""Column widths that fit width, shrinking the wrap_columns (widest first) but not below
	their longest word; None if the table cannot fit that way."""
	ncols = len(rows[0])
	widths = [max(len(r[i]) for r in rows) for i in range(ncols)]
	if not width:
		return widths
	floor = [max((len(w) for r in rows for w in r[i].split()), default=0) if i in wrap_columns else widths[i]
		for i in range(ncols)]
	excess = len(indent) + sum(widths) + 2 * (ncols - 1) - width
	while excess > 0:
		candidates = [i for i in wrap_columns if widths[i] > floor[i]]
		if not candidates:
			return None
		widest = max(candidates, key=lambda i: widths[i] - floor[i])
		widths[widest] -= 1
		excess -= 1
	return widths


def table(rows, indent='  ', widths=None):
	"""Aligned columns; cells longer than their column wrap onto further lines of the row."""
	widths = widths or [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
	lines = []
	for row in rows:
		cells = [textwrap.wrap(cell, widths[i], break_on_hyphens=False) or [''] if len(cell) > widths[i] else [cell]
			for i, cell in enumerate(row)]
		for n in range(max(len(c) for c in cells)):
			parts = [(c[n] if n < len(c) else '').ljust(widths[i]) for i, c in enumerate(cells)]
			lines.append((indent + '  '.join(parts)).rstrip())
	return lines


def blocks(entries_rows, indent='  ', width=None):
	"""One block per entry, for terminals too narrow for the table:
	    allow  NORTH\\jon.snow
	           WriteProperty: member (this object)  [!] Write member"""
	lines = []
	for access, principal, rights_text, obj, scope, finding in entries_rows:
		lines.append('%s%-12s  %s' % (indent, access, principal))
		detail = '%s%s (%s)' % (rights_text, ': %s' % obj if obj != '-' else '', scope)
		if finding:
			detail += '  ' + finding
		pad = indent + ' ' * 14
		lines.extend(textwrap.wrap(detail, max((width or 0) - len(pad), 30), initial_indent=pad,
			subsequent_indent=pad + '  ', break_on_hyphens=False) if width else [pad + detail])
	return lines


def format_acl(dn, sd, entries, principals, show='all', width=None):
	lines = ['ACL of %s' % dn]
	owner = str(sd.Owner) if sd.Owner is not None else None
	if owner:
		mark = '  %s owner is not privileged (can rewrite the DACL)' % MARK if not is_privileged(owner) else ''
		lines.append('  Owner: %s%s' % (principals.get(owner, owner), mark))
	if sd.Group is not None:
		lines.append('  Group: %s' % principals.get(str(sd.Group), str(sd.Group)))
	if sd.Dacl is None:
		lines.append('  DACL: none (not returned, or no DACL: everyone has full access)')
		return lines
	protected = bool(int(sd.Control) & 0x1000)  # SE_DACL_PROTECTED
	inherited = sum(1 for e in entries if e.inherited)
	lines.append('  DACL: %d entries, %d inherited%s' % (len(entries), inherited,
		', inheritance disabled' if protected else ''))
	shown = [e for e in entries if show == 'all' or (show == 'explicit' and not e.inherited) or (show == 'risky' and e.risky)]
	if not shown:
		lines.append('  (no %s entries)' % ('risky' if show == 'risky' else 'explicit'))
		return lines
	# denies first (as Windows evaluates them), then explicit before inherited, then by principal
	shown.sort(key=lambda e: (e.allow, e.inherited, e.principal.lower()))
	rows = [('Access', 'Principal', 'Rights', 'Object', 'Applies to', '')]
	for e in shown:
		access = ('allow' if e.allow else 'deny') + (' (inh.)' if e.inherited else '')
		finding = '%s %s' % (MARK, ', '.join(e.findings)) if e.risky else ''
		rows.append((access, e.principal, ', '.join(e.rights), e.object or '-', e.scope, finding))
	lines.append('')
	# Principal, Rights, Object, Applies to and the finding wrap at word boundaries when the
	# terminal is too narrow; if even that does not fit, one block per entry
	widths = fit_widths(rows, '  ', width, wrap_columns=(1, 2, 3, 4, 5))
	if widths is None:
		lines.extend(blocks(rows[1:], width=width))
	else:
		lines.extend(table(rows, widths=widths))
	return lines
