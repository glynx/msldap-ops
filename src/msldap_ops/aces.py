"""Building and removing ACEs for grant/revoke: high-level right names to DACL entries.

A right maps to one or more ACEs, each as an SDDL ACE string parsed by winacl. Plain rights (full
control, GenericWrite, ...) are 'A' ACEs; rights bound to an attribute or extended right ('OA')
carry the object GUID. grant appends the ACEs to the DACL, revoke removes the matching ones (same
type, SID, mask and object GUID); the whole security descriptor is written back, and the hook's
undo restores the previous one.
"""

from winacl.dtyp.ace import ACE, ACEType
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

# name -> list of (access mask hex, object GUID or None). Several ACEs for DCSync.
RIGHTS = {
	'fullcontrol': [('0xf01ff', None)],
	'genericall': [('0xf01ff', None)],
	'genericwrite': [('0x20028', None)],
	'writedacl': [('0x40000', None)],
	'writeowner': [('0x80000', None)],
	'allextendedrights': [('0x100', None)],
	'resetpassword': [('0x100', '00299570-246d-11d0-a768-00aa006e0529')],
	'writemembers': [('0x8', 'bf9679c0-0de6-11d0-a285-00aa003049e2')],
	'writespn': [('0x20', 'f3a64788-5306-11d1-a9c5-0000f80367c1')],
	'writekeycredential': [('0x20', '5b47d60f-6090-40b2-9f37-2a4de88f3063')],
	'rbcd': [('0x20', '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79')],
	'dcsync': [
		('0x100', '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),  # DS-Replication-Get-Changes
		('0x100', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'),  # DS-Replication-Get-Changes-All
	],
}

RIGHT_NAMES = sorted(RIGHTS)


def ace_strings(sid, right):
	"""SDDL ACE strings for a right granted to a SID, or None if the right is unknown."""
	entries = RIGHTS.get(right.lower())
	if entries is None:
		return None
	strings = []
	for mask, guid in entries:
		if guid is None:
			strings.append('(A;;%s;;;%s)' % (mask, sid))
		else:
			strings.append('(OA;;%s;%s;;%s)' % (mask, guid, sid))
	return strings


def _key(ace):
	"""Identity of an ACE for matching on revoke: type, SID, mask, object GUID."""
	return (
		ace.AceType,
		str(ace.Sid).upper(),
		int(ace.Mask),
		str(ace.ObjectType).lower() if getattr(ace, 'ObjectType', None) is not None else None,
	)


ALLOW_TYPES = (ACEType.ACCESS_ALLOWED_ACE_TYPE, ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE)


def grant(sd_bytes, sid, right):
	"""Returns the security descriptor bytes with the ACEs of the right added for the SID, and the
	number added (0 if the right is unknown or every ACE was already present)."""
	strings = ace_strings(sid, right)
	if strings is None:
		return None, 0
	sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
	present = {_key(a) for a in sd.Dacl.aces}
	added = 0
	for text in strings:
		ace = ACE.from_sddl(text)
		if _key(ace) in present:
			continue
		sd.Dacl.aces.append(ace)
		present.add(_key(ace))
		added += 1
	return sd.to_bytes(), added


def revoke(sd_bytes, sid, right):
	"""Returns the security descriptor bytes with the allow ACEs matching the right and SID removed,
	and the number removed."""
	strings = ace_strings(sid, right)
	if strings is None:
		return None, 0
	targets = {_key(ACE.from_sddl(text)) for text in strings}
	sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
	keep, removed = [], 0
	for ace in sd.Dacl.aces:
		if ace.AceType in ALLOW_TYPES and _key(ace) in targets:
			removed += 1
		else:
			keep.append(ace)
	sd.Dacl.aces = keep
	return sd.to_bytes(), removed


def rbcd_with(sd_bytes, sid):
	"""Security-descriptor bytes for msDS-AllowedToActOnBehalfOfOtherIdentity with an allow-all ACE
	for the SID added (a new descriptor if there was none, the SID not duplicated)."""
	from winacl.dtyp.acl import ACL
	from winacl.dtyp.sid import SID
	if sd_bytes:
		sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
		if sd.Dacl is None:
			sd.Dacl = _empty_acl()
	else:
		sd = SECURITY_DESCRIPTOR()
		sd.Owner = SID.from_string('S-1-5-32-544')
		sd.Group = None
		sd.Sacl = None
		sd.Dacl = _empty_acl()
		# SE_DACL_PRESENT | SE_SELF_RELATIVE
		sd.Control = 0x8004
	if any(str(a.Sid).upper() == sid.upper() for a in sd.Dacl.aces):
		return sd.to_bytes()
	sd.Dacl.aces.append(ACE.from_sddl('(A;;0xf01ff;;;%s)' % sid))
	return sd.to_bytes()


def _empty_acl():
	from winacl.dtyp.acl import ACL
	acl = ACL()
	acl.AclRevision = 4
	acl.Sbz1 = 0
	acl.Sbz2 = 0
	acl.aces = []
	return acl
