from winacl.dtyp.ace import ACEType
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops import aces

BASE = 'O:S-1-5-32-544G:S-1-5-32-544D:(A;;0xf01ff;;;S-1-5-32-544)'
SID = 'S-1-5-21-1-2-3-1105'


def sd_bytes(sddl=BASE):
	return SECURITY_DESCRIPTOR.from_sddl(sddl).to_bytes()


def aces_of(b):
	return SECURITY_DESCRIPTOR.from_bytes(b).Dacl.aces


def test_grant_plain_right():
	new, n = aces.grant(sd_bytes(), SID, 'genericall')
	assert n == 1
	ace = aces_of(new)[-1]
	assert ace.AceType == ACEType.ACCESS_ALLOWED_ACE_TYPE and str(ace.Sid) == SID and int(ace.Mask) == 0xf01ff


def test_grant_dcsync_adds_two_object_aces():
	new, n = aces.grant(sd_bytes(), SID, 'dcsync')
	assert n == 2
	guids = {str(a.ObjectType).lower() for a in aces_of(new)[-2:]}
	assert guids == {'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'}


def test_grant_is_idempotent():
	new, n = aces.grant(sd_bytes(), SID, 'dcsync')
	again, n2 = aces.grant(new, SID, 'dcsync')
	assert n2 == 0 and len(aces_of(again)) == len(aces_of(new))


def test_revoke_removes_only_the_matching_aces():
	granted, _ = aces.grant(sd_bytes(), SID, 'dcsync')
	before = len(aces_of(granted))
	revoked, n = aces.revoke(granted, SID, 'dcsync')
	assert n == 2 and len(aces_of(revoked)) == before - 2
	# the original admin full-control ACE is kept
	assert any(str(a.Sid) == 'S-1-5-32-544' for a in aces_of(revoked))


def test_revoke_nothing_present():
	_, n = aces.revoke(sd_bytes(), SID, 'resetpassword')
	assert n == 0


def test_unknown_right():
	assert aces.grant(sd_bytes(), SID, 'bogus') == (None, 0)
	assert aces.ace_strings(SID, 'bogus') is None
