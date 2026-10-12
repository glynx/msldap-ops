"""Overview of Kerberos delegation: unconstrained, constrained (with/without protocol transition)
and resource-based (RBCD).

Each kind is one LDAP query:

- unconstrained: userAccountControl TRUSTED_FOR_DELEGATION (0x80000), excluding domain controllers
  (SERVER_TRUST_ACCOUNT), which hold it by design
- constrained: msDS-AllowedToDelegateTo is set; TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (0x1000000)
  distinguishes "with protocol transition" (any authentication protocol) from Kerberos-only
- rbcd: msDS-AllowedToActOnBehalfOfOtherIdentity is set; its DACL names who may act on the object
"""

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap_ops.privileged import as_list, attr, sid_string

TRUSTED_FOR_DELEGATION = 0x80000
TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
SERVER_TRUST_ACCOUNT = 0x2000

KINDS = ('unconstrained', 'constrained', 'rbcd')

# kind -> (filter, attributes)
QUERIES = {
	# TRUSTED_FOR_DELEGATION set, SERVER_TRUST_ACCOUNT (domain controllers) excluded
	'unconstrained': (
		'(&(userAccountControl:1.2.840.113556.1.4.803:=%d)(!(userAccountControl:1.2.840.113556.1.4.803:=%d)))'
		% (TRUSTED_FOR_DELEGATION, SERVER_TRUST_ACCOUNT),
		['sAMAccountName', 'userAccountControl', 'objectSid'],
	),
	'constrained': (
		'(msDS-AllowedToDelegateTo=*)',
		['sAMAccountName', 'userAccountControl', 'msDS-AllowedToDelegateTo'],
	),
	'rbcd': (
		'(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
		['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
	),
}


def _name(entry):
	return attr(entry, 'sAMAccountName') or entry['objectName']


def unconstrained_row(entry):
	return {'name': _name(entry), 'dn': entry['objectName']}


def constrained_row(entry):
	uac = int(attr(entry, 'userAccountControl') or 0)
	return {
		'name': _name(entry),
		'dn': entry['objectName'],
		'protocol_transition': bool(uac & TRUSTED_TO_AUTH_FOR_DELEGATION),
		'targets': [str(t) for t in as_list(attr(entry, 'msDS-AllowedToDelegateTo'))],
	}


def rbcd_row(entry):
	sd = attr(entry, 'msDS-AllowedToActOnBehalfOfOtherIdentity')
	if isinstance(sd, bytes):
		sd = SECURITY_DESCRIPTOR.from_bytes(sd)
	allowed = []
	if sd is not None and getattr(sd, 'Dacl', None) is not None:
		allowed = [str(ace.Sid) for ace in sd.Dacl.aces]
	return {'name': _name(entry), 'dn': entry['objectName'], 'allowed': allowed}


ROW = {'unconstrained': unconstrained_row, 'constrained': constrained_row, 'rbcd': rbcd_row}


def section(title, rows):
	heading = '%s (%d)' % (title, len(rows))
	return [heading] + ([] if rows else ['  (none)'])


def format_unconstrained(rows):
	lines = section('Unconstrained delegation', rows)
	for row in sorted(rows, key=lambda r: r['name'].lower()):
		lines.append('  %s' % row['name'])
	return lines


def format_constrained(rows):
	lines = section('Constrained delegation', rows)
	for row in sorted(rows, key=lambda r: r['name'].lower()):
		mode = 'protocol transition' if row['protocol_transition'] else 'Kerberos only'
		lines.append('  %s  [%s]' % (row['name'], mode))
		for target in row['targets']:
			lines.append('      -> %s' % target)
	return lines


def format_rbcd(rows, names=None):
	names = names or {}
	lines = section('Resource-based constrained delegation', rows)
	for row in sorted(rows, key=lambda r: r['name'].lower()):
		lines.append('  %s' % row['name'])
		for sid in row['allowed']:
			lines.append('      <- %s' % names.get(sid, sid))
	return lines


FORMAT = {'unconstrained': format_unconstrained, 'constrained': format_constrained, 'rbcd': format_rbcd}
