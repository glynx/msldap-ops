"""Uniform display of directory objects (cat, query).

Every object starts with a '---' line (a separator on the terminal) and its DN; attribute names
are aligned, values of multi-valued attributes are listed below each other.
"""

import re

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

MAX_NAME_WIDTH = 32

# Most specific classes first: computers and managed service accounts also inherit user.
TYPE_ICONS = (
	('msds-groupmanagedserviceaccount', '⚙️'), ('msds-managedserviceaccount', '⚙️'),
	('computer', '🖥️'), ('group', '👥'), ('user', '👤'), ('contact', '👤'),
	('organizationalunit', '🗂️'), ('grouppolicycontainer', '📜'),
	('trusteddomain', '🔗'), ('foreignsecurityprincipal', '🔗'),
	('pkienrollmentservice', '🏛️'), ('pkicertificatetemplate', '📜'),
	('certificationauthority', '🔐'), ('dnszone', '🌐'), ('dnsnode', '📍'),
	('domaindns', '🌐'), ('domain', '🌐'), ('builtindomain', '📁'), ('container', '📁'),
)


def object_icon(classes):
	"""Icon for the most specific known objectClass, or a neutral object icon."""
	classes = [classes] if isinstance(classes, str) else classes or []
	known = {name.lower() for name in classes}
	return next((icon for name, icon in TYPE_ICONS if name in known), '📄')


def object_classes(attributes):
	return next((value for name, value in attributes.items() if name.lower() == 'objectclass'), [])


def object_metadata(attributes):
	return {name.lower(): value for name, value in attributes.items()
		if name.lower() in ('objectclass', 'useraccountcontrol') and value is not None}


def account_disabled(attributes):
	"""True/False for a known ACCOUNTDISABLE flag; None when the status is unknown."""
	value = next((value for name, value in attributes.items() if name.lower() == 'useraccountcontrol'), None)
	if isinstance(value, list):
		value = value[0] if value else None
	try:
		return bool(int(value) & 0x2)
	except (TypeError, ValueError):
		return None


def object_label(name, metadata=None, root=False):
	"""Shared Rich label for ls/map/tree; absent metadata adds no decoration."""
	from rich.text import Text
	metadata = metadata or {}
	classes = object_classes(metadata)
	disabled = account_disabled(metadata) is True
	label = '%s %s' % (object_icon(classes), name) if classes else name
	if disabled:
		label += ' [disabled]'
	return Text(label, style='bright_black' if disabled else ('bold' if root else ''))


def value_str(name, value):
	if isinstance(value, SECURITY_DESCRIPTOR):
		return value.to_sddl()
	if isinstance(value, bytes):
		if name.lower() == 'ntsecuritydescriptor':
			try:
				return SECURITY_DESCRIPTOR.from_bytes(value).to_sddl()
			except Exception:
				pass
		return value.hex()
	return str(value)


def cached_note(stored):
	"""Suffix for output that comes from the query cache; stored: datetime or None."""
	return '  (from cache: %s)' % stored.strftime('%Y-%m-%d %H:%M') if stored is not None else ''


def record_lines(dn, attributes, cached_at=None, icon=None, disabled=False):
	lines = ['---', 'DN: %s%s%s%s' % (icon + ' ' if icon else '', dn,
		' [disabled]' if disabled else '', cached_note(cached_at))]
	if not attributes:
		lines.append('  (no attributes returned)')
		return lines
	width = min(max(len(name) for name in attributes) + 1, MAX_NAME_WIDTH)
	for name, value in attributes.items():
		values = value if isinstance(value, list) else [value]
		texts = [value_str(name, v) for v in values] or ['']
		label = '%s:' % name
		pad = ' ' * (width + 1)
		first = True
		for text in texts:
			for part in text.splitlines() or ['']:
				if first:
					lines.append('  %s %s' % (label.ljust(width), part) if len(label) <= width else '  %s %s' % (label, part))
					first = False
				else:
					lines.append('  %s %s' % (pad[:-1], part))
	return lines


def search_error(err, base):
	"""Readable message for a failed search: result name, the DN and the closest existing object."""
	name = getattr(err, 'resultname', None)
	if name is None:
		return 'Search failed: %s' % err
	diag = getattr(err, 'diagnostic_message', b'')
	if isinstance(diag, bytes):
		diag = diag.decode('utf-8', 'replace')
	diag = diag.replace('\x00', '').strip()
	if name == 'noSuchObject':
		match = re.search(r"best match of:\s*'([^']*)'", diag)
		text = 'No such object: %s' % base
		if match and match.group(1):
			text += '\n  closest existing object: %s' % match.group(1)
		return text
	return 'Search failed (%s): %s' % (name, ' '.join(diag.split()))


def count_line(n, cached_at=None):
	return '(%d object%s)%s' % (n, '' if n == 1 else 's', cached_note(cached_at))
