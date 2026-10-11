"""Uniform display of directory objects (cat, query).

Every object starts with a '---' line (a separator on the terminal) and its DN; attribute names
are aligned, values of multi-valued attributes are listed below each other.
"""

import re

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

MAX_NAME_WIDTH = 32


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


def record_lines(dn, attributes):
	lines = ['---', 'DN: %s' % dn]
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


def count_line(n):
	return '(%d object%s)' % (n, '' if n == 1 else 's')
