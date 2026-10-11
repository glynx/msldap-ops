"""Uniform display of directory objects (cat, query).

Every object starts with a '---' line (a separator on the terminal) and its DN; attribute names
are aligned, values of multi-valued attributes are listed below each other.
"""

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


def count_line(n):
	return '(%d object%s)' % (n, '' if n == 1 else 's')
