"""Directory navigation: DN handling, path resolution, completion and the tree of known DNs.

The known DNs come from the query cache's DN index, i.e. every object any command has seen so far.
"""

import fnmatch
import re

from prompt_toolkit.completion import Completer, Completion


def split_dn(dn):
	"""RDNs of a DN; escaped commas (CN=Doe\\, John) do not split."""
	rdns, current, escaped = [], [], False
	for ch in dn:
		if escaped:
			current.append(ch)
			escaped = False
		elif ch == '\\':
			current.append(ch)
			escaped = True
		elif ch == ',':
			rdns.append(''.join(current).strip())
			current = []
		else:
			current.append(ch)
	if current or rdns:
		rdns.append(''.join(current).strip())
	return [r for r in rdns if r]


def join_dn(rdns):
	return ','.join(rdns)


def parent_dn(dn):
	rdns = split_dn(dn)
	return join_dn(rdns[1:]) if len(rdns) > 1 else None


def normalize(dn):
	return join_dn(split_dn(dn)).lower()


def is_under(dn, base):
	"""dn equals base or lies below it (RDN-wise, case-insensitive)."""
	d, b = split_dn(dn.lower()), split_dn(base.lower())
	return len(d) >= len(b) and d[len(d) - len(b):] == b


def naming_context_of(dn, naming_contexts):
	"""The most specific naming context dn belongs to, or None."""
	best = None
	for nc in naming_contexts or []:
		if is_under(dn, nc) and (best is None or len(split_dn(nc)) > len(split_dn(best))):
			best = nc
	return best


def relative_name(dn, base):
	"""dn relative to base ('CN=Users' for CN=Users,DC=x below DC=x), or None if not below."""
	if not is_under(dn, base) or normalize(dn) == normalize(base):
		return None
	rdns = split_dn(dn)
	return join_dn(rdns[:len(rdns) - len(split_dn(base))])


def resolve(path, current, naming_contexts):
	"""Absolute DN for a cd argument, or raises ValueError with an explanation.

	'..' is the parent, '.' the current DN, a DN inside one of the naming contexts is absolute,
	anything else is relative to the current DN ('CN=Computers', 'OU=Servers,OU=Tier0').
	"""
	path = path.strip()
	if path in ('', '.'):
		target = current
	elif path == '..' or path.startswith('../') or path.startswith('..,'):
		target = current
		while path.startswith('..'):
			parent = parent_dn(target)
			if parent is None or (naming_contexts and naming_context_of(parent, naming_contexts) is None):
				raise ValueError('%s is the top of its naming context on this DC.%s' % (target, _nc_hint(naming_contexts)))
			target = parent
			path = path[2:].lstrip('/,')
		if path:
			target = join_dn(split_dn(path) + split_dn(target))
	elif naming_contexts and naming_context_of(path, naming_contexts) is not None:
		target = join_dn(split_dn(path))
	elif not naming_contexts and '=' in path and current and is_under(path, current):
		target = join_dn(split_dn(path))
	else:
		target = join_dn(split_dn(path) + split_dn(current))
	if naming_contexts and naming_context_of(target, naming_contexts) is None:
		raise ValueError('%s is not stored on this DC.%s' % (target, _nc_hint(naming_contexts)))
	return target


def looks_like_path(arg):
	"""'.', '..', '*', '../x' or anything with an RDN (CN=..., OU=...); attribute lists have no '='."""
	return arg in ('.', '..', '*') or arg.startswith('../') or arg.startswith('..,') or '=' in arg


def cat_arguments(args):
	"""(path, attributes) for cat. The order is cat [path] [attributes]; msldap's order
	cat [attributes] [path] is recognized by the second argument: attribute names have no '='."""
	args = [a for a in args if a != '']
	if len(args) >= 2 and args[1] != '*' and looks_like_path(args[1]):
		args = [args[1], args[0]] + args[2:]
	elif len(args) == 1 and not looks_like_path(args[0]):
		args = ['.', args[0]]
	path = args[0] if args else '.'
	attributes = args[1] if len(args) > 1 else '*'
	return path, attributes


def split_pattern(path):
	"""(parent path, pattern RDN) if the last element of path is a pattern ('*', 'CN=Dom*',
	'../OU=*'), else None. Only the first RDN may contain '*'."""
	prefix = ''
	while path.startswith('../') or path.startswith('..,'):
		prefix += '../'
		path = path[3:]
	rdns = split_dn(path)
	if not rdns or '*' not in rdns[0] or any('*' in r for r in rdns[1:]):
		return None
	parent = (prefix + join_dn(rdns[1:])) if rdns[1:] else (prefix.rstrip('/') or '.')
	return parent, rdns[0]


def split_glob(path):
	"""(parent path, LDAP filter) for a pattern path (see split_pattern), else None:
	cat * lists the children, cat CN=Dom* the matching ones."""
	split = split_pattern(path)
	if split is None:
		return None
	parent, rdn = split
	if rdn == '*':
		return parent, '(objectClass=*)'
	attribute, sep, value = rdn.partition('=')
	if not sep or not attribute.strip():
		return None
	# DN escapes (CN=Doe\, J*) are plain characters in the filter
	value = re.sub(r'\\(.)', r'\1', value.strip())
	return parent, '(%s=%s)' % (attribute.strip(), escape_glob(value))


def rdn_matches(rdn, pattern):
	"""Case-insensitive match of an RDN against a pattern RDN; '*' alone matches everything,
	'Dom*' (no attribute) matches the value of any RDN type."""
	if pattern == '*':
		return True
	if '=' not in pattern:
		rdn = rdn.partition('=')[2]
	return fnmatch.fnmatchcase(rdn.lower(), pattern.lower().replace('[', '[[]'))


def escape_glob(value):
	"""RFC 4515 escaping except for '*', which stays a wildcard."""
	out = []
	for ch in value:
		if ch in '()\\\0':
			out.append('\\%02x' % ord(ch))
		else:
			out.append(ch)
	return ''.join(out)


def match_spans(value, pattern):
	"""(start, end) of the literal parts of a find pattern ('*' is a wildcard) in value, if the
	whole value matches (case-insensitive like LDAP), else []."""
	segments = pattern.split('*')
	regex = '.*?'.join('(%s)' % re.escape(seg) for seg in segments)
	m = re.fullmatch(regex, value, re.IGNORECASE | re.DOTALL)
	if m is None:
		return []
	return [m.span(i + 1) for i, seg in enumerate(segments) if seg]


def _nc_hint(naming_contexts):
	if not naming_contexts:
		return ''
	return ' Naming contexts of this DC: %s' % ', '.join(naming_contexts)


def quote(name):
	"""Quotes for aiocmd's shlex split: spaces would split, backslashes (escaped commas) would vanish."""
	if name.startswith("'") or not any(ch in name for ch in " \\\"'"):
		return name
	return "'%s'" % name.replace("'", "'\"'\"'")


class PositionalCompleter(Completer):
	"""Dispatches completion by argument position: completers[i] is used for the i-th argument,
	None means no suggestions there. The last completer is not repeated for further arguments."""

	def __init__(self, completers):
		self.completers = completers

	def get_completions(self, document, complete_event):
		from prompt_toolkit.document import Document
		text = document.text_before_cursor
		tokens = text.split()
		index = len(tokens) if (not text or text[-1].isspace()) else len(tokens) - 1
		if index >= len(self.completers):
			return
		completer = self.completers[index]
		if completer is None:
			return
		word = '' if (not text or text[-1].isspace()) else tokens[-1]
		yield from completer.get_completions(Document(word, len(word)), complete_event)


class DNCompleter(Completer):
	"""Complete direct children and naming contexts; offer deeper paths after an unescaped comma."""

	def __init__(self, get_current, get_known_dns, get_naming_contexts, get_children=None, limit=200):
		self.get_current = get_current
		self.get_known_dns = get_known_dns
		self.get_naming_contexts = get_naming_contexts
		self.get_children = get_children or (lambda: [])
		self.limit = limit

	def candidates(self):
		current = self.get_current() or ''
		seen, result = set(), []

		def add(value):
			key = value.lower()
			if key not in seen:
				seen.add(key)
				result.append(value)

		ncs = self.get_naming_contexts() or []
		parent = parent_dn(current) if current else None
		if parent and (not ncs or naming_context_of(parent, ncs) is not None):
			add('..')
		for name in self.get_children():
			add(name)
		relative = sorted(
			(r for r in (relative_name(dn, current) for dn in self.get_known_dns()) if r),
			key=lambda r: (len(split_dn(r)), r.lower()))
		for name in relative:
			add(name)
		for nc in ncs:
			if normalize(nc) != normalize(current):
				add(nc)
		return result

	def get_completions(self, document, complete_event):
		text = document.text_before_cursor
		typed = text.lstrip("'").lower()
		# Appending a character also recognizes a trailing, unescaped comma as a new RDN.
		deep = len(split_dn(typed + '_')) > 1
		ncs = {normalize(nc) for nc in self.get_naming_contexts() or []}
		count = 0
		for candidate in self.candidates():
			if not deep and len(split_dn(candidate)) > 1 and normalize(candidate) not in ncs:
				continue
			if candidate.lower().startswith(typed):
				yield Completion(quote(candidate), -len(text), display=candidate)
				count += 1
				if count >= self.limit:
					return


def directory_tree(known_dns, root, depth=None, metadata=None, full_names=False):
	"""Rich tree of DNs below root (RDN labels), up to depth levels."""
	from rich.tree import Tree
	from msldap_ops.records import object_label

	root_n = normalize(root)
	metadata = metadata or {}
	children = {}
	for dn in known_dns:
		if not is_under(dn, root) or normalize(dn) == root_n:
			continue
		rdns = split_dn(dn)
		rel = rdns[:len(rdns) - len(split_dn(root))]
		# register every level, also intermediate DNs that were never seen themselves
		for i in range(len(rel), 0, -1):
			parent = normalize(join_dn(rel[i:] + split_dn(root)))
			node = join_dn(rel[i - 1:] + split_dn(root))
			children.setdefault(parent, {})[normalize(node)] = (rel[i - 1], node)

	tree = Tree(object_label(root, metadata.get(root_n), root=True), guide_style='bright_black')

	def walk(dn_n, branch, level):
		if depth is not None and level >= depth:
			return
		items = sorted(children.get(dn_n, {}).items(), key=lambda kv: kv[1][0].lower())
		for child_n, (name, full_dn) in items:
			more = '' if depth is None or level + 1 < depth or not children.get(child_n) else ' (+%d)' % len(children[child_n])
			label = object_label(full_dn if full_names else name, metadata.get(child_n))
			label.append(more, style='bright_black')
			child = branch.add(label)
			walk(child_n, child, level + 1)

	walk(root_n, tree, 0)
	return tree
