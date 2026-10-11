"""Query cache: answers repeated searches without asking the server again.

Every completed search is stored with its raw results (the searchResEntry messages, before msldap
converts them), keyed by base, scope, filter, attributes and controls. A repeated search within the
TTL is answered from the cache: the raw results go through msldap's normal conversion, so commands
get exactly what a live search would return.

Not cached: background queries (the keepalive must reach the server), failed searches and searches
the caller stopped early - unless the search can only have one result (base scope, or an equality
filter on distinguishedName, objectSid, objectGUID or sAMAccountName), then the first result is the
complete answer. Any add/modify/delete drops the cached queries.

A broader cached search answers a narrower one as well: same filter and controls, the wanted base DN
at or below the cached one (subtree), all wanted attributes included (explicitly, or through '*' for
attributes '*' returns). E.g. after bofhound_collect, 'templates' gets the templates and enrollment
services from the cache. A read of one object (base scope, filter (objectClass=*), e.g. cat) is
answered by any cached result that contains the object with the wanted attributes.

Besides the queries the cache keeps an index of every DN seen in any result (live or cached), for
navigation.

The cache is kept per server and bound account and is written as JSON to
``./msldap-ops-cache/<server>_<account>.json`` (it contains directory data, like the query log).
"""

import base64
import datetime
import hashlib
import json
import os
import re
import time

DEFAULT_CACHE_DIR = 'msldap-ops-cache'
DEFAULT_TTL = 1800
FORMAT_VERSION = 1


def _b64(value):
	return base64.b64encode(value).decode('ascii')


def raw_to_json(raw):
	return {
		'dn': raw['objectName'].decode('utf-8', 'replace') if isinstance(raw['objectName'], bytes) else str(raw['objectName']),
		'a': [[a['type'].decode() if isinstance(a['type'], bytes) else str(a['type']), [_b64(v) for v in (a['attributes'] or [])]] for a in raw['attributes']],
	}


def raw_from_json(data):
	return {
		'objectName': data['dn'].encode('utf-8'),
		'attributes': [{'type': t.encode(), 'attributes': [base64.b64decode(v) for v in values]} for t, values in data['a']],
	}


UNIQUE_FILTER = re.compile(r'^\((distinguishedName|objectSid|objectGUID|sAMAccountName)=[^*()]+\)$', re.IGNORECASE)


def is_unique(params):
	"""True if the search can return at most one object."""
	return params.get('search_scope') == 0 or bool(UNIQUE_FILTER.match(params.get('query') or ''))


# attributes '*' does not return: operational and constructed ones. msDS-* are all treated like this,
# many of them are constructed (msDS-User-Account-Control-Computed, msDS-PrincipalName, ...)
NOT_IN_STAR = {
	'ntsecuritydescriptor', 'tokengroups', 'tokengroupsglobalanduniversal', 'tokengroupsnogcacceptable',
	'allowedattributes', 'allowedattributeseffective', 'allowedchildclasses', 'allowedchildclasseseffective',
	'canonicalname', 'createtimestamp', 'modifytimestamp', 'structuralobjectclass', 'subschemasubentry',
	'sdrightseffective', 'primarygrouptoken', 'parentguid', 'fromentry', 'possibleinferiors', 'entryttl',
	'attributetypes', 'objectclasses', 'ditcontentrules', 'extendedattributeinfo', 'extendedclassinfo',
	'1.1',
}


SD_FLAGS_OID_HEX = b'1.2.840.113556.1.4.801'.hex()


def in_star(attribute):
	attribute = attribute.lower()
	return attribute not in NOT_IN_STAR and not attribute.startswith('msds-')


def _dn_under(dn, base):
	"""True if dn is base or below it (both lowercased)."""
	return dn == base or dn.endswith(',' + base)


def returns_attributes(cached, wanted):
	"""True if every object in the cached results carries what the wanted search asks for:
	same types_only and controls (the SD flags control only matters for nTSecurityDescriptor),
	all wanted attributes (explicitly, or through '*' for attributes '*' returns)."""
	if cached['types_only'] != wanted['types_only']:
		return False
	if cached['controls'] != wanted['controls']:
		# the SD flags control only changes nTSecurityDescriptor
		without_sd = [c for c in cached['controls'] if SD_FLAGS_OID_HEX not in c]
		if without_sd != wanted['controls'] or 'ntsecuritydescriptor' in wanted['attributes']:
			return False
	have = set(cached['attributes'])
	for attribute in wanted['attributes']:
		if attribute in have:
			continue
		if attribute == '*' or '*' not in have or not in_star(attribute):
			return False
	return True


def covers(cached, wanted):
	"""True if the results of the cached search contain everything the wanted search returns."""
	if cached['filter'].lower() != (wanted['filter'] or '').lower():
		return False
	if cached['base'] != wanted['base'] and not (cached['scope'] == 2 and wanted['scope'] == 2 and _dn_under(wanted['base'], cached['base'])):
		return False
	if cached['base'] == wanted['base'] and cached['scope'] != wanted['scope']:
		return False
	return returns_attributes(cached, wanted)


def is_object_read(wanted):
	"""A base search with (objectClass=*): reads one object, whatever filter found it before."""
	return wanted['scope'] == 0 and (wanted['filter'] or '').replace(' ', '').lower() == '(objectclass=*)'


def project(raw, wanted):
	"""Reduces a cached result to the attributes the wanted search asks for."""
	attributes = set(wanted['attributes'])
	star = '*' in attributes
	keep = []
	for attribute in raw['attributes']:
		name = attribute['type'].decode().lower() if isinstance(attribute['type'], bytes) else str(attribute['type']).lower()
		if name in attributes or (star and in_star(name)):
			keep.append(attribute)
	return {'objectName': raw['objectName'], 'attributes': keep}


def _control_key(control):
	try:
		return control.dump().hex()
	except AttributeError:
		return repr(control)


def query_key(kind, params):
	"""Identifies a search by everything that influences its result."""
	controls = params.get('controls')
	if controls is not None:
		try:
			controls = list(controls)
		except TypeError:
			controls = [controls]
	parts = {
		'kind': kind,
		'base': (params.get('base') or '').lower(),
		'scope': params.get('search_scope'),
		'filter': params.get('query'),
		'attributes': sorted(a.decode().lower() if isinstance(a, bytes) else str(a).lower() for a in (params.get('attributes') or [])),
		'controls': sorted(_control_key(c) for c in (controls or [])),
		'types_only': bool(params.get('types_only') or params.get('typesOnly')),
	}
	return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest(), parts


def identity(connection):
	"""server_account, used for the file name: results depend on the server and the ACLs of the account."""
	target = getattr(connection, 'target', None)
	server = getattr(target, 'hostname', None) or getattr(target, 'ip', None) or 'unknown'
	cred = getattr(connection, 'credential', None)
	user = getattr(cred, 'username', None) or 'anonymous'
	domain = getattr(cred, 'domain', None)
	account = '%s\\%s' % (domain, user) if domain else user
	return str(server), account


def _safe(value):
	return re.sub(r'[^A-Za-z0-9._-]+', '_', value).strip('_') or 'x'


class QueryCache:
	def __init__(self, directory=DEFAULT_CACHE_DIR, ttl=DEFAULT_TTL, persist=True, enabled=True):
		self.directory = os.path.abspath(directory)
		self.ttl = ttl
		self.persist = persist
		self.enabled = enabled
		self.server = None
		self.account = None
		self.queries = {}  # key -> {'stored': ts, 'query': parts, 'entries': [json]}
		self.dns = {}  # lowercased DN -> [DN, last seen ts]
		self.hits = 0
		self.misses = 0
		self.last_stored = None  # when the result of the last hit was stored
		self._dirty = False

	# --- target -------------------------------------------------------------
	@property
	def path(self):
		if self.server is None:
			return None
		return os.path.join(self.directory, '%s_%s.json' % (_safe(self.server), _safe(self.account)))

	def bind(self, connection):
		"""Switches to the cache of the connection's server and account (loads it from disk)."""
		server, account = identity(connection)
		if (server, account) == (self.server, self.account):
			return
		self.save()
		self.server, self.account = server, account
		self.queries, self.dns = {}, {}
		self.load()

	def load(self):
		if not self.persist or self.path is None or not os.path.exists(self.path):
			return
		try:
			with open(self.path, encoding='utf-8') as f:
				data = json.load(f)
		except (OSError, ValueError):
			return
		if data.get('version') != FORMAT_VERSION:
			return
		self.queries = data.get('queries', {})
		self.dns = data.get('dns', {})
		self.expire()

	def save(self):
		if not self.persist or not self._dirty or self.path is None:
			return
		os.makedirs(self.directory, exist_ok=True)
		tmp = self.path + '.tmp'
		with open(tmp, 'w', encoding='utf-8') as f:
			json.dump({'version': FORMAT_VERSION, 'server': self.server, 'account': self.account,
				'queries': self.queries, 'dns': self.dns}, f)
		os.replace(tmp, self.path)
		self._dirty = False

	# --- queries ------------------------------------------------------------
	def expire(self, now=None):
		now = now or time.time()
		for key in [k for k, v in self.queries.items() if now - v['stored'] > self.ttl]:
			del self.queries[key]
			self._dirty = True

	def get(self, key, parts=None):
		"""Raw results of a cached search, or None.

		With parts, a broader cached search can answer as well: same filter and controls, a base
		DN at or above the wanted one (subtree scope) and all wanted attributes included; its
		results are reduced to the wanted base and attributes.
		"""
		if not self.enabled:
			return None
		now = time.time()
		item = self.queries.get(key)
		if item is not None and now - item['stored'] <= self.ttl:
			self.hits += 1
			self.last_stored = item['stored']
			return [raw_from_json(e) for e in item['entries']]
		if parts is not None:
			for item in self.queries.values():
				if now - item['stored'] <= self.ttl and covers(item['query'], parts):
					self.hits += 1
					self.last_stored = item['stored']
					return [project(raw_from_json(e), parts) for e in item['entries'] if _dn_under(e['dn'].lower(), parts['base'])]
			if is_object_read(parts):
				# the object in any cached result (newest first) that returned the wanted attributes
				for item in sorted(self.queries.values(), key=lambda v: -v['stored']):
					if now - item['stored'] > self.ttl or not returns_attributes(item['query'], parts):
						continue
					for e in item['entries']:
						if e['dn'].lower() == parts['base']:
							self.hits += 1
							self.last_stored = item['stored']
							return [project(raw_from_json(e), parts)]
		self.misses += 1
		return None

	def put(self, key, parts, raws):
		if not self.enabled:
			return
		self.queries[key] = {'stored': time.time(), 'query': parts, 'entries': [raw_to_json(r) for r in raws]}
		self._dirty = True

	def seen(self, raw):
		dn = raw['objectName']
		dn = dn.decode('utf-8', 'replace') if isinstance(dn, bytes) else str(dn)
		if dn:
			self.dns[dn.lower()] = [dn, time.time()]
			self._dirty = True

	def invalidate_queries(self):
		if self.queries:
			self.queries = {}
			self._dirty = True

	def flush(self, pattern=None):
		"""Drops cached queries (all, or those whose base or filter contains pattern) and, without
		a pattern, the DN index. Returns the number of dropped queries."""
		if pattern is None:
			dropped = len(self.queries)
			self.queries, self.dns = {}, {}
		else:
			p = pattern.lower()
			keys = [k for k, v in self.queries.items() if p in v['query']['base'] or p in (v['query']['filter'] or '').lower()]
			for k in keys:
				del self.queries[k]
			dropped = len(keys)
		self._dirty = True
		self.save()
		return dropped

	def stats(self):
		entries = sum(len(v['entries']) for v in self.queries.values())
		oldest = min((v['stored'] for v in self.queries.values()), default=None)
		return {
			'queries': len(self.queries), 'entries': entries, 'dns': len(self.dns),
			'hits': self.hits, 'misses': self.misses,
			'oldest': datetime.datetime.fromtimestamp(oldest).strftime('%H:%M:%S') if oldest else None,
		}

	def list_queries(self):
		now = time.time()
		rows = []
		for v in sorted(self.queries.values(), key=lambda v: v['stored']):
			q = v['query']
			rows.append((int(now - v['stored']), len(v['entries']), q['base'], q['filter']))
		return rows

	# --- objects across all cached searches -----------------------------------
	def find_attribute(self, dn, attribute, needs_control=None):
		"""(raw entry, stored timestamp) of the newest cached result for dn that contains
		attribute, or None. needs_control: hex OID that the search must have used (e.g. the SD
		flags control, without it unprivileged users get no or another security descriptor)."""
		if not self.enabled:
			return None
		dn, attribute = dn.lower(), attribute.lower()
		now = time.time()
		best = None
		for item in self.queries.values():
			if now - item['stored'] > self.ttl or (best is not None and item['stored'] <= best[1]):
				continue
			if needs_control and not any(needs_control in c for c in item['query']['controls']):
				continue
			for entry in item['entries']:
				if entry['dn'].lower() == dn and any(t.lower() == attribute and v for t, v in entry['a']):
					best = (entry, item['stored'])
					break
		if best is None:
			return None
		return raw_from_json(best[0]), best[1]

	def account_names(self):
		"""objectSid (string) -> sAMAccountName of every cached object that has both."""
		from msldap_ops.privileged import sid_string
		names = {}
		now = time.time()
		for item in sorted(self.queries.values(), key=lambda v: v['stored']):
			if now - item['stored'] > self.ttl:
				continue
			for entry in item['entries']:
				values = {t.lower(): v for t, v in entry['a']}
				sid, sam = values.get('objectsid'), values.get('samaccountname')
				if sid and sam:
					try:
						names[sid_string(base64.b64decode(sid[0])).upper()] = base64.b64decode(sam[0]).decode('utf-8', 'replace')
					except Exception:
						continue
		return names

	# --- hook listener ------------------------------------------------------
	def query_entry(self, query, entry):
		raw = getattr(entry, 'raw', None)
		if raw is not None:
			self.seen(raw)
