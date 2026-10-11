"""Query cache: answers repeated searches without asking the server again.

Every completed search is stored with its raw results (the searchResEntry messages, before msldap
converts them), keyed by base, scope, filter, attributes and controls. A repeated search within the
TTL is answered from the cache: the raw results go through msldap's normal conversion, so commands
get exactly what a live search would return.

Not cached: background queries (the keepalive must reach the server), failed searches and searches
the caller stopped early - unless the search can only have one result (base scope, or an equality
filter on distinguishedName, objectSid, objectGUID or sAMAccountName), then the first result is the
complete answer. Any add/modify/delete drops the cached queries.

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

	def get(self, key):
		"""Raw results of a cached search, or None."""
		if not self.enabled:
			return None
		item = self.queries.get(key)
		if item is None or time.time() - item['stored'] > self.ttl:
			self.misses += 1
			return None
		self.hits += 1
		return [raw_from_json(e) for e in item['entries']]

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

	# --- hook listener ------------------------------------------------------
	def query_entry(self, query, entry):
		raw = getattr(entry, 'raw', None)
		if raw is not None:
			self.seen(raw)
