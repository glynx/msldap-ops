"""Project-scoped historical names, separate from TTL-limited LDAP query results.

Only positive identity observations are retained. These records are display labels,
never security descriptors, memberships or authorization tokens.
"""

import base64
import datetime
import json
import os
import re
import sqlite3

from msldap_ops.privileged import sid_string

DOMAIN_SID = re.compile(r'^S-1-5-21-\d+-\d+-\d+$')
IDENTITY_ATTRIBUTES = {'objectsid', 'samaccountname', 'objectclass', 'securityidentifier',
	'flatname', 'trustpartner', 'name', 'ncname', 'netbiosname'}


def domain_dn(dn):
	"""Domain suffix of a DN (also works below Configuration/Schema)."""
	match = re.search(r'(?:^|,)(DC=[^,]+(?:,DC=[^,]+)*)$', dn, re.I)
	return match.group(1) if match else ''


def dns_name(dn):
	return '.'.join(part[3:] for part in domain_dn(dn).split(',')) if domain_dn(dn) else ''


def last_seen(observed):
	return datetime.datetime.fromtimestamp(observed, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


class IdentityCatalogue:
	def __init__(self, directory, persist=True):
		self.directory = directory
		self.path = os.path.join(directory, 'identities.sqlite3') if persist else None
		self._db = None
		self._imported = False

	@property
	def db(self):
		if self._db is None:
			if self.path:
				os.makedirs(self.directory, exist_ok=True)
			self._db = sqlite3.connect(self.path or ':memory:', timeout=10)
			self._db.row_factory = sqlite3.Row
			self._db.executescript('''
				CREATE TABLE IF NOT EXISTS identities (
					kind TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL,
					observed REAL NOT NULL, server TEXT, account TEXT,
					PRIMARY KEY (kind, key));
				CREATE TABLE IF NOT EXISTS imports (
					path TEXT PRIMARY KEY, mtime INTEGER NOT NULL, size INTEGER NOT NULL);
			''')
		return self._db

	def _upsert(self, kind, key, data, observed, server, account):
		old = self.db.execute('SELECT * FROM identities WHERE kind=? AND key=?', (kind, key)).fetchone()
		merged = json.loads(old['data']) if old else {}
		seen = merged.setdefault('_seen', {})
		for field, value in data.items():
			if field not in seen or seen[field][0] <= observed:
				merged[field] = value
				seen[field] = [observed, server, account]
		# Keep timestamps per field: an older trust can supply a missing NetBIOS
		# name without overwriting a newer domain name or making that label fresh.
		observed, server, account = max(seen.values(), key=lambda item: item[0])
		self.db.execute('''INSERT INTO identities VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(kind, key) DO UPDATE SET data=excluded.data, observed=excluded.observed,
			server=excluded.server, account=excluded.account''',
			(kind, key, json.dumps(merged), observed, server, account))

	def _observe(self, entries, observed, server, account):
		for entry in entries:
			try:
				values = {name.lower(): [base64.b64decode(v) for v in vals]
					for name, vals in entry['a'] if name.lower() in IDENTITY_ATTRIBUTES}
				def text(name):
					return values[name][0].decode('utf-8') if values.get(name) else ''
				dn = entry['dn']
				sid = sid_string(values['objectsid'][0]).upper() if values.get('objectsid') else ''
				sam = text('samaccountname')
				if sid and sam:
					self._upsert('principal', sid, {'name': sam, 'dn': dn}, observed, server, account)
				classes = [v.decode().lower() for v in values.get('objectclass', [])]
				if DOMAIN_SID.fullmatch(sid) and ('domaindns' in classes or 'domain' in classes):
					self._upsert('domain', sid, {'dn': dn, 'dns': dns_name(dn)}, observed, server, account)
				if values.get('securityidentifier'):
					trustsid = sid_string(values['securityidentifier'][0]).upper()
					if DOMAIN_SID.fullmatch(trustsid):
						data = {k: v for k, v in {'dns': text('trustpartner') or text('name'), 'flat': text('flatname')}.items() if v}
						if data:
							self._upsert('domain', trustsid, data, observed, server, account)
				if text('ncname') and text('netbiosname'):
					self._upsert('partition', text('ncname').lower(), {'flat': text('netbiosname')}, observed, server, account)
			except (KeyError, ValueError, TypeError, UnicodeError, IndexError):
				# A partial or malformed attribute is not a negative identity observation.
				continue

	def observe(self, entries, observed, server=None, account=None):
		self.import_files()
		with self.db:
			self.db.execute('BEGIN IMMEDIATE')
			self._observe(entries, observed, server, account)

	def import_files(self):
		"""Migrate all existing namespaces before expired results can disappear.

		Remember file versions separately: clearing identities must not reimport the
		same historical snapshots on the next run. Memory-only mode never reads disk.
		"""
		if self._imported or not self.path:
			return
		self._imported = True
		for filename in sorted(os.listdir(self.directory)) if os.path.isdir(self.directory) else []:
			if not filename.endswith('.json'):
				continue
			path = os.path.join(self.directory, filename)
			try:
				stat = os.stat(path)
				old = self.db.execute('SELECT mtime, size FROM imports WHERE path=?', (filename,)).fetchone()
				if old and (old['mtime'], old['size']) == (stat.st_mtime_ns, stat.st_size):
					continue
				with open(path, encoding='utf-8') as stream:
					data = json.load(stream)
				if not isinstance(data, dict) or data.get('version') != 1:
					continue
				with self.db:
					self.db.execute('BEGIN IMMEDIATE')
					for query in data.get('queries', {}).values():
						self._observe(query.get('entries', []), float(query['stored']), data.get('server'), data.get('account'))
					self.db.execute('INSERT OR REPLACE INTO imports VALUES (?, ?, ?)', (filename, stat.st_mtime_ns, stat.st_size))
			except (OSError, ValueError, KeyError, TypeError, AttributeError):
				continue

	def get(self, kind, key):
		self.import_files()
		row = self.db.execute('SELECT * FROM identities WHERE kind=? AND key=?', (kind, key)).fetchone()
		return dict(json.loads(row['data']), observed=row['observed'], server=row['server'], account=row['account']) if row else None

	def domain(self, sid):
		record = self.get('domain', sid.upper())
		if record is None:
			return None
		partition = self.get('partition', (record.get('dn') or ','.join('DC=' + p for p in record.get('dns', '').split('.'))).lower())
		if not record.get('flat') and partition:
			record['flat'] = partition['flat']
			record['_seen']['flat'] = partition['_seen']['flat']
		record['name'] = record.get('flat') or record.get('dns')
		field = 'flat' if record.get('flat') else 'dns'
		if field in record['_seen']:
			record['observed'], record['server'], record['account'] = record['_seen'][field]
		return record

	def rows(self):
		self.import_files()
		rows = []
		for row in self.db.execute('SELECT * FROM identities ORDER BY kind, key'):
			data = json.loads(row['data'])
			item = dict(row, data=data)
			field = next((field for field in ('name', 'flat', 'dns') if data.get(field)), None)
			if field:
				item['observed'], item['server'], item['account'] = data['_seen'][field]
			rows.append(item)
		return rows

	def clear(self):
		self._imported = False
		self.import_files()
		with self.db:
			count = self.db.execute('SELECT COUNT(*) FROM identities').fetchone()[0]
			self.db.execute('DELETE FROM identities')
		return count

	def mark_file(self, path):
		"""A snapshot just saved by QueryCache has already been catalogued."""
		if self.path:
			stat = os.stat(path)
			with self.db:
				self.db.execute('INSERT OR REPLACE INTO imports VALUES (?, ?, ?)',
					(os.path.basename(path), stat.st_mtime_ns, stat.st_size))
