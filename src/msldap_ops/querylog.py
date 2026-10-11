"""Query logging in the pyldapsearch / ldapsearch BOF format understood by bofhound.

Every search result is written as a record::

	--------------------
	objectClass: top, person, organizationalPerson, user
	distinguishedName: CN=...
	...

and every query is terminated with ``Retrieved N results total``. The records are built from the
raw LDAP values, not from the Python objects msldap converts them to, so that timestamps, intervals
and binary attributes look the way bofhound expects them:

- SIDs and GUIDs in their string form
- known binary attributes (security descriptors, certificates, ...) base64 encoded
- everything else as the string the server sent; values that are not printable text are base64
  encoded as well

Results without objectSid and objectGUID are not written, bofhound cannot use them. The query
parameters (base, scope, filter, attributes, result count, number of logged records) are written to a separate JSON
lines file next to it, so that the bofhound log stays free of anything the parser could misread.
"""

import base64
import datetime
import json
import os
import threading

from winacl.dtyp.guid import GUID
from winacl.dtyp.sid import SID

DEFAULT_LOG_DIR = 'msldap-ops-logs'
SEPARATOR = '-' * 20

SID_ATTRIBUTES = {
	'objectsid', 'securityidentifier', 'sidhistory', 'tokengroups', 'tokengroupsglobalanduniversal',
	'tokengroupsnogcacceptable', 'ms-ds-creatorsid', 'msds-computersid', 'msds-quotatrustee',
	'msds-shadowprincipalsid', 'syncwithsid', 'msauthz-centralaccesspolicyid',
}
GUID_ATTRIBUTES = {
	'objectguid', 'schemaidguid', 'attributesecurityguid', 'msds-optionalfeatureguid',
	'invocationid', 'msexchmailboxguid',
}
BASE64_ATTRIBUTES = {
	'ntsecuritydescriptor', 'msds-allowedtoactonbehalfofotheridentity', 'msds-groupmsamembership',
	'msds-generationid', 'auditingpolicy', 'dsasignature', 'logonhours', 'cacertificate',
	'crosscertificatepair', 'pkiexpirationperiod', 'pkioverlapperiod', 'pkikeyusage',
	'authorityrevocationlist', 'certificaterevocationlist', 'deltarevocationlist', 'dnsrecord',
	'replpropertymetadata', 'repluptodatevector', 'msds-managedpasswordid',
	'msds-managedpasswordpreviousid', 'msds-managedpassword', 'thumbnailphoto', 'jpegphoto',
}
# skipped like pyldapsearch does; large and not used by bofhound
IGNORED_ATTRIBUTES = {'usercertificate'}
# bofhound identifies objects by SID or GUID; records with neither are useless to it, and records
# with only a DN (e.g. msldap's tree probes during login) make its container resolution crash
IDENTIFYING_ATTRIBUTES = {'objectsid', 'objectguid'}


def _b64(value):
	return base64.b64encode(value).decode('ascii')


def _is_text(value):
	return all(ch.isprintable() or ch in '\t\r\n' for ch in value)


def format_value(name, value):
	"""Formats one raw attribute value (bytes) for the log."""
	lname = name.lower()
	try:
		if lname in SID_ATTRIBUTES:
			return str(SID.from_bytes(value))
		if lname in GUID_ATTRIBUTES:
			return str(GUID.from_bytes(value))
	except Exception:
		return _b64(value)
	if lname in BASE64_ATTRIBUTES:
		return _b64(value)
	try:
		text = value.decode('utf-8')
	except UnicodeDecodeError:
		return _b64(value)
	if not _is_text(text):
		return _b64(value)
	# the format is line based, a line break inside a value would start a new attribute
	return ' '.join(text.splitlines())


def is_identifiable(raw):
	for attribute in raw['attributes']:
		name = attribute['type']
		name = name.decode() if isinstance(name, bytes) else str(name)
		if name.lower() in IDENTIFYING_ATTRIBUTES and attribute['attributes']:
			return True
	return False


def format_entry(raw):
	"""Formats a raw ``searchResEntry`` (as passed to ``convert_result``) as a log record."""
	lines = [SEPARATOR]
	for attribute in raw['attributes']:
		name = attribute['type']
		name = name.decode() if isinstance(name, bytes) else str(name)
		if name.lower() in IGNORED_ATTRIBUTES:
			continue
		values = attribute['attributes'] or []
		lines.append('%s: %s' % (name, ', '.join(format_value(name, v) for v in values)))
	return lines


class QueryLog:
	"""Hook listener that writes all search results to ``<directory>/msldap-ops_<date>.log``."""

	def __init__(self, directory=DEFAULT_LOG_DIR):
		# resolved once, so that the location does not depend on later changes of the cwd
		self.directory = os.path.abspath(directory)
		self.enabled = True
		self._lock = threading.Lock()

	def _path(self, kind):
		day = datetime.datetime.now().strftime('%Y%m%d')
		if kind == 'records':
			return os.path.join(self.directory, 'msldap-ops_%s.log' % day)
		return os.path.join(self.directory, 'msldap-ops-queries_%s.jsonl' % day)

	@property
	def path(self):
		return self._path('records')

	@property
	def query_path(self):
		return self._path('queries')

	def _write(self, kind, text):
		with self._lock:
			os.makedirs(self.directory, exist_ok=True)
			with open(self._path(kind), 'a', encoding='utf-8') as f:
				f.write(text)

	def query_entry(self, query, entry):
		if not self.enabled:
			return
		raw = getattr(entry, 'raw', None)
		if raw is None or not is_identifiable(raw):
			return
		# one write per record keeps records intact when queries overlap
		self._write('records', '\n'.join(format_entry(raw)) + '\n')
		query.logged = getattr(query, 'logged', 0) + 1

	def query_end(self, query):
		if not self.enabled:
			return
		logged = getattr(query, 'logged', 0)
		self._write('records', 'Retrieved %d results total\n' % logged)
		record = query.to_dict()
		record['logged'] = logged
		self._write('queries', json.dumps(record) + '\n')
