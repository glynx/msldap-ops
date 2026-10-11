"""LAPS: the local administrator password of a computer, both versions.

Legacy LAPS stores the password in clear in ``ms-Mcs-AdmPwd`` with an expiration in
``ms-Mcs-AdmPwdExpirationTime``. Windows LAPS stores a JSON blob in ``msLAPS-Password`` (readable
directly) or an encrypted blob in ``msLAPS-EncryptedPassword`` (decryption needs an RPC call to the
DC, not possible over LDAP alone); the expiration is in ``msLAPS-PasswordExpirationTime``.

This module only reads the attributes and says, per computer, which version is set, when the
password expires and the password where it is readable. Reading the password is sensitive and
privileged, so the shell command asks for a target (a computer name or pattern) and only reads the
whole domain on an explicit ``laps all``.
"""

import datetime
import json

LEGACY_ATTRIBUTES = ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime']
WINDOWS_ATTRIBUTES = ['msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-PasswordExpirationTime']
ATTRIBUTES = ['cn', 'sAMAccountName'] + LEGACY_ATTRIBUTES + WINDOWS_ATTRIBUTES
COMPUTER_FILTER = '(sAMAccountType=805306369)'


def _attr(entry, name):
	attributes = entry['attributes']
	for key, value in attributes.items():
		if key.lower() == name.lower():
			return value
	return None


def filetime(value):
	"""A Windows FILETIME (int or already a datetime) as a datetime, or None."""
	if value is None:
		return None
	if isinstance(value, datetime.datetime):
		return value
	try:
		value = int(value)
	except (TypeError, ValueError):
		return None
	if value <= 0 or value == 0x7FFFFFFFFFFFFFFF:
		return None
	return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=value // 10)


def windows_password(blob):
	"""(account, password) from a msLAPS-Password JSON blob, or (None, None)."""
	if blob is None:
		return None, None
	if isinstance(blob, bytes):
		blob = blob.decode('utf-8', 'replace')
	try:
		data = json.loads(blob)
	except (ValueError, TypeError):
		return None, blob
	return data.get('n'), data.get('p')


class LapsEntry:
	def __init__(self, entry):
		self.name = _attr(entry, 'sAMAccountName') or _attr(entry, 'cn') or entry['objectName']
		self.dn = entry['objectName']
		self.legacy_password = _attr(entry, 'ms-Mcs-AdmPwd')
		account, password = windows_password(_attr(entry, 'msLAPS-Password'))
		self.windows_account = account
		self.windows_password = password
		self.encrypted = _attr(entry, 'msLAPS-EncryptedPassword') is not None
		self.expiry = filetime(_attr(entry, 'ms-Mcs-AdmPwdExpirationTime')) or filetime(_attr(entry, 'msLAPS-PasswordExpirationTime'))

	@property
	def version(self):
		if self.legacy_password is not None:
			return 'legacy'
		if self.windows_password is not None or self.windows_account is not None:
			return 'windows'
		if self.encrypted:
			return 'windows (encrypted)'
		return None

	@property
	def configured(self):
		return self.version is not None or self.expiry is not None

	@property
	def password(self):
		if self.legacy_password is not None:
			return self.legacy_password
		return self.windows_password


def format_entry(e):
	lines = ['%s  (%s)' % (e.name, e.version or 'LAPS not readable')]
	if e.windows_account:
		lines.append('  account:  %s' % e.windows_account)
	if e.password is not None:
		lines.append('  password: %s' % e.password)
	elif e.encrypted:
		lines.append('  password: encrypted (needs an RPC call to the DC, not available over LDAP)')
	else:
		lines.append('  password: not readable with this account')
	if e.expiry is not None:
		lines.append('  expires:  %s' % e.expiry.strftime('%Y-%m-%d %H:%M:%S'))
	return lines


def summary(entries):
	readable = sum(1 for e in entries if e.password is not None)
	encrypted = sum(1 for e in entries if e.password is None and e.encrypted)
	return '%d comp%s with LAPS, %d password%s readable%s' % (
		len(entries), 'uter' if len(entries) == 1 else 'uters',
		readable, '' if readable == 1 else 's',
		', %d encrypted' % encrypted if encrypted else '')
