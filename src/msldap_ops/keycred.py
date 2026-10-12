"""Shadow credential generation and local key export."""

import os
import hashlib
import struct
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from msldap.commons.keycredential import KeyCredential


def generate(subject, dn):
	"""Return a DN-Binary credential value and a matching passwordless PFX."""
	credential = KeyCredential.generate_self_signed_certificate(subject, deviceId=uuid.uuid4().bytes_le)
	pfx = serialize_key_and_certificates(
		name=None, key=credential.key, cert=credential.certificate, cas=None,
		encryption_algorithm=serialization.NoEncryption())
	# MS-ADTS: KeyHash hashes every entry after KeyHash, not the KeyID.
	entries = _entries(credential.dumpBinary())
	tail = b''.join(struct.pack('<HB', len(value), identifier) + value
		for identifier, value in entries if identifier > 2)
	blob = struct.pack('<I', 0x200) + b''.join(
		struct.pack('<HB', len(value), identifier) + value
		for identifier, value in entries if identifier < 2)
	blob += struct.pack('<HB', 32, 2) + hashlib.sha256(tail).digest() + tail
	hexdata = blob.hex()
	return 'B:%d:%s:%s' % (len(hexdata), hexdata, dn), pfx


def save_pfx(data, filename=None):
	"""Save key material before modifying AD; fail rather than overwrite an existing file."""
	filename = os.path.abspath(os.path.expanduser(filename or 'keycred-%s.pfx' % uuid.uuid4()))
	fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
	with os.fdopen(fd, 'wb') as f:
		f.write(data)
	return filename


def _entries(blob):
	"""Decode the length/identifier/value entries of a version 2 key credential."""
	if len(blob) < 4 or struct.unpack_from('<I', blob)[0] != 0x200:
		raise ValueError('Unsupported key credential version')
	entries, offset, previous = [], 4, 0
	while offset < len(blob):
		if len(blob) - offset < 3:
			raise ValueError('Truncated key credential entry')
		length, identifier = struct.unpack_from('<HB', blob, offset)
		offset += 3
		if offset + length > len(blob) or identifier <= previous:
			raise ValueError('Invalid key credential entry')
		entries.append((identifier, blob[offset:offset + length]))
		offset += length
		previous = identifier
	return entries


def identifiers(value):
	"""Device UUID and key hash for selecting a credential across sessions; None if malformed."""
	try:
		if isinstance(value, bytes):
			value = value.decode('utf-8')
		prefix, length, hexdata, dn = value.split(':', 3)
		if prefix != 'B' or int(length) != len(hexdata) or not dn:
			return None
		entries = dict(_entries(bytes.fromhex(hexdata)))
		key_id = entries.get(1)
		device = entries.get(6)
		if key_id is None or len(key_id) != 32 or (device is not None and len(device) != 16):
			return None
		device = uuid.UUID(bytes_le=device) if device else None
		return {'key_id': key_id.hex(), 'device_id': str(device) if device and device.int else None}
	except (ValueError, TypeError, AttributeError, UnicodeError):
		return None


def matches(value, selector):
	ids = identifiers(value)
	if ids is None:
		return False
	try:
		selector = str(uuid.UUID(selector))
	except ValueError:
		selector = selector.lower()
	return selector in (ids['device_id'], ids['key_id'])


def format_value(value):
	ids = identifiers(value)
	if ids is None:
		return ['  (unparsed) %s' % str(value)[:80]]
	return ['  Device ID: %s' % (ids['device_id'] or '(none)'), '    Key ID: %s' % ids['key_id']]
