"""Monkeypatch hooks that make every msldap search visible to msldap-ops.

msldap has no callback mechanism for search results, so we patch two places:

- ``msldap.connection.convert_result`` converts a raw ``searchResEntry`` into the dict that msldap
  hands to its callers. The patched version returns a :class:`SearchEntry`, a plain dict that
  additionally carries the raw message in ``.raw``. Callers of msldap do not notice the difference.
- ``MSLDAPClientConnection.search`` and ``MSLDAPClientConnection.pagedsearch`` are wrapped to
  report the start and end of a query together with its parameters, and every entry it returns.

Listeners implement any subset of ``query_start(query)``, ``query_entry(query, entry)``,
``query_end(query)`` and ``write_end(write)`` (add/modify/delete, see :class:`WriteInfo`). Exceptions raised by listeners are logged and never break the query.

A gate (see :func:`set_gate`) is asked before a query is sent and can let it through, skip it
(the caller gets an empty result) or abort it (the caller gets an error).

A cache (see :func:`set_cache`) can answer a search from earlier results; the gate is not asked
then, nothing is sent. add/modify/delete go through the gate as well (``gate.write(info)``) and
invalidate the cached queries.

Queries that do not run in the foreground task (see :func:`set_foreground`), e.g. msldap's
keepalive, are marked as ``background``.
"""

import asyncio
import contextlib
from contextvars import ContextVar

import datetime
import functools
import inspect
import logging

import msldap.connection
from msldap.commons.customvalue import LDAPCustomValue
from msldap.connection import MSLDAPClientConnection

from msldap_ops.cache import is_unique, query_key

logger = logging.getLogger(__name__)

SCOPE_NAMES = {0: 'base', 1: 'one', 2: 'sub'}
# operations that change the directory and invalidate cached searches
WRITE_METHODS = ('add', 'modify', 'delete')

_listeners = []
_originals = {}
_gate = None
_cache = None
# UNMANAGED: no shell is tracking commands, every query counts as foreground.
# Otherwise the task of the running command, or None between commands (then every query,
# e.g. msldap's keepalive, is background).
UNMANAGED = object()
_foreground = UNMANAGED
# while > 0, searches are internal (e.g. reading the old value for an undo): treated as background,
# so they are not gated, shown or logged (they may be cached, which is harmless)
_internal_read = 0
_fresh_reads = ContextVar('fresh_reads', default=False)


@contextlib.contextmanager
def fresh_reads(enabled=True):
	"""Bypass cached results while retaining logging and opsec for a write command's reads."""
	token = _fresh_reads.set(enabled or _fresh_reads.get())
	try:
		yield
	finally:
		_fresh_reads.reset(token)


@contextlib.contextmanager
def internal_read():
	global _internal_read
	_internal_read += 1
	try:
		yield
	finally:
		_internal_read -= 1


# a human label for the next change, set by a command whose intent the raw modify does not show
# (e.g. grant/revoke both write nTSecurityDescriptor); the change log shows it instead
_write_label = None


@contextlib.contextmanager
def labeled(text):
	global _write_label
	previous, _write_label = _write_label, text
	try:
		yield
	finally:
		_write_label = previous


class RawValue(LDAPCustomValue):
	"""Writes raw attribute bytes back verbatim (used to restore the previous value on undo,
	independent of the attribute's type)."""

	def encode(self):
		return list(self.value or [])


SEND = 'send'
SKIP = 'skip'


class QueryAborted(Exception):
	pass


class SearchEntry(dict):
	"""Search result as returned by msldap, plus the raw ``searchResEntry`` in ``raw``."""
	__slots__ = ('raw',)


class QueryInfo:
	"""Parameters and outcome of a single search."""

	def __init__(self, server, base, query, attributes, scope, controls):
		self.server = server
		self.base = base
		self.query = query
		self.attributes = [a.decode() if isinstance(a, bytes) else str(a) for a in (attributes or [])]
		self.scope = SCOPE_NAMES.get(scope, str(scope))
		self.controls = [_control_type(c) for c in (controls or [])]
		self.started = datetime.datetime.now(datetime.timezone.utc)
		self.finished = None
		self.count = 0
		self.error = None
		self.background = _is_background()
		self.skipped = False
		self.cached = False
		self.cached_at = None  # datetime the cached result was stored

	def to_dict(self):
		return {
			'started': self.started.isoformat(),
			'finished': self.finished.isoformat() if self.finished else None,
			'server': self.server,
			'base': self.base,
			'scope': self.scope,
			'filter': self.query,
			'attributes': self.attributes,
			'controls': self.controls,
			'count': self.count,
			'error': None if self.error is None else str(self.error),
			'background': self.background,
			'skipped': self.skipped,
			'cached': self.cached,
		}


def _control_type(control):
	try:
		ctype = control['controlType']
	except Exception:
		return str(control)
	return ctype.decode() if isinstance(ctype, bytes) else str(ctype)


def _server_name(connection):
	target = getattr(connection, 'target', None)
	for attr in ('hostname', 'ip'):
		value = getattr(target, attr, None)
		if value:
			return str(value)
	return None


def _is_background():
	if _internal_read:
		return True
	if _foreground is UNMANAGED:
		return False
	if _foreground is None:
		return True
	try:
		return asyncio.current_task() is not _foreground
	except RuntimeError:
		return False


def set_foreground(task):
	"""Marks the task of the command currently running (None: no command is running); queries
	from other tasks are background. UNMANAGED switches the tracking off."""
	global _foreground
	_foreground = task


def set_gate(gate):
	"""gate: async callable(QueryInfo) -> SEND or SKIP, may raise QueryAborted. None removes it."""
	global _gate
	_gate = gate


def set_cache(cache):
	"""cache: msldap_ops.cache.QueryCache or None."""
	global _cache
	_cache = cache


def add_listener(listener):
	if listener not in _listeners:
		_listeners.append(listener)


def remove_listener(listener):
	if listener in _listeners:
		_listeners.remove(listener)


def _notify(event, *args):
	for listener in list(_listeners):
		handler = getattr(listener, event, None)
		if handler is None:
			continue
		try:
			handler(*args)
		except Exception:
			logger.exception('msldap-ops listener %r failed in %s', listener, event)


def _patched_convert_result(x):
	entry = SearchEntry(_originals['convert_result'](x))
	entry.raw = x
	return entry


def _wrap_search(original, controls_param, passthrough=None):
	"""Wraps an async generator method with the signature of ``MSLDAPClientConnection.search``."""
	signature = inspect.signature(original)

	@functools.wraps(original)
	async def wrapper(self, *args, **kwargs):
		bound = signature.bind(self, *args, **kwargs)
		bound.apply_defaults()
		params = bound.arguments
		if (not _listeners and _gate is None and _cache is None) or (passthrough is not None and params.get(passthrough)):
			async for item in original(self, *args, **kwargs):
				yield item
			return

		info = QueryInfo(
			_server_name(self),
			params['base'],
			params['query'],
			params['attributes'],
			params['search_scope'],
			_flatten_controls(params.get(controls_param)),
		)
		key = None
		if _cache is not None and not info.background:
			# the keepalive has to reach the server, it is neither answered from nor stored in the cache
			_cache.bind(self)
			key, parts = query_key(original.__name__, params)
			raws = None if _fresh_reads.get() else _cache.get(key, parts)
			if raws is not None:
				info.cached = True
				if _cache.last_stored is not None:
					info.cached_at = datetime.datetime.fromtimestamp(_cache.last_stored)
				if _gate is not None and hasattr(_gate, 'cached'):
					_gate.cached(info)
				_notify('query_start', info)
				try:
					for raw in raws:
						entry = msldap.connection.convert_result(raw)
						info.count += 1
						_notify('query_entry', info, entry)
						yield entry, None
				finally:
					info.finished = datetime.datetime.now(datetime.timezone.utc)
					_notify('query_end', info)
				return

		if _gate is not None:
			try:
				decision = await _gate(info)
			except QueryAborted as e:
				info.error = e
				info.skipped = True
				info.finished = datetime.datetime.now(datetime.timezone.utc)
				_notify('query_end', info)
				yield None, e
				return
			if decision == SKIP:
				info.skipped = True
				info.finished = datetime.datetime.now(datetime.timezone.utc)
				_notify('query_end', info)
				return

		_notify('query_start', info)
		raws = []
		complete = False
		try:
			async for entry, err in original(self, *args, **kwargs):
				if err is not None:
					info.error = err
				elif entry is not None:
					info.count += 1
					raws.append(getattr(entry, 'raw', None))
					_notify('query_entry', info, entry)
				yield entry, err
			complete = True
		finally:
			info.finished = datetime.datetime.now(datetime.timezone.utc)
			# only complete, successful searches; a caller that stopped early saw only a part,
			# unless the search can only have one result anyway
			if not complete and raws and is_unique(params):
				complete = True
			if key is not None and complete and info.error is None and None not in raws:
				_cache.put(key, parts, raws)
			_notify('query_end', info)

	wrapper.__msldap_ops_original__ = original
	return wrapper


# attributes whose values are never shown or logged
SECRET_ATTRIBUTES = {'unicodepwd', 'userpassword', 'clienttextpassword', 'ms-mcs-admpwd', 'mslaps-password',
	'mslaps-encryptedpassword', 'mslaps-encrypteddsrmpassword', 'supplementalcredentials', 'dbcspwd', 'unicodepwdhistory'}
MAX_VALUE = 200


def change_value(attribute, value):
	"""Display/log form of a value in an add or modify."""
	from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
	if attribute.lower() in SECRET_ATTRIBUTES:
		return '<hidden>'
	if isinstance(value, SECURITY_DESCRIPTOR):
		return value.to_sddl()
	if isinstance(value, bytes):
		try:
			if attribute.lower() in ('ntsecuritydescriptor', 'msds-allowedtoactonbehalfofotheridentity', 'msds-groupmsamembership'):
				return SECURITY_DESCRIPTOR.from_bytes(value).to_sddl()
		except Exception:
			pass
		try:
			text = value.decode('utf-8')
			if not text.isprintable():
				raise ValueError
		except ValueError:
			text = value.hex()
	else:
		text = str(value)
	if len(text) > MAX_VALUE:
		text = '%s... (%d characters)' % (text[:MAX_VALUE], len(text))
	return text


class WriteInfo:
	"""An add, modify or delete: [(operation, attribute, [values])] in changes."""

	def __init__(self, server, operation, dn, changes):
		self.server = server
		self.operation = operation
		self.dn = dn
		self.changes = []
		self.modify_ops = []  # raw (op, attribute, value) for computing the inverse
		if operation == 'add':
			for attribute, value in (changes or {}).items():
				values = value if isinstance(value, (list, tuple)) else [value]
				self.changes.append(('set', attribute, [change_value(attribute, v) for v in values]))
		elif operation == 'modify':
			for attribute, ops in (changes or {}).items():
				for op, value in ops:
					values = value if isinstance(value, (list, tuple)) else [value]
					self.changes.append((op, attribute, [change_value(attribute, v) for v in values]))
					self.modify_ops.append((op, attribute, value))
		self.started = datetime.datetime.now(datetime.timezone.utc)
		self.finished = None
		self.ok = None
		self.error = None
		self.skipped = False
		self.reason = None  # why it was not sent (set by the gate)
		self.label = _write_label  # a command's description of this change, if any

	def to_dict(self):
		return {
			'type': 'write',
			'started': self.started.isoformat(),
			'finished': self.finished.isoformat() if self.finished else None,
			'server': self.server,
			'operation': self.operation,
			'dn': self.dn,
			'changes': [{'op': op, 'attribute': a, 'values': v} for op, a, v in self.changes],
			'ok': self.ok,
			'error': None if self.error is None else str(self.error),
			'skipped': self.skipped,
		}


def _sd_flags_control():
	from msldap.protocol.messages import Control
	from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
	flags = SDFlagsRequest.OWNER_SECURITY_INFORMATION | SDFlagsRequest.GROUP_SECURITY_INFORMATION | SDFlagsRequest.DACL_SECURITY_INFORMATION
	return Control({'controlType': b'1.2.840.113556.1.4.801', 'criticality': True, 'controlValue': SDFlagsRequestValue({'Flags': flags}).dump()})


async def _read_raw(connection, dn, attributes):
	"""Raw bytes of the given attributes of one object (lowercased name -> [bytes]), as an internal
	background search; None if it could not be read."""
	want = {a.lower() for a in attributes}
	sd = 'ntsecuritydescriptor' in want
	controls = [_sd_flags_control()] if sd else None
	old = {}
	with internal_read():
		async for entry, err in connection.search(dn, '(objectClass=*)', [a.encode() for a in attributes],
				search_scope=0, controls=controls):
			if err is not None:
				return None
			raw = getattr(entry, 'raw', None)
			if raw is None:
				continue
			for attribute in raw['attributes']:
				name = attribute['type'].decode() if isinstance(attribute['type'], bytes) else str(attribute['type'])
				old[name.lower()] = list(attribute['attributes'] or [])
	return old


async def _prepare_undo(connection, info, controls):
	"""(undo action, reason) for a change, computed before it is applied.

	The action is ('operation', dn, changes, controls) that reverses info, or None with a reason
	when the change cannot be undone automatically. For modify, 'add'/'delete' of values invert
	directly; 'replace' needs the old value, read here and written back verbatim (RawValue). The
	undo reuses the forward controls, so a security-descriptor change is restored with the same SD
	flags (DACL for grant/revoke, owner for a chown) instead of the whole descriptor."""
	if info.operation == 'add':
		return ('delete', info.dn, None, None), None
	if info.operation == 'delete':
		return None, 'deleting an object cannot be undone automatically'
	if info.operation != 'modify':
		return None, 'not undoable'
	needs_old = [attr for op, attr, _ in info.modify_ops
		if op == 'replace' and attr.lower() not in SECRET_ATTRIBUTES]
	old = await _read_raw(connection, info.dn, needs_old) if needs_old else {}
	inverse, reasons = {}, []
	for op, attribute, value in info.modify_ops:
		if attribute.lower() in SECRET_ATTRIBUTES:
			reasons.append('%s (secret)' % attribute)
			continue
		if op == 'add':
			inverse.setdefault(attribute, []).append(('delete', value))
		elif op == 'delete':
			inverse.setdefault(attribute, []).append(('add', value))
		elif op == 'replace':
			if old is None:
				reasons.append('%s (old value not readable)' % attribute)
				continue
			inverse.setdefault(attribute, []).append(('replace', RawValue(old.get(attribute.lower(), []))))
		else:
			reasons.append('%s (%s)' % (attribute, op))
	if reasons:
		# a partial restore would be misleading, so the whole change counts as not undoable
		return None, 'cannot undo: ' + ', '.join(reasons)
	return ('modify', info.dn, inverse, list(controls) if controls else None), None


def _wrap_write(original):
	"""Wraps add/modify/delete: the gate is asked first (show/confirm/dryrun), the old values an
	undo needs are read before the change, listeners get write_end(info) always and
	write_done(info, undo, reason) on a successful change; cached searches are dropped afterwards."""
	signature = inspect.signature(original)

	@functools.wraps(original)
	async def wrapper(self, *args, **kwargs):
		bound = signature.bind(self, *args, **kwargs)
		params = bound.arguments
		info = WriteInfo(_server_name(self), original.__name__, params.get('entry'),
			params.get('changes', params.get('attributes')))
		if _gate is not None and hasattr(_gate, 'write'):
			try:
				decision = await _gate.write(info)
			except QueryAborted as e:
				decision, info.reason = SKIP, str(e)
			if decision == SKIP:
				info.skipped = True
				info.error = Exception('not sent: %s' % (info.reason or 'skipped'))
				info.finished = datetime.datetime.now(datetime.timezone.utc)
				_notify('write_end', info)
				return False, info.error
		# read the old values that the inverse needs, before the change goes out
		undo, undo_reason = await _prepare_undo(self, info, params.get('controls'))
		try:
			result = await original(self, *args, **kwargs)
		except Exception as e:
			info.ok, info.error = False, e
			raise
		else:
			try:
				info.ok, info.error = result
			except (TypeError, ValueError):
				info.ok = bool(result)
			if info.ok:
				_notify('write_done', info, undo, undo_reason)
			return result
		finally:
			info.finished = datetime.datetime.now(datetime.timezone.utc)
			if _cache is not None and not info.skipped:
				_cache.invalidate_queries()
			_notify('write_end', info)

	wrapper.__msldap_ops_original__ = original
	return wrapper


def _flatten_controls(controls):
	if controls is None:
		return []
	# search() receives an asn1 Controls object from pagedsearch, pagedsearch receives a list
	try:
		return list(controls)
	except TypeError:
		return [controls]


def install():
	"""Installs the hooks. Calling it more than once is harmless."""
	if _originals:
		return
	_originals['convert_result'] = msldap.connection.convert_result
	_originals['search'] = MSLDAPClientConnection.search
	_originals['pagedsearch'] = MSLDAPClientConnection.pagedsearch

	msldap.connection.convert_result = _patched_convert_result
	# pagedsearch calls search(return_done=True) for every page; those calls are not reported
	# separately, the surrounding pagedsearch already is
	MSLDAPClientConnection.search = _wrap_search(_originals['search'], 'controls', passthrough='return_done')
	MSLDAPClientConnection.pagedsearch = _wrap_search(_originals['pagedsearch'], 'controls')
	for name in WRITE_METHODS:
		_originals[name] = getattr(MSLDAPClientConnection, name)
		setattr(MSLDAPClientConnection, name, _wrap_write(_originals[name]))


def uninstall():
	if not _originals:
		return
	msldap.connection.convert_result = _originals.pop('convert_result')
	MSLDAPClientConnection.search = _originals.pop('search')
	MSLDAPClientConnection.pagedsearch = _originals.pop('pagedsearch')
	for name in WRITE_METHODS:
		setattr(MSLDAPClientConnection, name, _originals.pop(name))
