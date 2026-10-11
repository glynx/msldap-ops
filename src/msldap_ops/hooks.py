"""Monkeypatch hooks that make every msldap search visible to msldap-ops.

msldap has no callback mechanism for search results, so we patch two places:

- ``msldap.connection.convert_result`` converts a raw ``searchResEntry`` into the dict that msldap
  hands to its callers. The patched version returns a :class:`SearchEntry`, a plain dict that
  additionally carries the raw message in ``.raw``. Callers of msldap do not notice the difference.
- ``MSLDAPClientConnection.search`` and ``MSLDAPClientConnection.pagedsearch`` are wrapped to
  report the start and end of a query together with its parameters, and every entry it returns.

Listeners implement any subset of ``query_start(query)``, ``query_entry(query, entry)`` and
``query_end(query)``. Exceptions raised by listeners are logged and never break the query.

A gate (see :func:`set_gate`) is asked before a query is sent and can let it through, skip it
(the caller gets an empty result) or abort it (the caller gets an error).

A cache (see :func:`set_cache`) can answer a search from earlier results; the gate is not asked
then, nothing is sent. add/modify/delete invalidate the cached queries.

Queries that do not run in the foreground task (see :func:`set_foreground`), e.g. msldap's
keepalive, are marked as ``background``.
"""

import asyncio

import datetime
import functools
import inspect
import logging

import msldap.connection
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
			raws = _cache.get(key)
			if raws is not None:
				info.cached = True
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


def _wrap_write(original):
	@functools.wraps(original)
	async def wrapper(self, *args, **kwargs):
		try:
			return await original(self, *args, **kwargs)
		finally:
			if _cache is not None:
				_cache.invalidate_queries()

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
