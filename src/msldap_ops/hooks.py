"""Monkeypatch hooks that make every msldap search visible to msldap-ops.

msldap has no callback mechanism for search results, so we patch two places:

- ``msldap.connection.convert_result`` converts a raw ``searchResEntry`` into the dict that msldap
  hands to its callers. The patched version returns a :class:`SearchEntry`, a plain dict that
  additionally carries the raw message in ``.raw``. Callers of msldap do not notice the difference.
- ``MSLDAPClientConnection.search`` and ``MSLDAPClientConnection.pagedsearch`` are wrapped to
  report the start and end of a query together with its parameters, and every entry it returns.

Listeners implement any subset of ``query_start(query)``, ``query_entry(query, entry)`` and
``query_end(query)``. Exceptions raised by listeners are logged and never break the query.
"""

import datetime
import functools
import inspect
import logging

import msldap.connection
from msldap.connection import MSLDAPClientConnection

logger = logging.getLogger(__name__)

SCOPE_NAMES = {0: 'base', 1: 'one', 2: 'sub'}

_listeners = []
_originals = {}


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
		if not _listeners or (passthrough is not None and params.get(passthrough)):
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
		_notify('query_start', info)
		try:
			async for entry, err in original(self, *args, **kwargs):
				if err is not None:
					info.error = err
				elif entry is not None:
					info.count += 1
					_notify('query_entry', info, entry)
				yield entry, err
		finally:
			info.finished = datetime.datetime.now(datetime.timezone.utc)
			_notify('query_end', info)

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


def uninstall():
	if not _originals:
		return
	msldap.connection.convert_result = _originals.pop('convert_result')
	MSLDAPClientConnection.search = _originals.pop('search')
	MSLDAPClientConnection.pagedsearch = _originals.pop('pagedsearch')
