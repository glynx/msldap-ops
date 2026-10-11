"""Session change log: every successful directory change with its inverse, so it can be undone.

The hook (see msldap_ops.hooks) computes the inverse of each change before it is applied and emits
``write_done(info, undo, reason)``. This listener records them in order. ``undo`` is an action
``(operation, dn, changes)`` that reverses the change (applied through the connection, so it is
itself shown/confirmed by opsec and recorded), or ``None`` with a ``reason`` when the change cannot
be undone automatically (object deletion, a password, an unreadable old value).

Only kept in memory for the running session; the query journal keeps the durable audit trail.
"""

import datetime


class Change:
	def __init__(self, info, undo, reason):
		self.when = datetime.datetime.now()
		self.operation = info.operation
		self.dn = info.dn
		self.summary = describe(info)
		self.undo = undo  # (operation, dn, changes) or None
		self.reason = reason
		self.undone = False

	@property
	def undoable(self):
		return self.undo is not None and not self.undone


SUMMARY_VALUE = 48


def _short(attribute, values):
	if attribute.lower() == 'ntsecuritydescriptor':
		return '<security descriptor>'
	if not values:
		return '(all)'
	text = '; '.join(values)
	return text if len(text) <= SUMMARY_VALUE else text[:SUMMARY_VALUE] + '...'


def describe(info):
	"""Compact one-line description of a change (long values and security descriptors shortened)."""
	if info.operation == 'add':
		return 'add %s' % info.dn
	if info.operation == 'delete':
		return 'delete %s' % info.dn
	parts = ['%s %s=%s' % (op, attribute, _short(attribute, values)) for op, attribute, values in info.changes]
	return 'modify %s: %s' % (info.dn, ', '.join(parts))


class ChangeLog:
	def __init__(self):
		self.changes = []

	def write_done(self, info, undo, reason):
		self.changes.append(Change(info, undo, reason))

	def __len__(self):
		return len(self.changes)

	def last_undoable(self):
		for change in reversed(self.changes):
			if change.undoable:
				return change
		return None


async def apply_undo(connection, change):
	"""Applies the inverse of a change through the connection (add/modify/delete). Returns
	(ok, error). The undo itself goes through the gate and is recorded like any other change."""
	operation, dn, changes = change.undo
	if operation == 'modify':
		ok, err = await connection.modify(dn, changes)
	elif operation == 'delete':
		ok, err = await connection.delete(dn)
	elif operation == 'add':
		ok, err = await connection.add(dn, changes)
	elif operation == 'setsd':
		# restore the DACL only, so WriteDacl is enough (changes holds the old descriptor bytes)
		from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest
		ok, err = await connection.set_objectacl_by_dn(dn, changes, flags=SDFlagsRequest.DACL_SECURITY_INFORMATION)
	else:
		return False, Exception('unknown undo operation %r' % operation)
	if ok:
		change.undone = True
	return ok, err
