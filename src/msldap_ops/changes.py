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

	@property
	def undoable(self):
		return self.undo is not None


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
	if getattr(info, 'label', None):
		return info.label
	if info.operation == 'add':
		return 'add %s' % info.dn
	if info.operation == 'delete':
		return 'delete %s' % info.dn
	parts = ['%s %s=%s' % (op, attribute, _short(attribute, values)) for op, attribute, values in info.changes]
	return 'modify %s: %s' % (info.dn, ', '.join(parts))


class ChangeLog:
	def __init__(self):
		self.changes = []
		self._applying = False  # while True, the write of an undo is not recorded as a new change

	def write_done(self, info, undo, reason):
		if self._applying:
			return
		self.changes.append(Change(info, undo, reason))

	def __len__(self):
		return len(self.changes)

	def last_undoable(self):
		for change in reversed(self.changes):
			if change.undoable:
				return change
		return None

	async def undo(self, connection, change):
		"""Applies the inverse of a change. On success the change is removed from the log (and the
		undo itself is not added as a new change); the journal keeps the audit trail. (ok, error)."""
		self._applying = True
		try:
			ok, err = await apply_undo(connection, change)
		finally:
			self._applying = False
		if ok and change in self.changes:
			self.changes.remove(change)
		return ok, err


async def apply_undo(connection, change):
	"""Applies the inverse of a change through the connection (add/modify/delete). The undo reuses
	the forward controls (e.g. the SD flags control), so a security-descriptor change restores the
	same portion. (ok, err)."""
	operation, dn, changes, controls = change.undo
	if operation == 'modify':
		if controls:
			# the captured controls are Control objects; the connection-level modify takes them as
			# is, while the client-level modify would wrap them again
			target = getattr(connection, '_con', connection)
			return await target.modify(dn, changes, controls=controls)
		return await connection.modify(dn, changes)
	if operation == 'delete':
		return await connection.delete(dn)
	if operation == 'add':
		return await connection.add(dn, changes)
	return False, Exception('unknown undo operation %r' % operation)
