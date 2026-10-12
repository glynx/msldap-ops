"""Explicit connection options; the URL's authentication mode remains the default."""

from asyauth.common.constants import asyauthProtocol
from msldap.commons.factory import LDAPConnectionFactory


def ntlm_bind_factory(factory, mode):
	"""Override only NTLM's LDAP bind framing, preserving credentials and transport settings."""
	if mode is None:
		return factory
	if mode not in ('sasl', 'sicily'):
		raise ValueError('Invalid NTLM bind mode: %s' % mode)
	credential = factory.get_credential()
	if credential.protocol not in (asyauthProtocol.NTLM, asyauthProtocol.SICILY):
		raise ValueError('--ntlm-bind requires NTLM or SICILY authentication in the connection URL')
	credential.protocol = asyauthProtocol.SICILY if mode == 'sicily' else asyauthProtocol.NTLM
	return LDAPConnectionFactory(credential, factory.get_target())
