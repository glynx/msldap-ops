from types import SimpleNamespace

import pytest

from asyauth.common.constants import asyauthProtocol, asyauthSecret
from msldap.client import MSLDAPClient
from msldap.commons.factory import LDAPConnectionFactory
from msldap.examples.msldapclient import MSLDAPClientConsole

from msldap_ops.connections import ntlm_bind_factory
from msldap_ops.shell import MSLDAPOpsConsole


@pytest.mark.parametrize('mode, protocol', [('sasl', asyauthProtocol.NTLM), ('sicily', asyauthProtocol.SICILY)])
def test_bind_override_preserves_credentials_transport_and_socks(mode, protocol):
	url = ('ldap+ntlm-nt://NORTH\\user:0123456789abcdef0123456789abcdef@dc.example.test/DC=north'
		'?proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080&pagesize=500')
	original = LDAPConnectionFactory.from_url(url)
	configured = ntlm_bind_factory(original, mode)
	assert original.credential.protocol == asyauthProtocol.NTLM
	assert configured.credential.protocol == protocol
	assert configured.credential.stype == asyauthSecret.NT
	assert configured.credential.secret == original.credential.secret
	assert configured.credential.username == 'user' and configured.credential.domain == 'NORTH'
	assert configured.target.get_host() == original.target.get_host()
	assert configured.target.tree == 'DC=north' and configured.target.ldap_query_page_size == 500
	assert len(configured.target.proxies) == 1
	assert vars(configured.target.proxies[0]) == vars(original.target.proxies[0])
	assert configured.target is not original.target


def test_url_mode_is_preserved_without_override():
	factory = LDAPConnectionFactory.from_url('ldap+sicily-password://NORTH\\user:dummy@dc.example.test')
	assert ntlm_bind_factory(factory, None) is factory
	assert ntlm_bind_factory(factory, 'sasl').credential.protocol == asyauthProtocol.NTLM


@pytest.mark.parametrize('url', [
	'ldap+kerberos-password://NORTH\\user:dummy@dc.example.test?dc=192.0.2.1',
	'ldap+simple://NORTH\\user:dummy@dc.example.test', 'ldap://dc.example.test',
])
def test_bind_override_refuses_other_authentication_modes(url):
	factory = LDAPConnectionFactory.from_url(url)
	with pytest.raises(ValueError, match='requires NTLM or SICILY'):
		ntlm_bind_factory(factory, 'sicily')


@pytest.mark.parametrize('scheme, mode, signing, cb, protocol', [
	('ldap+ntlm-password', None, False, False, asyauthProtocol.NTLM),
	('ldap+ntlm-password', 'sicily', True, True, asyauthProtocol.SICILY),
	('ldaps+ntlm-password', 'sicily', True, True, asyauthProtocol.SICILY),
	('ldap+sicily-password', 'sasl', False, False, asyauthProtocol.NTLM),
])
async def test_login_propagates_connection_options_on_initial_and_replacement_urls(
	scheme, mode, signing, cb, protocol, monkeypatch,
):
	seen = []
	async def connect(client):
		seen.append((client.creds.protocol, client._disable_signing, client._disable_channel_binding))
		client._tree = 'DC=north'
		client._con = SimpleNamespace(is_anon=True)  # skip directory reads in this bind-options test
		return True, None
	monkeypatch.setattr(MSLDAPClient, 'connect', connect)
	url = scheme + '://NORTH\\user:dummy@dc.example.test'
	console = MSLDAPOpsConsole(url, ntlm_bind=mode, no_signing=signing, no_channel_binding=cb)
	assert await console.do_login() is True
	assert await console.do_login(url) is True
	assert seen == [(protocol, signing, cb)] * 2


async def test_bind_override_is_rejected_before_login_for_other_auth(monkeypatch, capsys):
	async def unexpected_login(*args, **kwargs):
		pytest.fail('an incompatible override must not attempt a login')
	monkeypatch.setattr(MSLDAPClientConsole, 'do_login', unexpected_login)
	console = MSLDAPOpsConsole('ldap+simple://user:secret@dc.example.test', ntlm_bind='sicily')
	assert await console.do_login() is False
	out = capsys.readouterr().out
	assert '--ntlm-bind requires NTLM or SICILY' in out
	assert 'secret' not in out and 'Traceback' not in out


async def test_failed_login_does_not_retry_another_bind(monkeypatch):
	calls = []
	async def failed_login(self, url=None):
		calls.append(url)
		return False
	monkeypatch.setattr(MSLDAPClientConsole, 'do_login', failed_login)
	console = MSLDAPOpsConsole('ldap+ntlm-password://NORTH\\user:dummy@dc.example.test')
	assert await console.do_login() is False
	assert calls == [None]


async def test_sicily_bind_sends_discovery_negotiate_response_without_signing():
	from asyauth.protocols.ntlm.messages.challenge import NTLMChallenge
	from asyauth.protocols.ntlm.messages.negotiate import NTLMNegotiate
	from asyauth.protocols.ntlm.structures.avpair import AVPairs, AVPAIRType
	from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
	from msldap.commons.common import MSLDAPClientStatus
	from msldap.connection import MSLDAPClientConnection
	from msldap.protocol.messages import LDAPMessage

	flags = (NegotiateFlags.NEGOTIATE_UNICODE | NegotiateFlags.NEGOTIATE_NTLM |
		NegotiateFlags.NEGOTIATE_TARGET_INFO | NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY |
		NegotiateFlags.NEGOTIATE_128 | NegotiateFlags.NEGOTIATE_56)
	challenge = NTLMChallenge.construct(challenge=b'12345678', targetName='NORTH',
		targetInfo=AVPairs({AVPAIRType.MsvAvNbDomainName: 'NORTH', AVPAIRType.MsvAvNbComputerName: 'DC'}),
		flags=flags).to_bytes()

	class Client(MSLDAPClientConnection):
		async def send_message(self, message):
			self.message_id += 1
			wire = LDAPMessage(dict(message, messageID=self.message_id)).dump()
			bind = LDAPMessage.load(wire)['protocolOp'].chosen
			requests.append((bind['authentication'].name, bind['authentication'].native))
			return self.message_id

		async def recv_message(self, message_id):
			matched = {1: b'NTLM', 2: challenge, 3: b''}[message_id]
			return [LDAPMessage({'messageID': message_id, 'protocolOp': {'bindResponse': {
				'resultCode': 'success', 'matchedDN': matched, 'diagnosticMessage': b''}}})]

	factory = ntlm_bind_factory(LDAPConnectionFactory.from_url(
		'ldap+ntlm-password://NORTH\\user:dummy@dc.example.test'), 'sicily')
	client = Client(factory.get_target(), factory.get_credential())
	client.status = MSLDAPClientStatus.CONNECTED
	client._disable_signing = True
	client.network = SimpleNamespace(packetizer=SimpleNamespace(is_plain_msg=True))
	requests = []
	assert await client.bind() == (True, None)
	assert [name for name, data in requests] == ['sicily_disco', 'sicily_nego', 'sicily_resp']
	negotiate = NTLMNegotiate.from_bytes(requests[1][1])
	assert not negotiate.NegotiateFlags & (NegotiateFlags.NEGOTIATE_SIGN | NegotiateFlags.NEGOTIATE_SEAL)
	assert not client.auth.signing_needed() and not client.auth.encryption_needed()
	assert client.network.packetizer.is_plain_msg is True
