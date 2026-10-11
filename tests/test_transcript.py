import io
import sys

from msldap_ops import transcript, ui


def test_transcript(tmp_path, monkeypatch):
	path = tmp_path / 't.log'
	stream = ui.StyledStream(io.StringIO())
	monkeypatch.setattr(sys, 'stdout', stream)
	t = transcript.start(str(path))
	try:
		t.command('DC=essos,DC=local', 'cat', ['*', 'cn'])
		print('DN: CN=x')
		print('\x1b[1;35mcolored\x1b[0m line')
		t.command('DC=essos,DC=local', 'query', ['(cn=*)', '>', 'out.txt'])
		t.command(None, 'login', ['ldap+ntlm-password://essos\\a:secret@dc'])
		t.answer('send? ', 'y')
		# an inner stream of a stacked pair does not copy
		stream.tee = False
		print('not twice')
	finally:
		transcript.stop()
	text = path.read_text()
	assert '] msldap-ops DC=essos,DC=local > cat \'*\' cn\nDN: CN=x\ncolored line\n' in text
	assert "> query '(cn=*)' > out.txt\n" in text
	assert '] msldap-ops > login [arguments not recorded]' in text and 'secret' not in text
	assert 'send? y\n' in text
	assert 'not twice' not in text
	assert text.startswith('### ') and text.rstrip().endswith('transcript stopped')
	assert transcript.active() is None


def test_default_path():
	assert transcript.default_path().startswith('./msldap-ops-transcript_') and transcript.default_path().endswith('.log')


def test_transcript_command(tmp_path, monkeypatch, capsys):
	import asyncio

	from msldap_ops.shell import MSLDAPOpsConsole
	monkeypatch.chdir(tmp_path)
	console = MSLDAPOpsConsole(None)
	assert asyncio.run(console.do_transcript('on')) is True
	assert transcript.active().path.startswith(str(tmp_path) + '/msldap-ops-transcript_')
	assert asyncio.run(console.do_transcript()) is True
	assert asyncio.run(console.do_transcript('off')) is True
	assert transcript.active() is None
	assert 'transcript: off (written to ' in capsys.readouterr().out
	assert asyncio.run(console.do_transcript('bogus')) is False
