import os
import stat

from msldap_ops import history


def test_secrets_are_detected():
	assert history.is_sensitive('login ldap+ntlm-password://essos\\khal.drogo:horse@192.168.56.12')
	assert history.is_sensitive('login "ldap+ntlm-nt://essos\\khal.drogo:739120ebc4dd940310bc4bb5c9d37021@dc"')
	assert history.is_sensitive("changeuserpw 'CN=x,DC=essos,DC=local' NewPass1!")
	assert history.is_sensitive('adduser CN=x,DC=y Secret1')
	assert history.is_sensitive('addcomputer evil$ Secret1')
	assert not history.is_sensitive('addcomputer')
	assert not history.is_sensitive('login')
	assert not history.is_sensitive('login ldap+kerberos://essos\\khal.drogo@dc/?dc=192.168.56.12')
	assert not history.is_sensitive('query (sAMAccountName=x) cn > out.txt')
	assert not history.is_sensitive("query '(cn=a\"b')")


def test_file_history_is_private_and_skips_secrets(tmp_path):
	path = tmp_path / 'state' / 'msldap-ops' / 'history'
	h = history.PrivateFileHistory(str(path))
	assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
	h.append_string('find_admins')
	h.append_string('login ldap+ntlm-password://essos\\a:secret@dc')
	# the secret stays available in this session
	assert h.get_strings()[-1].startswith('login')
	text = path.read_text()
	assert 'find_admins' in text and 'secret' not in text
	assert list(history.PrivateFileHistory(str(path)).load_history_strings()) == ['find_admins']


def test_default_path_follows_xdg(monkeypatch, tmp_path):
	monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path))
	assert history.default_path() == str(tmp_path / 'msldap-ops' / 'history')


def test_unique_recent():
	assert history.unique_recent(['ls', 'cd ..', 'ls', 'cat']) == ['ls', 'cd ..', 'cat']


def test_fzf_select(monkeypatch, tmp_path):
	# a fake fzf that prints the second line of its input and records its query
	fake = tmp_path / 'fzf'
	fake.write_text('#!/bin/sh\necho "$@" > "%s/args"\nsed -n 2p\n' % tmp_path)
	fake.chmod(0o755)
	monkeypatch.setenv('PATH', '%s:%s' % (tmp_path, os.environ['PATH']))
	assert history.fzf_available()
	assert history.fzf_select(['find_admins', 'templates vulnerable'], 'temp') == 'templates vulnerable'
	assert '--query temp' in (tmp_path / 'args').read_text()
	fake.write_text('#!/bin/sh\nexit 130\n')
	assert history.fzf_select(['x']) is None

