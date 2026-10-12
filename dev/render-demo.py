"""Build the README GIF from real command output and an in-memory demo directory.

Run: uv run --with pillow python dev/render-demo.py
No connection URLs, network calls, credentials or engagement files are used.
"""

import argparse
import asyncio
import contextlib
import datetime
import io
import os
from pathlib import Path
import re
import shlex
import tempfile
from types import SimpleNamespace

from PIL import Image, ImageDraw, ImageFont
from rich.console import Console
from rich.text import Text
from rich.cells import cell_len

from msldap_ops import aces, hooks, navigation, records, ui
from msldap_ops.changes import ChangeLog
from msldap_ops.opsec import OpsecGate
from msldap_ops.querylog import QueryLog
from msldap_ops.shell import MSLDAPOpsConsole
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR


ROOT = Path(__file__).resolve().parents[1]
BASE = 'DC=demo,DC=local'
CONFIG = 'CN=Configuration,' + BASE
DOMAIN_SID = 'S-1-5-21-111111111-222222222-333333333'
USER_SID = DOMAIN_SID + '-1101'
ENROLL = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
COLS, ROWS = 112, 23
FONT_SIZE, LINE_HEIGHT, PAD = 18, 27, 28
BG, FG, MUTED, ACCENT = '#101722', '#d5dfeb', '#8292a8', '#78c4d4'


def entry(rdn, classes, **attrs):
    dn = rdn + ',' + BASE if rdn else BASE
    return {'objectName': dn, 'attributes': {
        'distinguishedName': dn, 'objectClass': ['top'] + classes, **attrs}}


def certificate(name, **extra):
    attrs = {
        'name': name, 'cn': name, 'displayName': name,
        'distinguishedName': 'CN=%s,CN=Certificate Templates,%s' % (name, CONFIG),
        'msPKI-Certificate-Name-Flag': 0, 'msPKI-Enrollment-Flag': 0,
        'msPKI-Private-Key-Flag': 0x10, 'msPKI-RA-Signature': 0,
        'msPKI-Template-Schema-Version': 2, 'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2'],
        'pKIExpirationPeriod': -datetime.timedelta(days=365),
        'pKIOverlapPeriod': -datetime.timedelta(weeks=6), 'msPKI-Minimal-Key-Size': 2048,
        'nTSecurityDescriptor': SECURITY_DESCRIPTOR.from_sddl(
            'O:{0}-512G:{0}-512D:(OA;;CR;{1};;{0}-513)(A;;GA;;;{0}-512)'.format(DOMAIN_SID, ENROLL)
        ).to_bytes(),
    }
    attrs.update(extra)
    return {'objectName': attrs['distinguishedName'], 'attributes': attrs}


class DemoDirectory:
    """Only fixture data; deliberately has no transport or login implementation."""

    def __init__(self):
        self._tree, self.domainsid = BASE, DOMAIN_SID
        self._serverinfo = {'namingContexts': [BASE, CONFIG],
            'configurationNamingContext': CONFIG, 'schemaNamingContext': 'CN=Schema,' + CONFIG}
        self.target = SimpleNamespace(hostname='dc01.demo.local', ip=None)
        self.entries = [
            entry('', ['domainDNS'], objectSid=DOMAIN_SID),
            entry('CN=Computers', ['container']), entry('CN=Users', ['container']),
            entry('OU=Service Accounts', ['organizationalUnit']),
            entry('CN=APP01,CN=Computers', ['user', 'computer'], sAMAccountName='APP01$', userAccountControl=4096),
            entry('CN=OLDPC,CN=Computers', ['user', 'computer'], sAMAccountName='OLDPC$', userAccountControl=4098),
            entry('CN=alex.morgan,CN=Users', ['user'], sAMAccountName='alex.morgan',
                objectSid=USER_SID, userAccountControl=512, description='Demo account'),
            entry('CN=Domain Users,CN=Users', ['group'], sAMAccountName='Domain Users', objectSid=DOMAIN_SID + '-513'),
            entry('CN=svc.web,OU=Service Accounts', ['user'], sAMAccountName='svc.web',
                userAccountControl=512 | 0x1000000, **{'msDS-AllowedToDelegateTo': ['HTTP/app01.demo.local']}),
        ]
        self.certificates = [
            certificate('User'),
            certificate('WebEnroll', **{'msPKI-Certificate-Name-Flag': 1}),
            certificate('CodeSigning', **{'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.3'],
                'nTSecurityDescriptor': SECURITY_DESCRIPTOR.from_sddl(
                    'O:{0}-512G:{0}-512D:(A;;GA;;;{0}-512)(A;;WD;;;{0}-1109)'.format(DOMAIN_SID)
                ).to_bytes()}),
        ]

    def _get_configuration_nc(self):
        return CONFIG

    async def whoami(self):
        return 'u:DEMO\\alex.morgan', None

    async def resolv_sid(self, sid):
        return 'DEMO', {USER_SID: 'alex.morgan', DOMAIN_SID + '-513': 'Domain Users',
            DOMAIN_SID + '-512': 'Domain Admins', DOMAIN_SID + '-1109': 'svc.build'}.get(sid, '???'), None

    async def pagedsearch(self, query, attributes, controls=None, tree=None, search_scope=2):
        if query.startswith('(sAMAccountName='):
            found = [entry('CN=alex.morgan,CN=Users', ['user'], **{'msDS-PrincipalName': 'DEMO\\alex.morgan'})]
        elif 'tokenGroups' in attributes:
            found = [{'objectName': tree, 'attributes': {'objectSid': USER_SID, 'tokenGroups': [DOMAIN_SID + '-513']}}]
        elif 'pKIEnrollmentService' in query:
            found = [{'objectName': 'CN=DEMO-CA,' + CONFIG, 'attributes': {'name': 'DEMO-CA',
                'dNSHostName': 'ca.demo.local', 'certificateTemplates': ['User', 'WebEnroll', 'CodeSigning']}}]
        elif 'pKICertificateTemplate' in query:
            found = self.certificates
        elif '524288' in query:
            found = []
        elif 'AllowedToDelegateTo' in query:
            found = [e for e in self.entries if e['attributes'].get('msDS-AllowedToDelegateTo')]
        elif 'AllowedToActOnBehalf' in query:
            found = [entry('CN=APP01,CN=Computers', ['computer'], sAMAccountName='APP01$',
                **{'msDS-AllowedToActOnBehalfOfOtherIdentity': aces.rbcd_with(None, USER_SID)})]
        elif search_scope == 1:
            found = [e for e in self.entries if navigation.parent_dn(e['objectName']) == tree]
        elif query == '(objectClass=domain)':
            found = self.entries[:1]
        elif query == '(sAMAccountType=805306368)':
            found = [e for e in self.entries if e['attributes']['objectClass'][-1] == 'user']
        elif query == '(objectCategory=group)':
            found = [e for e in self.entries if 'group' in e['attributes']['objectClass']]
        else:
            raise ValueError('Unimplemented demo query: ' + query)
        for item in found:
            yield item, None

    async def get_tree_plot(self, dn, level=1):
        def children(parent, remaining):
            return {e['objectName']: children(e['objectName'], remaining - 1) if remaining > 1 else {}
                for e in self.entries if navigation.parent_dn(e['objectName']) == parent}
        return {dn: children(dn, level)}

    async def search(self, dn, query, attributes, search_scope=0, controls=None):
        item = next(e for e in self.entries if e['objectName'] == dn)
        raw = {'objectName': dn.encode(), 'attributes': []}
        for attribute in attributes:
            name = attribute.decode()
            value = item['attributes'].get(name, [])
            values = value if isinstance(value, list) else [value]
            raw['attributes'].append({'type': attribute, 'attributes': [str(v).encode() for v in values]})
        yield SimpleNamespace(raw=raw), None

    @hooks._wrap_write
    async def modify(self, entry, changes, controls=None):
        target = next(e for e in self.entries if e['objectName'] == entry)
        for name, ops in changes.items():
            for op, values in ops:
                assert op == 'replace'
                if isinstance(values, hooks.RawValue):
                    values = [v.decode() for v in values.encode()]
                target['attributes'][name] = values
        return True, None


class TerminalBuffer(io.StringIO):
    def isatty(self):
        return True


async def capture():
    os.environ['COLUMNS'] = str(COLS)
    os.environ.pop('NO_COLOR', None)
    os.environ['TERM'] = 'xterm-256color'
    ui.set_enabled(True)
    directory = DemoDirectory()
    changes = ChangeLog()

    async def answer(question):
        print(question + 'y')
        return 'y'

    gate = OpsecGate(ask=answer)
    scenes = []
    with tempfile.TemporaryDirectory(prefix='msldap-ops-demo-') as log_dir:
        querylog = QueryLog(log_dir)
        shell = MSLDAPOpsConsole(None, gate=gate, changes_log=changes, querylog=querylog)
        shell.connection, shell._current_dn = directory, BASE
        shell.prompt = '[%s]> ' % BASE
        shell._directory_metadata = {e['objectName'].lower(): records.object_metadata(e['attributes']) for e in directory.entries}
        hooks.set_gate(gate)
        hooks.add_listener(changes)

        async def command(text):
            path = shell._current_dn
            buffer = TerminalBuffer()
            with contextlib.redirect_stdout(ui.StyledStream(buffer)):
                parts = shlex.split(text)
                ok = await shell._run_single_command(parts[0], parts[1:])
            if ok is False:
                raise RuntimeError(text + ': ' + buffer.getvalue())
            output = buffer.getvalue().replace(log_dir, './msldap-ops-logs')
            # Keep the animation deterministic; timestamps are illustrative.
            output = re.sub(r'msldap-ops_(?:\d|[-_])+\.log', 'msldap-ops_demo.log', output)
            styled = Text.from_ansi(output)
            styled.rstrip()
            return path, text, styled

        try:
            scenes.append(('Browse the directory', 'Directory browsing with Rich trees, object icons and disabled account indicators.', [
                await command('tree 2'), await command('ls CN=Computers')]))
            scenes.append(('Review delegation', 'Kerberos delegation overview with resolved principals and service targets.', [
                await command('delegations')]))
            scenes.append(('Check certificate templates', 'Certificate template checks with findings for the evaluated token and separate review hints.', [
                await command('templates')]))
            scenes.append(('Collect for BloodHound', 'Selective BloodHound collection with query logs ready for bofhound.', [
                await command('bofhound_collect domain,users,groups')]))
            write_scene = [await command('cd CN=Users'), await command('opsec confirm-write'),
                await command('setattr CN=alex.morgan description "Demo review"')]
            changes.changes[-1].when = datetime.datetime(2026, 1, 1, 12, 0)
            write_scene.extend([await command('changes'), await command('undo')])
            assert not changes.changes
            account = next(e for e in directory.entries if e['attributes'].get('sAMAccountName') == 'alex.morgan')
            assert account['attributes']['description'] == ['Demo account']
            scenes.append(('Confirm, track and undo changes', 'Write confirmation, session change tracking and undo for supported operations.', write_scene))
        finally:
            hooks.remove_listener(changes)
            hooks.set_gate(None)
            hooks.set_foreground(hooks.UNMANAGED)
            ui.set_enabled(None)
    return scenes


def font_path(name):
    candidates = [Path('/usr/share/fonts/TTF') / name,
        Path('/usr/share/fonts/truetype/dejavu') / name]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise SystemExit('Font not found: %s (install DejaVu fonts or use --font)' % name)


def render(scenes, output, font=None):
    regular = ImageFont.truetype(str(font or font_path('DejaVuSansMono.ttf')), FONT_SIZE)
    bold = ImageFont.truetype(str(font or font_path('DejaVuSansMono-Bold.ttf')), FONT_SIZE)
    caption_font = ImageFont.truetype(str(font or font_path('DejaVuSans.ttf')), 19)
    cell = regular.getlength('M')
    width, height = round(COLS * cell + 2 * PAD), 830
    renderer = Console(width=COLS, force_terminal=True, highlight=False)
    emoji_path = Path('/usr/share/fonts/noto/NotoColorEmoji.ttf')
    emoji_font = ImageFont.truetype(str(emoji_path), 109) if emoji_path.exists() else None
    emojis = {}
    frames, durations = [], []
    ansi = ['#101722', '#e06c75', '#98c379', '#e5c07b', '#61afef', '#c678dd', '#56b6c2', '#d5dfeb',
        '#8292a8', '#ff7b86', '#b4e88d', '#f4d58d', '#85c3ff', '#e2a1f3', '#78dce8', '#ffffff']

    def draw_text(canvas, content, y):
        draw = ImageDraw.Draw(canvas)
        lines = renderer.render_lines(content, renderer.options, pad=False)
        for line in lines:
            x = float(PAD)
            for segment in line:
                style = segment.style
                color = style.color.get_truecolor() if style and style.color else None
                color = tuple(color) if color else tuple(bytes.fromhex(FG[1:]))
                number = style.color.number if style and style.color else None
                if number is not None and number < len(ansi):
                    color = tuple(bytes.fromhex(ansi[number][1:]))
                if style and style.dim:
                    bg = tuple(bytes.fromhex(BG[1:]))
                    color = tuple(round(a * .57 + b * .43) for a, b in zip(color, bg))
                face = bold if style and style.bold else regular
                for char in re.findall(r'.\ufe0f|.', segment.text):
                    cells = cell_len(char)
                    if ord(char[0]) >= 0x1f000 and emoji_font:
                        if char not in emojis:
                            glyph = Image.new('RGBA', (160, 160))
                            ImageDraw.Draw(glyph).text((0, 0), char, font=emoji_font, embedded_color=True)
                            box = glyph.getbbox()
                            glyph = glyph.crop(box) if box else glyph
                            glyph.thumbnail((round(2 * cell) - 2, LINE_HEIGHT - 4), Image.Resampling.LANCZOS)
                            emojis[char] = glyph
                        glyph = emojis[char]
                        if number == 8:
                            glyph = glyph.copy()
                            glyph.putalpha(glyph.getchannel('A').point(lambda a: round(a * .45)))
                        canvas.paste(glyph, (round(x), round(y + 2)), glyph)
                    else:
                        draw.text((round(x), y), char, font=face, fill=color)
                    x += cells * cell
            y += LINE_HEIGHT

    def frame(index, title, caption, transcript, duration, cursor=False):
        canvas = Image.new('RGB', (width, height), BG)
        draw = ImageDraw.Draw(canvas)
        draw.rounded_rectangle((1, 1, width - 2, height - 2), 14, outline='#2a394c', width=2)
        draw.text((PAD, 17), 'msldap-ops', font=bold, fill=FG)
        draw.line((PAD, 55, width - PAD, 55), fill='#2a394c')
        draw.text((PAD, 72), '%02d / %02d   %s' % (index + 1, len(scenes), title), font=bold, fill=ACCENT)
        rendered = renderer.render_lines(transcript, renderer.options, pad=False)
        assert len(rendered) <= ROWS, (title, len(rendered), transcript.plain)
        draw_text(canvas, transcript, 119)
        if cursor:
            last = rendered[-1] if rendered else []
            x = PAD + sum(segment.cell_length for segment in last) * cell
            y = 119 + (len(rendered) - 1) * LINE_HEIGHT
            draw.rectangle((round(x), y + 3, round(x + cell - 2), y + 22), fill=ACCENT)
        draw.line((PAD, 765, width - PAD, 765), fill='#2a394c')
        assert caption_font.getlength(caption) <= width - 2 * PAD - 15, caption
        draw.rounded_rectangle((PAD, 782, PAD + 3, 803), 1, fill=ACCENT)
        draw.text((PAD + 15, 780), caption, font=caption_font, fill=FG)
        for step in range(len(scenes)):
            left = PAD + step * (width - 2 * PAD) / len(scenes)
            right = PAD + (step + 1) * (width - 2 * PAD) / len(scenes) - 6
            draw.rectangle((round(left), 816, round(right), 819), fill=ACCENT if step <= index else '#2a394c')
        frames.append(canvas)
        durations.append(duration)

    for index, (title, caption, commands) in enumerate(scenes):
        transcript = Text()
        for path, command, result in commands:
            prompt = Text()
            prompt.append('msldap-ops', style='bright_black')
            prompt.append(' ' + path, style='bold cyan')
            prompt.append(' > ', style='bold green')
            for length in range(0, len(command), 3):
                typing = transcript + prompt + Text(command[:length])
                frame(index, title, caption, typing, 90, cursor=True)
            transcript += prompt + Text(command + '\n')
            result_lines = result.split('\n')
            for line in result_lines:
                transcript += line + Text('\n')
                frame(index, title, caption, transcript, 95)
            transcript += Text('\n')
            # Keep long scenes readable instead of scrolling earlier commands away.
            if len(renderer.render_lines(transcript, renderer.options, pad=False)) > ROWS - 6:
                transcript.rstrip()
                frame(index, title, caption, transcript, 1800)
                transcript = Text()
        transcript.rstrip()
        frame(index, title, caption, transcript, 4000)

    output.parent.mkdir(parents=True, exist_ok=True)
    # A shared palette keeps text colors stable and allows GIF delta compression.
    sample = Image.new('RGB', (width, height * len(scenes)))
    scene_frames = [j for j in range(len(frames)) if durations[j] == 4000]
    for i in range(len(scenes)):
        sample.paste(frames[scene_frames[i]], (0, height * i))
    quantized = sample.quantize(colors=240)
    palette = Image.new('P', (1, 1))
    # Reserve terminal colors so small red findings do not get averaged into yellow hints.
    colors = [channel for color in ansi for channel in bytes.fromhex(color[1:])]
    palette.putpalette(colors + quantized.getpalette()[:240 * 3])
    indexed = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    indexed[0].save(output, save_all=True, append_images=indexed[1:], duration=durations,
        loop=0, optimize=True, disposal=1)
    # A still frame makes reviewing the appearance possible without playing the GIF.
    frames[scene_frames[0]].save(output.with_suffix('.png'))
    print('%s: %d frames, %.1f seconds, %.2f MiB' % (
        output, len(frames), sum(durations) / 1000, output.stat().st_size / 1024 ** 2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/assets/demo.gif')
    parser.add_argument('--font', type=Path, help='Optional monospace TrueType font')
    args = parser.parse_args()
    render(asyncio.run(capture()), args.output, args.font)


if __name__ == '__main__':
    main()
