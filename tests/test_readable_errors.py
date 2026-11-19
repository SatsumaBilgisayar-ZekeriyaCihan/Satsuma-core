"""2.2.51: the warnings-and-errors view no longer shows false alarms and bare codes.

Field screenshot 2026-11-19 (Kayıtlar → Tüm kayıtlar → Yalnızca uyarı ve hatalar):
AUDIT_SOURCE_CHANGED every ten minutes, "Tarayıcı bellek taraması hataları ·
Hata (×2)" and a bare "otx_domain".
"""
import os

from satsuma import record_catalog as catalog
from satsuma.audit_host import AuditReader


class Store:
    def __init__(self):
        self.state, self.records = {}, []

    def get(self, key, default=None):
        return self.state.get(key, default)

    def set(self, key, value):
        self.state[key] = value

    def add(self, kind, body):
        self.records.append((kind, body))


LINE = ('type=SYSCALL msg=audit(1795089000.123:{n}): arch=c000003e syscall=59 success=yes\n'
        'type=EOE msg=audit(1795089000.123:{n}): \n')


def test_a_followed_auditd_rotation_is_not_reported_as_a_source_change(tmp_path):
    log = tmp_path / 'audit.log'
    log.write_text(LINE.format(n=1))
    os.chmod(log, 0o600)
    store = Store()
    reader = AuditReader(store, log)
    reader.poll()
    # auditd rotates: the old file is renamed, a new one is created.
    os.rename(log, tmp_path / 'audit.log.1')
    log.write_text(LINE.format(n=2))
    os.chmod(log, 0o600)
    reader.poll()            # reads the old file to its end and closes it
    reader.poll()            # opens the new file
    reader.poll()
    assert not [b for k, b in store.records if k == 'host_errors'], store.records
    assert any(k == 'audit' and ':2)' in str(b) for k, b in store.records)


def test_a_real_source_change_is_still_reported(tmp_path):
    log = tmp_path / 'audit.log'
    log.write_text(LINE.format(n=1))
    os.chmod(log, 0o600)
    store = Store()
    store.set('audit_cursor', {'identity': [0, 0], 'offset': 10})   # a file this reader never followed
    AuditReader(store, log).poll()
    assert [b['status'] for k, b in store.records if k == 'host_errors'] == ['AUDIT_SOURCE_CHANGED']


def test_error_lines_read_as_sentences():
    temp = catalog.render('temporary_scan_error', {'path': '/tmp/x.bin', 'error': 'PermissionError'}, 1.0)
    assert temp['text'] == 'Geçici dosya taranamadı' and temp['detail'] == '/tmp/x.bin · izin yok'
    with_reason = catalog.render('temporary_scan_error', {'path': '/tmp/y', 'error': 'OSError', 'reason': '[Errno 5] Input/output error'}, 1.0)
    assert with_reason['detail'].endswith('Input/output error')
    otx = catalog.render('errors', {'component': 'otx_domain', 'domain': 'bad.example', 'error': 'HTTP 429'}, 1.0)
    assert otx['text'] == 'OTX alan adı sorgusu başarısız: bad.example' and otx['detail'] == 'HTTP 429'
    audit = catalog.render('host_errors', {'status': 'AUDIT_SOURCE_CHANGED', 'detail': 'x'}, 1.0)
    assert audit['text'].startswith('Denetim günlüğü baştan okundu') and audit['tone'] == 'warn'
    assert catalog.describe('temporary_scan_error')['name'] == 'Geçici dosya taraması hataları'


def test_level_follows_the_tone_of_an_error_kind():
    import json
    import sqlite3
    from contextlib import contextmanager
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE records (id INTEGER PRIMARY KEY, created REAL, kind TEXT, body TEXT)')
    for kind, body in (('host_errors', {'status': 'AUDIT_SOURCE_CHANGED'}), ('errors', {'component': 'otx_domain', 'error': 'x'})):
        db.execute('INSERT INTO records(created,kind,body) VALUES(?,?,?)', (100.0, kind, json.dumps(body)))

    @contextmanager
    def connect():
        yield db
    levels = {i['kind']: i['level'] for i in catalog.timeline((('core', connect),), now=200.0)['items']}
    assert levels == {'host_errors': 'Uyarı', 'errors': 'Hata'}
