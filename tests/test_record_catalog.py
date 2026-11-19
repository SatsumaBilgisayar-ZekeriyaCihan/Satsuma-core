"""Every stored record kind is named and shown; none is hidden (2.2.29).

Field report 2026-11-04: many database warnings never reached the panel.

Saklanan her kayıt türü adlandırılır ve gösterilir; hiçbiri gizlenmez.
"""
import json
import re
import sqlite3
import time
from pathlib import Path

from satsuma import record_catalog as rc

ROOT = Path(__file__).parents[1]
WRITE = re.compile(r"\.add\(\s*['\"]([a-z_]+)['\"]")
NOT_RECORDS = set()  # set.add() calls with string literals that are not store writes


def written_kinds():
    kinds = set()
    for folder in ('satsuma', 'workers', 'installer'):
        for path in (ROOT / folder).rglob('*.py'):
            kinds.update(WRITE.findall(path.read_text(errors='replace')))
    return kinds - NOT_RECORDS


def test_every_kind_the_code_writes_is_in_the_catalog():
    missing = sorted(written_kinds() - set(rc.KINDS))
    assert not missing, 'record kinds written but not in record_catalog.KINDS: ' + ', '.join(missing)


def test_every_catalog_entry_is_complete():
    for kind, entry in rc.KINDS.items():
        assert entry['name'] and entry['what'] and entry['why'], kind
        assert entry['db'] in ('core', 'host'), kind
        assert entry['group'] in {g for g, _ in rc.GROUPS}, kind


def db_with(rows):
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE records(id INTEGER PRIMARY KEY, kind TEXT, created REAL, body TEXT)')
    for kind, created, body in rows:
        db.execute('INSERT INTO records(kind,created,body) VALUES(?,?,?)', (kind, created, json.dumps(body)))
    return db


class Keep:
    def __init__(self, db):
        self.db = db
    def __enter__(self):
        return self.db
    def __exit__(self, *a):
        return False


def test_overview_shows_unknown_kinds_and_zero_counts_and_respects_the_window():
    now = 1_000_000.0
    db = db_with([('actions', now - 90_000, {}), ('actions', now - 60, {}), ('mystery_kind', now - 30, {'x': 1})])
    result = rc.overview((('core', lambda: Keep(db)),), hours=24, now=now)
    by = {k['kind']: k for k in result['kinds']}
    assert by['actions']['count'] == 1
    assert by['mystery_kind']['known'] is False and by['mystery_kind']['count'] == 1
    assert 'mystery_kind' in result['unknown_kinds']
    assert by['findings']['count'] == 0
    assert result['total'] == 2


def test_explained_renders_sentences_and_masks_secrets():
    db = db_with([('actions', time.time(), {'action': 'process.terminate', 'status': 'terminated', 'exit_verified': True,
                                             'pid': 7, 'rule_id': 'SATSUMA-SUDO-HARD-002', 'api_key': 'sekret'})])
    page = rc.explained(db, 'actions')
    item = page['items'][0]
    assert item['text'].startswith('Süreç durdurma')
    assert 'sonlandırıldı' in item['chip']
    assert item['raw']['api_key'] == '[GİZLENDİ]'
    assert 'sekret' not in json.dumps(page, ensure_ascii=False)


def test_render_never_fails_on_odd_bodies():
    for kind in list(rc.KINDS) + ['unknown']:
        for body in ({}, {'event': 'x'}, 'text', 5, None, {'finding': {'event': {}}}):
            out = rc.render(kind, body)
            assert set(out) >= {'text', 'detail', 'chip', 'tone'}


def test_investigation_findings_carry_the_source_process():
    from satsuma.investigation import source_identity
    from satsuma.presentation import process_fields
    finding = {'rule_id': 'SATSUMA-PRIV-001', 'event': {'pid': '4242', 'uid': '1000', 'exe': '/usr/bin/sudo',
                                                      'cmd': 'sudo -i', 'metadata': {'extensions': {'host.ppid': 7}}}}
    identity = source_identity(finding)
    assert identity['pid'] == '4242' and identity['cmd'] == 'sudo -i' and identity['ppid'] == 7
    assert process_fields({'event': identity}) == ('/usr/bin/sudo', '4242')


def test_records_panel_is_reachable_from_the_sidebar():
    # 2.2.47: Kayıtlar is a section of its own; the explained kinds are one of its tabs.
    from satsuma.dashboard_qt.windows.nav import SECTION_OF, TITLES
    assert SECTION_OF['records'] == 'logs' and SECTION_OF['logbook'] == 'logs' and TITLES['records'] == 'Türlere göre'


def test_every_finding_names_the_triggering_process_as_the_one_to_stop():
    from satsuma.investigation import investigate, KILL_ROLE
    finding = {'rule_id': 'SATSUMA-NO-ROLES', 'summary': 'x', 'severity': 'critical',
               'event': {'pid': '155153', 'exe': '/usr/bin/systemctl', 'cmd': 'systemctl stop auditd'}}
    result = investigate(None, finding)
    assert result['roles_played'][0]['role'] == KILL_ROLE and result['roles_played'][0]['critical']
    assert 'tanımlı rol bulunamadı' not in result['warning'] and '155153' in result['warning']
    logged = investigate(None, {**finding, 'log_only': True})
    assert 'yalnızca kayıt' in logged['roles_played'][0]['role'] and not logged['roles_played'][0]['critical']


def test_deep_engine_records_read_as_sentences():
    """2.2.48 field report: 'pending' was the whole sentence and deep_engine_evidence was an undefined kind."""
    from satsuma import record_catalog as catalog
    assert catalog.describe('deep_engine_evidence')['known']
    line = catalog.render('deep_engine_evidence', {'rule_id': 'SATSUMA-IMPACT-001', 'severity': 'critical', 'window_events': 48,
                                                   'authorization': 'none'}, 10.0)
    assert line['text'] == 'Yıkıcı dosya silme komutu · derin motor gözlemi' and '48 olaylık pencere' in line['detail']
    assert line['chip'] == 'Kritik'
    review = catalog.render('deep_rule_review_events', {'status': 'pending', 'rule_id': 'SATSUMA-DISC-001',
                                                        'timestamp': '2026-11-18T10:00:00', 'process': {'exe': '/usr/bin/uname'}}, 20.0)
    assert review['text'] == 'Sistem bilgisi toplama: onayınızı bekliyor' and review['time'] == 20.0
    assert '/usr/bin/uname' in review['detail']
    rejected = catalog.render('deep_rule_review_events', {'status': 'operator_label_rejected',
                                                          'review_evidence': {'rule_id': 'SATSUMA-DISC-001'}}, 1.0)
    assert rejected['chip'] == 'Yanlış alarm olarak işaretlendi'
