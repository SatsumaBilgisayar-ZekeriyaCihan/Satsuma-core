"""Blocked-address page: one unreadable source does not hide the rest, reasons are plain Turkish.

Engellenen adresler sayfası: okunamayan tek bir kaynak diğerlerini gizlemez,
nedenler sade Türkçedir.
"""
import sqlite3

from satsuma import dashboard_api


def test_unreadable_suricata_guard_keeps_the_otx_blocks(monkeypatch, tmp_path):
    db = tmp_path / 'core.db'
    con = sqlite3.connect(db)
    con.executescript("CREATE TABLE state(key TEXT PRIMARY KEY, body TEXT NOT NULL);"
                      "CREATE TABLE records(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, created REAL NOT NULL, body TEXT NOT NULL);")
    con.execute("INSERT INTO state VALUES('policy_effective', '{\"workers\": {}}')")
    con.execute("INSERT INTO state VALUES('persistent_blocks', ?)",
                ('{"203.0.113.9": {"reason": "Operator OTX threshold (TLS verified): Curiosity; interesting", "added_at": 1}}',))
    con.commit(); con.close()
    monkeypatch.setattr(dashboard_api, '_connect', lambda: dashboard_api._connect_at(db))
    real = sqlite3.connect
    def connect(target, *a, **k):
        if 'guard.sqlite' in str(target):
            raise sqlite3.OperationalError('unable to open database file')
        return real(target, *a, **k)
    monkeypatch.setattr(dashboard_api.sqlite3, 'connect', connect)
    monkeypatch.setattr(dashboard_api.Path, 'is_file', lambda self: True if 'guard.sqlite' in str(self) else self.exists())
    result = dashboard_api.m_response()
    assert result['data_state'] == 'OK', result.get('error')
    assert result['suricata_guard_state'] == 'UNREADABLE'
    assert [b['ip'] for b in result['blocked_ips']] == ['203.0.113.9']


def test_otx_reason_is_shown_in_plain_turkish_and_shortened():
    from satsuma.dashboard_qt.panels.network_response import NetworkResponsePanel, display_rows
    long = 'Operator OTX threshold (TLS verified): ' + 'AnyDesk Hijack | ' * 20
    rows = display_rows([{'ip': '203.0.113.9', 'reason': long}])
    assert rows[0]['reason'].startswith('OTX: eşikten fazla tehdit raporu (TLS doğrulandı) — raporlar: AnyDesk Hijack')
    assert len(rows[0]['reason']) == NetworkResponsePanel.REASON_LIMIT and rows[0]['reason'].endswith('…')
    assert 'saldırının türü değildir' in NetworkResponsePanel.PANEL_SUBTITLE
