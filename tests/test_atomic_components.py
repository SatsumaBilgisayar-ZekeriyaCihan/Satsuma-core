"""Fedora Atomic field report 2026-11-18 (2.2.42): clamonacc, retired ram_v2, OPNsense status."""
import json
import os
import sqlite3
from pathlib import Path

import pytest

from installer import onaccess_setup as onaccess

BASE = ('Foreground no\nLocalSocket /run/clamd.scan/clamd.sock\nUser clamscan\n')


@pytest.fixture
def atomic_home(tmp_path, monkeypatch):
    real = tmp_path / 'var/home'
    real.mkdir(parents=True)
    link = tmp_path / 'home'
    os.symlink('var/home', link)
    monkeypatch.setattr(onaccess, 'PROTECTED', (str(link),))
    monkeypatch.setattr(onaccess.pwd, 'getpwnam', lambda user: True)
    return link, real


def test_on_access_watches_the_real_folder(atomic_home):
    link, real = atomic_home
    text = onaccess.render(BASE)
    assert f'OnAccessIncludePath {real}' in text and f'OnAccessIncludePath {link}\n' not in text


def test_a_block_written_with_the_link_is_moved_to_the_real_folder(atomic_home, tmp_path, monkeypatch):
    link, real = atomic_home
    if os.geteuid() != 0:
        pytest.skip('trusted_file wants a root-owned configuration')
    config = tmp_path / 'scan.conf'
    old = BASE + '\n' + '\n'.join([onaccess.START, f'OnAccessIncludePath {link}', 'OnAccessPrevention yes',
                                    'OnAccessExcludeUname clamscan', 'OnAccessMaxFileSize 5M', onaccess.END]) + '\n'
    config.write_text(old); os.chmod(config, 0o600)
    monkeypatch.setattr(onaccess, 'CONFIG', config)
    assert onaccess.migrate_link_paths(config)
    text = config.read_text()
    assert f'OnAccessIncludePath {real}\n' in text and text.startswith(BASE)
    assert onaccess.verify()
    assert not onaccess.migrate_link_paths(config)        # second run changes nothing


def test_normal_fedora_keeps_home(monkeypatch):
    monkeypatch.setattr(onaccess, 'PROTECTED', ('/',))
    assert onaccess.protected_paths() == ['/']


def test_opnsense_without_a_log_is_not_configured_not_a_fault(tmp_path):
    from workers.opnsense.worker import WorkerOpnsense

    class Store(dict):
        def set(self, key, value): self[key] = value
        def get(self, key, default=None): return dict.get(self, key, default)
    store = Store()
    report = WorkerOpnsense(store, {'opnsense_mode': 'file', 'opnsense_log_path': str(tmp_path / 'absent.log')}).collect()
    assert report['status'] == 'NOT_CONFIGURED' and 'yapılandırılmamış' in report['reason']
    link = tmp_path / 'link.log'; os.symlink(tmp_path / 'x', link)
    report = WorkerOpnsense(store, {'opnsense_mode': 'file', 'opnsense_log_path': str(link)}).collect()
    assert report['status'] == 'ERROR'                    # a symlinked log is still a fault


def test_panel_hides_retired_components_and_names_not_configured(tmp_path, monkeypatch):
    from satsuma import dashboard_api
    db = tmp_path / 'core.db'
    with sqlite3.connect(db) as c:
        c.execute('CREATE TABLE state(key TEXT PRIMARY KEY, body TEXT)')
        import time
        rows = {'worker.ram_v2.health': {'status': 'RETIRED', 'updated_at': time.time()},
                'worker.opnsense.health': {'status': 'NOT_CONFIGURED', 'updated_at': time.time(), 'reason': 'yok'}}
        c.executemany('INSERT INTO state VALUES(?,?)', [(k, json.dumps(v)) for k, v in rows.items()])
    monkeypatch.setattr(dashboard_api, 'DB_PATH', str(db))
    monkeypatch.setattr(dashboard_api, 'HOST_DB_PATH', str(tmp_path / 'absent.db'))
    result = dashboard_api.m_workers()
    rows = result.get('workers', result) if isinstance(result, dict) else result
    names = {r['name']: r for r in (rows.values() if isinstance(rows, dict) else rows)}
    assert 'ram_v2' not in names
    assert names['opnsense']['status_tr'] == 'Yapılandırılmamış'
