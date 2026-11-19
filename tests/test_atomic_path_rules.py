"""2.2.54: file rules see Fedora Atomic's real paths (/var/home, /var/roothome).

Field 2026-11-19: audit reports /var/home/u/.ssh/authorized_keys; the rules said
/home/*/.ssh/authorized_keys and never matched.
"""
import time

import pytest

from satsuma.dashboard_api import RULES_DIR
from satsuma.smart_rules import SmartRuleEngine


@pytest.fixture(scope='module')
def engine():
    return SmartRuleEngine(RULES_DIR)


def write(engine, path, uid='1000'):
    event = {'source': 'audit', 'kind': 'file_access', 'action': 'file_access', 'path': path, 'file_path': path,
             'operation': 'write', 'nametype': 'CREATE', 'exe': '/usr/bin/tee', 'cmd': 'tee ' + path, 'uid': uid,
             'pid': '4242', 'timestamp': time.time()}
    return {f['rule_id'] for f in engine.match(event)}


@pytest.mark.parametrize('path,rule', [
    ('/var/home/u/.ssh/authorized_keys', 'SATSUMA-PERS-003'),
    ('/var/roothome/.ssh/authorized_keys', 'SATSUMA-PERS-003'),
    ('/var/home/u/.bashrc', 'SATSUMA-PERS-004'),
    ('/var/home/u/.config/systemd/user/x.service', 'SATSUMA-PERS-002'),
    ('/var/home/u/.config/autostart/x.desktop', 'SATSUMA-PERS-006'),
])
def test_real_atomic_paths_match(engine, path, rule):
    assert rule in write(engine, path)


def test_unrelated_var_paths_do_not(engine):
    assert not write(engine, '/var/home/u/Belgeler/notlar.txt') & {'SATSUMA-PERS-003', 'SATSUMA-PERS-004'}


def test_aliases_only_rewrite_the_start():
    forms = SmartRuleEngine._path_forms('/var/home/u/.bashrc')
    assert forms == ('/var/home/u/.bashrc', '/home/u/.bashrc')
    assert SmartRuleEngine._path_forms('/data/var/home/x') == ('/data/var/home/x',)
