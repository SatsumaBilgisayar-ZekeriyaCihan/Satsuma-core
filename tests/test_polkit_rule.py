"""2.2.53: Satsuma's own first-password screen is not a critical pkexec escalation.

Field 2026-11-19: "[CRITICAL] Şüpheli pkexec hedef/argüman kullanımı … PID 5440
python3.15: öldürülecek süreç". The dashboard runs
"pkexec /usr/bin/satsuma-enroll-desktop --user NAME --password-stdin"; the rule
matched the words "pkexec" and "--user" anywhere, although --user belonged to
the program pkexec runs. Only pkexec's own options count now.
"""
import json
from pathlib import Path

import pytest

from satsuma.ai_rule_package import digest
from satsuma.dashboard_api import RULES_DIR
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).resolve().parents[1]
RULE = 'SATSUMA-POLKIT-001'


@pytest.fixture(scope='module')
def engine():
    return SmartRuleEngine(RULES_DIR)


def hits(engine, cmd):
    rule = next(r for r in engine.rules if r['_id'] == RULE)
    return engine._matches(rule['base_match'], {'source': 'sys_proc', 'cmd': cmd, 'exe': '/usr/bin/pkexec'})


@pytest.mark.parametrize('cmd', [
    '/usr/bin/pkexec /usr/bin/satsuma-enroll-desktop --user omer --password-stdin',
    'pkexec /usr/bin/gparted',
    'pkexec env --user x',
    'pkexec /usr/bin/flatpak --user install x',
])
def test_arguments_of_the_program_pkexec_runs_do_not_count(engine, cmd):
    assert not hits(engine, cmd)


@pytest.mark.parametrize('cmd', [
    'pkexec --user root /bin/sh', '/usr/bin/pkexec --user=root /bin/sh', 'pkexec /tmp/x',
    'pkexec --user omer /dev/shm/a', 'pkexec --keep-cwd /var/tmp/y', "sh -c 'pkexec --user root id'",
])
def test_real_suspicious_uses_still_match(engine, cmd):
    assert hits(engine, cmd)


def test_catalog_fingerprint_follows_the_rule(engine):
    rule = next(r for r in engine.rules if r['_id'] == RULE)
    content = {k: v for k, v in rule.items() if not k.startswith('_')}
    catalog = json.loads((ROOT / 'schemas/rule-response-catalog-v1.json').read_text())
    row = next(r for r in catalog['rules'] if r['rule_id'] == RULE)
    assert row['detection_sha256'] == digest(content) == rule['_content_hash']
    assert row['match'] == rule['base_match']


def test_the_dashboard_still_calls_pkexec_that_way():
    text = (ROOT / 'satsuma/dashboard_qt/first_password.py').read_text()
    assert "'/usr/bin/pkexec',['/usr/bin/satsuma-enroll-desktop','--user'" in text
