"""SATSUMA-CLOUD-001 matches real metadata access, not searches for it (field log 2026-10-25).

SATSUMA-CLOUD-001 gerçek metadata erişimini yakalar, onu arayan komutları değil.
"""
from pathlib import Path

import pytest

from satsuma.smart_rules import SmartRuleEngine, _split_script

ROOT = Path(__file__).parents[1]


@pytest.fixture(scope='module')
def engine():
    return SmartRuleEngine(ROOT / 'rules')


def cloud(engine, cmd):
    return any(f['rule_id'] == 'SATSUMA-CLOUD-001' for f in engine.match({'source': 'sys_proc', 'cmd': cmd, 'pid': 1}))


@pytest.mark.parametrize('cmd', [
    'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'wget -qO- http://metadata.google.internal/computeMetadata/v1/',
    'sudo -u nobody curl -s 169.254.169.254',
    'bash -c "ausearch -i | grep x; curl http://169.254.169.254/"',
    'python3 -c "import urllib.request as u; u.urlopen(\'http://169.254.169.254/latest/meta-data/\')"',
])
def test_real_access_is_found(engine, cmd):
    assert cloud(engine, cmd)


@pytest.mark.parametrize('cmd', [
    'grep -rn 169.254.169.254 /var/log/audit',
    "bash -c \"sudo ausearch -i --start today | grep -E '169.254.169.254|metadata.google.internal'\"",
    'echo /latest/meta-data/',
    'rg metadata.google.internal /etc',
])
def test_searching_for_it_is_not_access(engine, cmd):
    assert not cloud(engine, cmd)


def test_scripts_split_into_simple_commands_with_quotes_respected():
    assert _split_script("a -x | b 'c;d' && e; (f) & g") == ('a -x', "b 'c;d'", 'e', 'f', 'g')
    assert _split_script("unbalanced 'quote") == ("unbalanced 'quote",)
