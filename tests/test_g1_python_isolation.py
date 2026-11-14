"""Audit G1: no root Python process reads PYTHON* variables or root's user site.

A ``.pth`` file in /root/.local/lib/python3*/site-packages runs on every start
of a Python process that does not ignore the user site, and the integrity
manifest does not cover that directory. Every root launch therefore uses
``-I``, or ``-E -s`` with a fixed root-owned working directory where ``-m``
needs the current directory on the path.

Denetim G1: hiçbir root Python süreci PYTHON* değişkenlerini ya da root'un
kullanıcı paket dizinini okumaz. Bu dizindeki bir ``.pth`` dosyası her
açılışta çalışır ve bütünlük manifesti onu kapsamaz. Bu yüzden her root
çalıştırması ``-I`` kullanır; ``-m`` için çalışma dizini gerekiyorsa root'a
ait sabit bir dizinde ``-E -s`` kullanır.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
CALL = re.compile(r'/usr/bin/python3((?:\s+-\S+(?:\s+pycache_prefix=\S+)?)*)')


def flags(text):
    return set(re.findall(r'(?<!\S)-([A-Za-z])\b', text))


def isolated(options, module_dir_fixed):
    found = flags(options)
    return 'I' in found or ({'E', 's'} <= found and module_dir_fixed)


UNITS = sorted((ROOT / 'systemd').glob('*.service'))


@pytest.mark.parametrize('unit', UNITS, ids=lambda p: p.name)
def test_every_python_in_a_unit_ignores_environment_and_user_site(unit):
    text = unit.read_text()
    fixed = 'WorkingDirectory=/opt/satsuma-core' in text
    for line in text.splitlines():
        if line.startswith('Exec') and '/usr/bin/python3' in line:
            assert isolated(CALL.search(line).group(1), fixed), line


def test_the_six_services_from_the_audit_are_covered():
    for name in ('operator', 'reader', 'guardian', 'self-health', 'configuration', 'core-dns-refresh'):
        text = (ROOT / f'systemd/satsuma-{name}.service').read_text()
        assert ' -E -s -B -m satsuma.' in text and 'WorkingDirectory=/opt/satsuma-core' in text


def test_install_scriptlets_run_python_isolated():
    for line in (ROOT / 'packaging/satsuma-core.spec').read_text().splitlines():
        if '/usr/bin/python3' not in line or line.lstrip().startswith(('Requires', '#')):
            continue
        options = CALL.search(line).group(1)
        assert isolated(options, 'cd /opt/satsuma-core &&' in line), line


def test_root_admin_cli_is_isolated():
    first = (ROOT / 'packaging/root/usr/bin/satsuma-admin').read_text().splitlines()[0]
    assert first == '#!/usr/bin/python3 -I'
