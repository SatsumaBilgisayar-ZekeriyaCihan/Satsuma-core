"""2.2.36: a network-modes start failure no longer aborts the rest of %posttrans.

2.2.36: network-modes başlatılamaması artık %posttrans'ın geri kalanını durdurmaz.

Field 2026-11-04 (2.2.35 install): satsuma-network-modes.service failed, the
start command ended in "|| exit 1", and the integrity check, MITM watch timer,
module lock, flow guard, desktop enrollment, configuration reload and health
check never ran. The failure is still reported.
Saha 2026-11-04 (2.2.35 kurulumu): satsuma-network-modes.service başlamadı,
başlatma komutu "|| exit 1" ile bitiyordu; bütünlük denetimi, MITM izleyici
zamanlayıcısı, modül kilidi, akış bekçisi, masaüstü kaydı, yapılandırma
yeniden yükleme ve sağlık kontrolü hiç çalışmadı. Hata yine bildirilir.
"""
from pathlib import Path

SPEC = Path(__file__).parents[1] / 'packaging/satsuma-core.spec'


def _posttrans():
    return SPEC.read_text().split('%posttrans\n', 1)[1].split('%postun\n', 1)[0]


def _lines(text):
    return [line.strip() for line in text.splitlines()]


def test_network_modes_is_not_in_a_fatal_start_list():
    for line in _lines(_posttrans()):
        if line.startswith('systemctl start ') and 'satsuma-network-modes.service' in line:
            assert line == 'systemctl start satsuma-network-modes.service || network_modes_failed=1'
            return
    raise AssertionError('network-modes start line not found')


def test_every_later_step_comes_after_the_non_fatal_start():
    text = _posttrans()
    start = text.index('systemctl start satsuma-network-modes.service || network_modes_failed=1')
    for later in ('systemctl start satsuma-integrity-check.service || exit 1',
                  'systemctl start satsuma-mitm-watch.timer',
                  'systemctl enable satsuma-module-lock.timer',
                  'systemctl enable --now satsuma-flow-guard.service',
                  '/usr/bin/satsuma-enroll-desktop --auto',
                  'satsuma.configuration_reload',
                  'systemctl start satsuma-self-health.service'):
        assert text.index(later) > start, later


def test_the_other_units_stay_fatal_and_are_still_started():
    text = _posttrans()
    line = [l for l in _lines(text) if l.startswith('systemctl start satsuma-configuration.path')][0]
    assert line.endswith('|| exit 1')
    for unit in ('satsuma-core.service', 'satsuma-teams.service', 'satsuma-reader.service',
                 'satsuma-operator.service', 'satsuma-integrity-check.timer', 'satsuma-core-security-scan.timer'):
        assert unit in line


def test_network_modes_is_still_enabled_at_boot():
    enable = [l for l in _lines(_posttrans()) if l.startswith('systemctl enable satsuma-configuration.path')][0]
    assert 'satsuma-network-modes.service' in enable


def test_failure_is_initialised_reported_and_never_exits():
    text = _posttrans()
    assert 'network_modes_failed=0' in text
    assert text.index('network_modes_failed=0') < text.index('|| network_modes_failed=1')
    block = text.split('if [ "$network_modes_failed" -ne 0 ]; then', 1)[1].split('\n fi', 1)[0]
    assert 'satsuma-network-modes' in block and 'exit 1' not in block
