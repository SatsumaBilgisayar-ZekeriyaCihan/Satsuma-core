"""Phase 2: every Satsuma unit the plan names runs with NoNewPrivileges."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNITS = ('core-dns-refresh', 'firewall-watch', 'image', 'network-modes', 'network',
         'quarantine-confirm', 'quarantine-rollback')


def test_phase2_units_cannot_gain_privileges():
    for unit in UNITS:
        assert 'NoNewPrivileges=yes' in (ROOT / f'systemd/satsuma-{unit}.service').read_text(), unit


def test_firstboot_exception_is_written_down():
    text = (ROOT / 'systemd/satsuma-ostree-firstboot.service').read_text()
    assert 'NoNewPrivileges=yes' not in text and 'No NoNewPrivileges on purpose' in text


def test_reader_runs_as_its_own_user_with_read_only_capability():
    unit = (ROOT / 'systemd/satsuma-reader.service').read_text()
    assert 'User=satsuma-reader' in unit and 'User=root' not in unit
    assert 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH\n' in unit and 'AmbientCapabilities=CAP_DAC_READ_SEARCH\n' in unit
    sysusers = (ROOT / 'packaging/root/usr/lib/sysusers.d/satsuma-core.conf').read_text()
    assert 'u satsuma-reader -:satsuma-reader' in sysusers
    assert 'u satsuma-reader -:satsuma-reader' in (ROOT / 'packaging/satsuma-core.spec').read_text()


def test_reader_sees_suricata_through_the_unit_not_proc(monkeypatch):
    from satsuma import dashboard_api as api
    monkeypatch.setattr(api, '_unit_active', lambda unit, runner=None: unit == 'satsuma-suricata-ips.service')
    assert api._proc_running('suricata') == 'RUNNING'
