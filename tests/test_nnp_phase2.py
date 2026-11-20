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


def test_reader_runs_as_root_again_until_verified_in_the_field():
    """2.2.64: as satsuma-reader the panel read nothing on the owner's computer (2026-11-20)."""
    unit = (ROOT / 'systemd/satsuma-reader.service').read_text()
    assert 'User=root' in unit and 'User=satsuma-reader' not in unit and 'AmbientCapabilities' not in unit


def test_reader_sees_suricata_through_the_unit_not_proc(monkeypatch):
    from satsuma import dashboard_api as api
    monkeypatch.setattr(api, '_unit_active', lambda unit, runner=None: unit == 'satsuma-suricata-ips.service')
    assert api._proc_running('suricata') == 'RUNNING'
