"""2.2.62: permanent hidepid switched by the owner; services that must see everything get the group."""
from types import SimpleNamespace

from satsuma import hidepid


def test_enable_writes_one_proc_line_and_the_group_dropins(tmp_path):
    fstab, units = tmp_path / 'fstab', tmp_path / 'units'
    fstab.write_text('UUID=1 / btrfs defaults 0 0\nproc /proc proc defaults,hidepid=2 0 0\n')
    out = hidepid.enable(fstab, units, group_lookup=lambda name: SimpleNamespace(gr_gid=977))
    text = fstab.read_text()
    assert text.count('/proc') == 1 and 'hidepid=invisible,gid=977' in text and 'UUID=1 / btrfs' in text
    assert hidepid.configured(fstab)
    for unit in ('polkit.service', 'systemd-logind.service', 'satsuma-core-security-scan.service'):
        assert 'SupplementaryGroups=satsuma-proc' in (units / (unit + '.d') / hidepid.DROPIN).read_text()
    assert out['gid'] == 977
    hidepid.enable(fstab, units, group_lookup=lambda name: SimpleNamespace(gr_gid=977))
    assert fstab.read_text().count('/proc') == 1


def test_disable_removes_only_satsumas_lines(tmp_path):
    fstab, units = tmp_path / 'fstab', tmp_path / 'units'
    fstab.write_text('UUID=1 / btrfs defaults 0 0\n')
    hidepid.enable(fstab, units, group_lookup=lambda name: SimpleNamespace(gr_gid=5))
    hidepid.disable(fstab, units)
    assert fstab.read_text() == 'UUID=1 / btrfs defaults 0 0\n' and not hidepid.configured(fstab)
    assert not list(units.rglob(hidepid.DROPIN))


def test_active_reads_the_proc_mount(tmp_path):
    info = tmp_path / 'mountinfo'
    info.write_text('22 1 0:21 / /proc rw,nosuid shared:13 - proc proc rw,hidepid=invisible,gid=977\n')
    assert hidepid.active(info)
    info.write_text('22 1 0:21 / /proc rw,nosuid shared:13 - proc proc rw\n')
    assert not hidepid.active(info)
