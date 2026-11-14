"""One removal script for every Satsuma version: release/kaldir.sh.

Static safety checks: USB input and the old sudo gate are handled before any
package goes, every change goes through the dry-run switch, only
/usr/bin/sudo is used, the protected archive is never touched, and each
release's kur.sh --kaldir hands over to the same script.

Her Satsuma sürümü için tek kaldırma betiği: release/kaldir.sh.

Statik güvenlik denetimleri: USB girişi ve eski sudo kapısı herhangi bir paket
kaldırılmadan önce ele alınır, her değişiklik kuru çalışma anahtarından geçer,
yalnızca /usr/bin/sudo kullanılır, korunan arşive hiç dokunulmaz ve her
sürümün kur.sh --kaldir'i aynı betiğe devreder.
"""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / 'release/kaldir.sh'
TEXT = SCRIPT.read_text()
READ_ONLY = ('-v', 'test ', 'grep ', 'find ', 'grubby --info', 'cat ', 'nft list tables', '/usr/bin/python3 -I -c')


def test_parses():
    subprocess.run(['bash', '-n', str(SCRIPT)], check=True)


def test_no_version_specific_removal_scripts():
    assert sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / 'release').rglob('kaldir*.sh')) == ['release/kaldir.sh']
    assert re.search(r'\b2\.\d+\.\d+-\d', TEXT) is None  # no pinned package version


def test_every_satsuma_package_is_removed():
    assert "rpm -qa --qf '%{NAME}\\n' 'satsuma*'" in TEXT
    assert 'yap dnf remove -y "${PAKETLER[@]}"' in TEXT


def test_usb_and_sudo_gate_come_before_any_package_removal():
    package = TEXT.index('yap dnf remove')
    for step in ('--remove-args="$ARG"', 'Parametre hâlâ duruyor', '--usbguard-restore',
                 'SATSUMA_SUDO_GATE/d', 'visudo -c', 'nft_satsuma;'):
        assert TEXT.index(step) < package, step


def test_queue_tables_are_removed_after_the_package():
    assert TEXT.index('yap dnf remove') < TEXT.index('yap nft delete table inet')


def test_only_absolute_sudo_and_every_change_is_dry_runnable():
    assert 'S=/usr/bin/sudo' in TEXT
    body = TEXT.split('$S -v\n', 1)[1]
    assert re.search(r'(^|[\s;(|&])sudo\s', '\n'.join(
        l for l in body.splitlines()
        if not l.lstrip().startswith('#') and not re.search(r'(echo|uyar|printf).*sudo', l))) is None
    for line in body.splitlines():
        for call in re.findall(r'\$S ([^;|&)]+)', line):
            assert call.startswith(READ_ONLY) or call.startswith('systemctl reboot'), line


def test_nftables_reinstall_waits_until_the_firewall_is_gone():
    # Field report 2026-10-25: dnf reinstall nftables in step 3 could not reach
    # the mirrors through Satsuma's own firewall, and set -e stopped the script.
    step3 = TEXT.split('3/11', 1)[1].split('4/11', 1)[0]
    assert 'dnf reinstall' not in step3
    reinstall = TEXT.index('yap dnf reinstall -y nftables')
    assert TEXT.index('yap nft delete table inet') < reinstall
    assert TEXT.index('yap dnf remove') < reinstall
    # With nftables.service still pointing at Satsuma, no reboot is offered.
    guard = TEXT.index('YENİDEN BAŞLATMAYIN')
    assert reinstall < guard < TEXT.index('sor "Şimdi yeniden başlatılsın mı?"')


def test_remote_server_masks_stay_unless_the_user_says_yes():
    step = TEXT.split('9/11', 1)[1].split('10/11', 1)[0]
    assert 'if sor "Maskeler' in step and '(( KURU )) ||' not in step


def test_protected_archive_is_never_touched():
    assert TEXT.index('-name "$KORUNAN"') < TEXT.index('yap tar ') < TEXT.index('rm -rf "${var[@]}"')
    assert 'unzip' not in TEXT and '7z' not in TEXT


def test_no_pipe_into_grep_q_under_pipefail():
    assert '| grep -q' not in TEXT


def test_release_kur_sh_hands_removal_to_the_shared_script():
    for kur in (ROOT / 'release').glob('2.2.[3-9]*/kur.sh'):
        text = kur.read_text()
        assert 'exec bash "$aday"' in text and 'release/kaldir.sh' in text
        assert 'dnf remove' not in text


def test_dry_run_on_a_clean_system_changes_nothing(tmp_path):
    # Runs the real script; sudo/grubby/rpm are stubs that only log.
    log = tmp_path / 'log'
    for name in ('sudo', 'rpm', 'systemctl', 'find', 'mountpoint', 'grubby', 'nft'):
        stub = tmp_path / name
        stub.write_text('#!/bin/sh\necho "%s $*" >> %s\n' % (name, log))
        stub.chmod(0o755)
    text = TEXT.replace('S=/usr/bin/sudo', 'S=' + str(tmp_path / 'sudo'))
    text = text.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'export PATH=%s:/usr/bin:/bin' % tmp_path)
    text = text.replace('source /etc/os-release', 'ID=fedora')
    script = tmp_path / 'kaldir.sh'
    script.write_text(text)
    out = subprocess.run(['bash', str(script), '--kuru'], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert 'Kuru çalışma bitti' in out.stdout
    calls = log.read_text().splitlines()
    sudo_calls = [c for c in calls if c.startswith('sudo ')]
    assert sudo_calls and all(c[5:].startswith(READ_ONLY) for c in sudo_calls), sudo_calls
