"""satsuma-core-windows is tested in its own directory, so its tests always run with Satsuma's.

satsuma-core-windows kendi klasöründe test edilir; testleri Satsuma'nınkilerle birlikte hep çalışır.
"""
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / 'satsuma-core-windows'


def test_windows_tests_pass():
    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests'],
                            cwd=PROJECT, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]


def test_windows_rules_share_the_linux_threshold():
    from satsuma import peer_watch
    text = (PROJECT / 'satsuma_win/peers.py').read_text()
    assert 'from satsuma.peer_watch import NO_PTR, THRESHOLD, PeerTable, PtrResolver' in text
    assert peer_watch.THRESHOLD == 5


def test_exe_is_built_on_github_after_the_tests_and_asks_for_administrator():
    import yaml
    workflow = yaml.safe_load((PROJECT.parent / '.github/workflows/satsuma-core-windows.yml').read_text())
    steps = [s.get('name') or s.get('uses') for s in workflow['jobs']['build']['steps']]
    assert steps.index('Tests (on Windows)') < steps.index('Build satsuma-core-windows.exe')
    end_to_end = 'Service end to end (install, verify, uninstall on this Windows server)'
    assert steps.index('Build satsuma-core-windows.exe') < steps.index('Digest')
    # The exe is published only by the service job, after the service proof on a second server.
    # Exe yalnızca hizmet işi tarafından, ikinci sunucudaki hizmet kanıtından sonra yayımlanır.
    service = workflow['jobs']['service']
    assert service['needs'] == 'build'
    names = [s.get('name') or s.get('uses') for s in service['steps']]
    published = [i for i, s in enumerate(service['steps'])
                 if s.get('uses', '').startswith('actions/upload-artifact')
                 and s['with']['name'] == 'satsuma-core-windows-exe']
    assert published and names.index(end_to_end) < published[0]
    assert all(s['with']['name'] != 'satsuma-core-windows-exe' for s in workflow['jobs']['build']['steps']
               if s.get('uses', '').startswith('actions/upload-artifact'))
    build = next(s for s in workflow['jobs']['build']['steps'] if s.get('name') == 'Build satsuma-core-windows.exe')
    assert '--uac-admin' in build['run'] and 'satsuma_core_windows.py' in build['run']
    assert workflow['jobs']['build']['runs-on'].startswith('windows')
    assert (PROJECT / 'satsuma_core_windows.py').exists()
