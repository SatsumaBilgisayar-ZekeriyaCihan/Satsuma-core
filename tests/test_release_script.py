"""Every release folder is created once, with its real digest.

Field photo 2026-10-25: release/2.2.7's digest lines changed from the 2.2.6
placeholder to the real value in a second commit, which looked like
tampering. packaging/release.sh now builds first and commits the folder once.

Her sürüm klasörü bir kez, gerçek özetiyle oluşturulur.
"""
import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RELEASES = sorted(p for p in (ROOT / 'release').iterdir() if p.is_dir() and (p / 'SHA256SUMS').exists()) if (ROOT / 'release').is_dir() else []


@pytest.mark.parametrize('folder', RELEASES, ids=lambda p: p.name)
def test_published_digest_matches_the_package_everywhere(folder):
    entries=[]
    for line in (folder / 'SHA256SUMS').read_text().splitlines():
        if not line.strip():continue
        digest,name=line.split(maxsplit=1)
        assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
        assert Path(name).name==name, 'Release manifest must not escape its folder'
        assert hashlib.sha256((folder/name).read_bytes()).hexdigest()==digest
        entries.append((digest,name))
    assert entries, 'Empty release manifest'
    packages=[(digest,name) for digest,name in entries if name.endswith('.rpm')]
    assert len(packages)==1
    digest,name=packages[0]
    expected=('satsuma-core-2.2.15-2.inceleme1.fc40.x86_64.rpm'
              if folder.name=='2.2.15-inceleme-fc40'
              else f'satsuma-core-{folder.name}-1.fc44.x86_64.rpm')
    assert name==expected
    if (folder / 'kur.sh').exists():
        assert f'SHA256={digest}' in (folder / 'kur.sh').read_text()
    if (folder / 'KURULUM.md').exists():
        assert digest in (folder / 'KURULUM.md').read_text()


def _git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True).stdout


def test_release_script_makes_one_commit_with_the_real_digest(tmp_path):
    repo = tmp_path / 'repo'
    old = (ROOT / 'VERSION').read_text().strip()
    major, minor, patch = old.split('.')
    new_v = f'{major}.{minor}.{int(patch) + 1}'
    for rel in ('VERSION', 'satsuma/__init__.py', 'installer/release_install.py', 'packaging/satsuma-core.spec',
                'packaging/release.sh', f'release/{old}/SHA256SUMS'):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        if (ROOT / rel).exists():
            shutil.copy2(ROOT / rel, repo / rel)
        else:  # built release folders are not kept in the source tree
            (repo / rel).write_text(f'{"0" * 64}  satsuma-core-{old}-1.fc44.x86_64.rpm\n')
    # Stub build: same tarball name line as the real build.sh, fake package.
    (repo / 'packaging/build.sh').write_text(
        '#!/bin/bash\n# satsuma-core-' + old + '\nv=$(cat VERSION)\nmkdir -p "$SATSUMA_RPM_BUILD_ROOT/RPMS/x86_64"\n'
        'echo "paket $v" > "$SATSUMA_RPM_BUILD_ROOT/RPMS/x86_64/satsuma-core-$v-1.fc44.x86_64.rpm"\n')
    (repo / f'release/{old}/satsuma-core-{old}-1.fc44.x86_64.rpm').write_text('eski')
    _git(tmp_path, 'init', '-q', str(repo))
    _git(repo, 'config', 'user.email', 't@example.com'); _git(repo, 'config', 'user.name', 't')
    _git(repo, 'add', '-A'); _git(repo, 'commit', '-q', '-m', 'base')
    (repo / 'docs').mkdir()
    (repo / f'docs/RELEASE-{new_v}.md').write_text('# new\n')
    (tmp_path / 'msg').write_text('Release\n\n---\n\nSürüm\n')
    out = subprocess.run(['bash', 'packaging/release.sh', new_v, str(tmp_path / 'msg')], cwd=repo,
                         capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path),
                         'SATSUMA_RPM_BUILD_ROOT': str(tmp_path / 'build')})
    assert out.returncode == 0, out.stderr
    assert _git(repo, 'rev-list', '--count', 'HEAD') == '2\n'
    files = _git(repo, 'show', '--name-only', '--format=', 'HEAD').split()
    # Only the package and its digest are published (user decision 2026-10-26).
    assert sorted(f for f in files if f.startswith('release/')) == [
        f'release/{new_v}/SHA256SUMS', f'release/{new_v}/satsuma-core-{new_v}-1.fc44.x86_64.rpm']
    real = hashlib.sha256(f'paket {new_v}\n'.encode()).hexdigest()
    new = repo / f'release/{new_v}'
    assert (new / 'SHA256SUMS').read_text() == f'{real}  satsuma-core-{new_v}-1.fc44.x86_64.rpm\n'
    assert sorted(p.name for p in new.iterdir()) == ['SHA256SUMS', f'satsuma-core-{new_v}-1.fc44.x86_64.rpm']
    assert (repo / 'VERSION').read_text().strip() == new_v
    # A published folder is never rewritten.
    again = subprocess.run(['bash', 'packaging/release.sh', new_v, str(tmp_path / 'msg')], cwd=repo,
                           capture_output=True, text=True)
    assert again.returncode != 0
