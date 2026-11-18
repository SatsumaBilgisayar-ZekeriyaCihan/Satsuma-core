"""Satsuma ClamAV on-access installer: default enabled on Fedora, any host type.

Guards pre-existing clamd config; never overwrites custom on-access policies.
Installer invokes `install` before enabling the Satsuma on-access service.
`verify` checks configuration without modifying the host.
"""
import os
from pathlib import Path
import pwd
import stat

CONFIG = Path('/etc/clamd.d/scan.conf')
BACKUP = Path('/var/lib/satsuma-core/av-onaccess-backup/scan.conf')
START = '# SATSUMA_ONACCESS_BEGIN'
END = '# SATSUMA_ONACCESS_END'
# Intentionally bounded: protecting / (or all mounts) can deadlock the host.
# Explicitly report this limited initial coverage instead of suggesting full-system prevention.
PROTECTED = ('/home',)


def protected_paths():
    """PROTECTED as real folders.

    2.2.42 (owner, Fedora Atomic 2026-11-18: satsuma-clamonacc failed after every
    restart): on Fedora Atomic /home is a link to var/home and clamonacc was
    told to watch the link. The configuration names the real folder; on a
    normal Fedora system the path is unchanged.
    Atomic'te /home, var/home'a bağdır; yapılandırma gerçek klasörü yazar.
    """
    return [os.path.realpath(path) for path in PROTECTED]

def properties(config_text):
    found = {}
    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'): continue
        key, _, value = line.partition(' ')
        found.setdefault(key, []).append(value.strip())
    return found

def validate_local_socket(opts):
    """Reject ambiguous or retired ClamAV endpoints before changing configuration."""
    from pathlib import PurePosixPath
    sockets = opts.get('LocalSocket', [])
    if len(sockets) != 1 or opts.get('TCPSocket') or opts.get('TCPAddr'):
        raise RuntimeError('Exactly one local Unix socket and no TCP listener required')
    raw = sockets[0]
    endpoint = PurePosixPath(raw)
    if (not endpoint.is_absolute() or '..' in endpoint.parts or
            str(endpoint).startswith('/run/satsuma-ram-clamd/')):
        raise RuntimeError('Unsafe ClamAV Unix socket path')


def render(config_text):
    if START in config_text or END in config_text:
        raise RuntimeError('Managed block already present')
    opts = properties(config_text)
    validate_local_socket(opts)
    if any(key.startswith('OnAccess') for key in opts):
        raise RuntimeError('Existing on-access policy needs explicit reconciliation')
    user = opts.get('User', ['clamscan'])[0]
    pwd.getpwnam(user)
    lines = [START, *(f'OnAccessIncludePath {path}' for path in protected_paths()),
             'OnAccessPrevention yes', f'OnAccessExcludeUname {user}',
             'OnAccessMaxFileSize 5M', END]
    return config_text.rstrip() + '\n\n' + '\n'.join(lines) + '\n'

def trusted_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise RuntimeError('Untrusted file: '+str(path))

def verify():
    trusted_file(CONFIG)
    text = CONFIG.read_text()
    opts = properties(text)
    if text.count(START) != 1 or text.count(END) != 1:
        raise RuntimeError('Satsuma on-access configuration missing')
    if opts.get('OnAccessPrevention') != ['yes'] or opts.get('OnAccessIncludePath') != protected_paths():
        raise RuntimeError('On-access prevention or protected paths differ')
    validate_local_socket(opts)
    user = opts.get('User', ['clamscan'])[0]
    if opts.get('OnAccessExcludeUname') != [user]:
        raise RuntimeError('ClamAV daemon must be excluded to prevent recursion')
    return True

def migrate_link_paths(config=CONFIG):
    """Rewrite a managed block written with the link path (/home) to the real folder.

    Only lines inside Satsuma's own block are touched; returns True when changed.
    """
    trusted_file(config)
    text = config.read_text()
    if text.count(START) != 1 or text.count(END) != 1:
        return False
    head, rest = text.split(START, 1)
    block, tail = rest.split(END, 1)
    wanted = protected_paths()
    lines = block.splitlines(keepends=True)
    current = [l.split(' ', 1)[1].strip() for l in lines if l.startswith('OnAccessIncludePath ')]
    if current == wanted or current != list(PROTECTED):
        return False
    real = iter(wanted)
    block = ''.join(f'OnAccessIncludePath {next(real)}\n' if l.startswith('OnAccessIncludePath ') else l for l in lines)
    temp = config.with_name(config.name + '.satsuma-new')
    with temp.open('x') as out:
        out.write(head + START + block + END + tail)
    os.chmod(temp, 0o600)
    os.replace(temp, config)
    return True


def install():
    if os.geteuid() != 0: raise PermissionError('root required')
    trusted_file(CONFIG)
    current = CONFIG.read_text()
    if START in current or END in current:
        if migrate_link_paths():
            verify()
            return 'Configured; protected path moved to its real folder, restart clamonacc'
        verify()
        return 'Already configured'
    new_text = render(current)
    if BACKUP.exists() or BACKUP.is_symlink():
        raise RuntimeError('Existing backup: refusing to overwrite')
    BACKUP.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    trusted_file(CONFIG)
    with BACKUP.open('xb') as out: out.write(CONFIG.read_bytes())
    os.chmod(BACKUP, 0o600)
    temp = CONFIG.with_name(CONFIG.name+'.satsuma-new')
    try:
        with temp.open('x') as out: out.write(new_text)
        os.chmod(temp, 0o600)
        os.replace(temp, CONFIG)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return 'Configured; restart clamd@scan before starting clamonacc'

def rollback():
    if os.geteuid() != 0: raise PermissionError('root required')
    trusted_file(CONFIG)
    trusted_file(BACKUP)
    current = CONFIG.read_text()
    if START not in current or END not in current:
        raise RuntimeError('Managed block missing; manual reconciliation needed')
    # Ensure external changes are not discarded during rollback.
    original = BACKUP.read_text()
    if current != render(original):
        raise RuntimeError('Configuration changed since installation; manual merge needed')
    temp = CONFIG.with_name(CONFIG.name+'.satsuma-restore')
    with temp.open('x') as out: out.write(original)
    os.chmod(temp, 0o600)
    os.replace(temp, CONFIG)
    return 'Original scan.conf restored; clamd service restart required'

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=['install','verify','rollback'])
    action=parser.parse_args().action
    print({'install':install,'verify':verify,'rollback':rollback}[action]())
