"""Fedora Atomic (Silverblue, Kinoite, COSMIC Atomic...) differences in one place.

Owner's request 2026-11-13/18: Satsuma installs with ``rpm-ostree install``.
On an ostree system /usr is read-only, kernel arguments belong to the
deployment (``rpm-ostree kargs``, not grubby) and regular files a package puts
under /var are dropped by rpm-ostree (only directories become tmpfiles.d
entries). On a normal Fedora system nothing here changes behaviour.

Detection: /run/ostree-booted exists on every booted ostree system (ostree
creates it in the initramfs). Assumption to verify on a device: the sandbox in
which rpm-ostree runs package scripts may not show /run, so the spec also
treats "rpm-ostree present and no systemd running" as ostree.

Fedora Atomic farkları tek yerde: /usr salt okunur, çekirdek bağımsız
değişkenleri ``rpm-ostree kargs`` ile ayarlanır, paketin /var altına koyduğu
dosyaları rpm-ostree atar. Normal Fedora'da hiçbir davranış değişmez.
"""
import subprocess
from pathlib import Path

MARKER = Path('/run/ostree-booted')
RPM_OSTREE = '/usr/bin/rpm-ostree'
GRUBBY = '/usr/sbin/grubby'
SYSCTL_DIR_USR = Path('/usr/lib/sysctl.d')
SYSCTL_DIR_ETC = Path('/etc/sysctl.d')


def booted(marker=None):
    return Path(MARKER if marker is None else marker).exists()


def sysctl_dir(marker=None):
    """Where Satsuma's own sysctl files go: /usr/lib/sysctl.d, or /etc/sysctl.d on ostree."""
    return SYSCTL_DIR_ETC if booted(marker) else SYSCTL_DIR_USR


def sysctl_file(name, marker=None):
    return str(sysctl_dir(marker) / name)


def boot_entries(runner=subprocess.run, marker=None):
    """{entry: set(words)} of the command lines the next boot will use.

    grubby: one entry per installed kernel. ostree: one entry, the default
    deployment's kernel arguments (``rpm-ostree kargs`` prints them).
    """
    if booted(marker):
        result = runner([RPM_OSTREE, 'kargs'], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError('rpm-ostree kargs failed: ' + (result.stderr or '')[:200])
        return {'ostree-default-deployment': set(result.stdout.split())}
    result = runner([GRUBBY, '--info=ALL'], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError('grubby --info=ALL failed: ' + (result.stderr or '')[:200])
    entries, kernel = {}, None
    for line in result.stdout.splitlines():
        key, _, value = line.partition('=')
        value = value.strip().strip('"')
        if key == 'kernel':
            kernel = value
            entries[kernel] = set()
        elif key == 'args' and kernel is not None:
            entries[kernel] = set(value.split())
    return entries


def update_args(add=(), remove=(), runner=subprocess.run, marker=None):
    """Add and remove kernel command-line words for the next boot; the runner's result.

    ostree: ``rpm-ostree kargs --append-if-missing/--delete-if-present`` stages
    a new deployment only when something changes. grubby: every installed kernel.
    """
    add, remove = [a for a in add if a], [r for r in remove if r]
    if not add and not remove:
        return subprocess.CompletedProcess([], 0, '', '')
    if booted(marker):
        command = [RPM_OSTREE, 'kargs'] + ['--append-if-missing=' + a for a in add] \
            + ['--delete-if-present=' + r for r in remove]
        return runner(command, capture_output=True, text=True, timeout=600)
    if remove and add:
        first = runner([GRUBBY, '--update-kernel=ALL', '--remove-args=' + ' '.join(remove)],
                       capture_output=True, text=True, timeout=60)
        if first.returncode:
            return first
        remove = []
    command = [GRUBBY, '--update-kernel=ALL'] + (['--args=' + ' '.join(add)] if add else []) \
        + (['--remove-args=' + ' '.join(remove)] if remove else [])
    return runner(command, capture_output=True, text=True, timeout=60)


def tool_name(marker=None):
    return 'rpm-ostree kargs' if booted(marker) else 'grubby'
