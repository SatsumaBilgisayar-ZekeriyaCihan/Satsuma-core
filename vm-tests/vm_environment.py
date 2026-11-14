"""Conservative VM-only admission control for potentially disruptive tests.

This is not an anti-tampering boundary: a privileged host can spoof VM signals.
For safety, unknown, container and physical environments are never admitted.
"""
from pathlib import Path
import subprocess

# Explicitly supported systemd-detect-virt identifiers for Fedora VM testing.
SUPPORTED = frozenset({'kvm', 'qemu', 'vmware', 'oracle', 'xen', 'microsoft',
                       'parallels', 'bhyve', 'bochs'})


def detect_vm(*, run=subprocess.run, fedora=Path('/etc/fedora-release')):
    """Return (admitted, reason), with no host mutations."""
    if not fedora.is_file():
        return False, 'Fedora release marker is absent'
    try:
        container = run(['/usr/bin/systemd-detect-virt', '--container', '--quiet'],
                        capture_output=True, timeout=3, check=False)
        if container.returncode == 0:
            return False, 'Container environment is not a supported Fedora VM test'
        if container.returncode != 1:
            return False, 'Container detection is inconclusive'
        vm = run(['/usr/bin/systemd-detect-virt', '--vm'],
                 capture_output=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, 'Virtualization detection unavailable: ' + type(exc).__name__
    kind = vm.stdout.decode('utf-8', 'replace').strip().lower()
    if vm.returncode == 0 and kind in SUPPORTED:
        return True, kind
    return False, 'Physical, unrecognized, or undetectable virtualization environment'


def require_vm(**kwargs):
    admitted, reason = detect_vm(**kwargs)
    if not admitted:
        raise RuntimeError('VM-ONLY TEST REFUSED: ' + reason)
    return reason
