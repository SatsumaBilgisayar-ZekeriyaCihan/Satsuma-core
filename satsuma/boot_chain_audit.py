"""Non-mutating local boot-chain evidence for Fedora/rpm-ostree/bootc.

Local evidence is not remote attestation. Nothing here changes TPM, UEFI,
SELinux, service state, kernel command line, network or installed packages.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

EFI_GUID = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
PCRLOCK_COMMAND = ('/usr/lib/systemd/systemd-pcrlock', '--no-pager', '--json=short', 'log')


def decode_efi_bool(blob):
    """efivarfs prepends four attribute bytes to the EFI UINT8 payload."""
    if not isinstance(blob, bytes) or len(blob) != 5 or blob[4] not in (0, 1):
        return None
    return bool(blob[4])


def _efi_flag(root, name):
    path = root / (name + '-' + EFI_GUID)
    try:
        with path.open('rb') as handle:
            raw = handle.read(6)
    except (OSError, ValueError):
        return None
    return decode_efi_bool(raw)


def _tpm_info(root):
    try:
        names = sorted(p.name for p in root.iterdir() if p.name.startswith('tpm') and p.name[3:].isdigit())
    except OSError:
        return {'status': 'UNAVAILABLE', 'devices_observed': 0}
    return {'status': 'DEVICE_OBSERVED' if names else 'NO_DEVICE_OBSERVED',
            'devices_observed': min(len(names), 16),
            'note': 'TPM aygitinin gorulmesi TPM2 PCR dogrulamasi veya uzaktan attestasyon degildir'}


def _pcr_consistency(*, runner=subprocess.run):
    """Run only documented read-only 'log', never 'make-policy' or 'lock-*'."""
    try:
        p = runner(list(PCRLOCK_COMMAND), capture_output=True, timeout=12, check=False,
                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        return {'status': 'CHECK_UNAVAILABLE', 'verified': False}
    if p.returncode:
        return {'status': 'LOG_OR_PCR_CHECK_FAILED', 'verified': False}
    out = p.stdout
    if not isinstance(out, (str, bytes)) or len(out) > 2 * 1024 * 1024:
        return {'status': 'INVALID_CHECK_OUTPUT', 'verified': False}
    # The success exit code indicates that pcrlock completed its *local* check.
    # Do not store event log: it can contain device identifiers/paths.
    return {'status': 'LOCAL_LOG_CHECK_COMPLETED', 'verified': False,
            'note': 'Yerel PCR gunluk kontrolu; bagimsiz TPM quote veya referans eslesmesi degil'}


def collect(*, efivar_root=Path('/sys/firmware/efi/efivars'),
            tpm_root=Path('/sys/class/tpm'), runner=subprocess.run):
    """Read-only evidence. Never assert the machine is trustworthy."""
    efivar_root = Path(efivar_root)
    try:
        uefi = efivar_root.is_dir()
    except OSError:
        uefi = False
    secure = _efi_flag(efivar_root, 'SecureBoot') if uefi else None
    setup = _efi_flag(efivar_root, 'SetupMode') if uefi else None
    if not uefi:
        state = 'UEFI_NOT_OBSERVED'
    elif secure is None or setup is None:
        state = 'EFI_VARIABLES_UNAVAILABLE'
    elif secure and not setup:
        state = 'SECURE_BOOT_ENABLED_OBSERVED'
    elif setup:
        state = 'FIRMWARE_SETUP_MODE'
    else:
        state = 'SECURE_BOOT_DISABLED_OBSERVED'
    tpm = _tpm_info(Path(tpm_root))
    check = (_pcr_consistency(runner=runner) if tpm['status'] == 'DEVICE_OBSERVED'
             else {'status': 'NO_TPM_CHECK', 'verified': False})
    return {
        'status': 'LOCAL_EVIDENCE_ONLY', 'verified': False,
        'secure_boot': {'status': state, 'secure_boot': secure, 'setup_mode': setup,
                        'note': 'UEFI degiskenleri yerel gozlemdir; firmware veya OS ele gecirilmis olabilir'},
        'tpm': tpm,
        'pcr_log': check,
        'missing_evidence': [
            'Independent TPM quote with nonce, EK/AK trust validation',
            'PCR replay against independently trusted boot reference',
            'Kernel, initramfs, modules, rootfs and runtime integrity attestation'],
    }


def main(argv=None):
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Read-only local Secure Boot and TPM boot evidence')
    parser.parse_args(argv)
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
