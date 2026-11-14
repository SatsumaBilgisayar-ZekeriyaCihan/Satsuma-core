"""Read-only hardware memory-encryption readiness; never infer active from flags."""
import json
from pathlib import Path
import subprocess


def assess(cpuinfo, cmdline='', kernel_log=None, board='unknown'):
    fields = {}
    for line in cpuinfo.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            fields.setdefault(key.strip(), value.strip())
    flags = set(fields.get('flags', '').split())
    requested = [arg for arg in cmdline.split() if arg.startswith('mem_encrypt=')]
    # CPU exposure or mem_encrypt=on alone does not prove firmware/kernel
    # activation. Only report SME active with the kernel's explicit result.
    active = kernel_log is not None and any(
        'Memory Encryption Features active:' in line and 'SME' in line.split('active:', 1)[1].split()
        for line in kernel_log.splitlines())
    return {'cpu_model': fields.get('model name', 'unknown'), 'board_model': board,
            'cpu_features': sorted(flags & {'sme', 'sev', 'sev_es', 'sev_snp', 'tme', 'mktme'}),
            'kernel_request': requested,
            'status': 'SME_ACTIVE_REPORTED_BY_KERNEL' if active else 'ACTIVATION_UNVERIFIED',
            'kernel_evidence_available': kernel_log is not None,
            'all_ram_encrypted_verified': False,
            'scope': 'Hardware encryption does not prevent privileged process-memory reads; '
                     'shared/DMA pages may be decrypted. Keys are managed by hardware/firmware.'}


def inspect():
    board_path = Path('/sys/class/dmi/id/board_name')
    try:
        board = board_path.read_text().strip()
    except OSError:
        board = 'unknown'
    try:
        completed = subprocess.run(['dmesg', '--color=never'], capture_output=True,
                                   text=True, timeout=5)
        log = completed.stdout if completed.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        log = None
    # The full kernel log and boot command line are never printed or retained.
    return assess(Path('/proc/cpuinfo').read_text(), Path('/proc/cmdline').read_text(), log, board)


if __name__ == '__main__':
    print(json.dumps(inspect(), ensure_ascii=False, indent=2))
