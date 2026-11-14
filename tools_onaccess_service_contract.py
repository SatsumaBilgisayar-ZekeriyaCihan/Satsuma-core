"""Read-only inspection of on-access quarantine service permission contract.

Only reports conflicts; does not grant privileges or change service settings.
"""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent

def inspect(root=ROOT):
    unit = (Path(root) / 'systemd/satsuma-onaccess-listener.service').read_text()
    issues = []
    if 'ProtectHome=read-only' in unit:
        issues.append('ProtectHome=read-only blocks direct quarantine moves under /home')
    if 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH' in unit:
        issues.append('CAP_DAC_READ_SEARCH alone cannot override target write permissions or guarantee chown')
    if 'ReadWritePaths=/var/lib/satsuma-core' not in unit:
        issues.append('Private quarantine storage write allowance not verified')
    return {'ready_for_verified_quarantine': not issues, 'issues': issues,
            'scope': 'static systemd contract only; SELinux and Fedora execution not verified'}

if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2))
