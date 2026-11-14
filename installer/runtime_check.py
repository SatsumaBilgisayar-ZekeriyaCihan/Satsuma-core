"""Report observed service/data readiness; never change firewall or file ownership."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, '/opt/satsuma-core')

UNITS = ('satsuma-image', 'satsuma-app-control', 'satsuma-core-gateway', 'satsuma-core-sentinel', 'satsuma-containment', 'satsuma-early-guard', 'satsuma-network', 'satsuma-suricata-ips',
         'satsuma-core', 'satsuma-reader', 'satsuma-operator', 'satsuma-guardian',
         'satsuma-network-identity', 'satsuma-core-subnet', 'satsuma-udev', 'satsuma-rescue', 'satsuma-self-health.timer', 'satsuma-suricata-otx-guard', 'satsuma-teams', 'satsuma-core-audit', 'satsuma-core-finding')


def record_boot_verdict(result, verdict):
    """Separate service readiness from application verification failures and response authorization."""
    state = verdict.get('state', 'UNKNOWN')
    unlocked = state == 'FULL_CHECKED' and verdict.get('response_unlocked') is True
    result['boot_verdict'] = state
    result['boot_response_unlocked'] = unlocked
    if state == 'WARNING' and not verdict.get('response_unlocked', False):
        result.setdefault('warnings', []).append(
            'Early guard: application inventory mismatch; active responses remain locked'
        )
    elif not unlocked:
        result['errors'].append('Early guard: ' + str(state))
    return result


def record_modem_status(result,identity):
    fresh=isinstance(identity.get('updated_at'),(int,float)) and 0<=time.time()-identity['updated_at']<=10
    if identity.get('status')=='MODEM_APPROVAL_REQUIRED' and fresh:
        result['modem_approval_pending']=True
        result['warnings'].append('Select and explicitly approve your modem in the welcome/admin screen')
    elif identity.get('status')!='MATCHED_USER_APPROVAL' or not fresh:
        result['errors'].append('User-approved modem reference is changed, missing or stale')
    return result


def check():
    from satsuma.dashboard_api_client import ReaderClient
    from satsuma.ips import read_ready
    from satsuma.early_guard import read_verdict
    result = {'host_cleanliness_verified': False, 'services': {}, 'errors': [], 'warnings': []}
    try:
        report = json.loads(Path('/var/lib/satsuma-core/containment/status.json').read_text())
        result['remote_containment'] = report
        if report.get('status') != 'guarded' or not 0 <= time.time() - report['updated_at'] < 25:
            result['errors'].append('Remote server containment is degraded or stale')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result['errors'].append('Remote server containment report: ' + str(exc))
    for unit in UNITS:
        state = subprocess.run(['/usr/bin/systemctl', 'is-active', unit if unit.endswith(('.service','.timer')) else unit + '.service'],
                               capture_output=True, text=True, timeout=5).stdout.strip()
        result['services'][unit] = state
        if state != 'active':
            result['errors'].append(unit + ': ' + state)
    result['ips'] = read_ready()
    if not result['ips']['ready']:
        result['errors'].append('IPS: ' + str(result['ips']))
    record_boot_verdict(result, read_verdict())
    try:
        client = ReaderClient()
        health = client.call('health')
        result['core_status'] = health.get('status')
        result['core_updated_at'] = health.get('updated_at')
        result['reader'] = health.get('reader')
        if (health.get('status') != 'running' or not health.get('reader')
                or not isinstance(health.get('updated_at'), (int, float))
                or not 0 <= time.time() - health['updated_at'] <= 10):
            result['errors'].append('Core/EVE health is missing, degraded or stale')
        result['network_identity'] = client.call('state', key='network_identity', default={})
        identity = result['network_identity']
        record_modem_status(result,identity)
        critical = client.call('state', key='critical_integrity', default={})
        result['critical_integrity'] = critical
        if (critical.get('status') != 'HEALTHY'
                or not isinstance(critical.get('checked_at'), (int, float))
                or not 0 <= time.time() - critical['checked_at'] <= 15):
            result['errors'].append('Critical integrity is unhealthy, missing or stale: ' + str(critical))
        overview = client.call('overview')
        result['dashboard_core_status'] = overview.get('system', {}).get('core_status')
        if result['dashboard_core_status'] != 'RUNNING':
            result['errors'].append('Dashboard does not report running Core')
    except Exception as exc:
        result['errors'].append('Reader: ' + str(exc))
    result['installation_ready'] = not result['errors']
    result['ready'] = result['installation_ready'] and not result.get('modem_approval_pending',False)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wait', type=int, default=0)
    parser.add_argument('--allow-pending-modem', action='store_true', help='Installer may finish while explicit modem selection remains pending; does not mark protection ready')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run sudo satsuma-status; protected IPS and containment reports require root')
    deadline = time.monotonic() + max(0, min(args.wait, 120))
    while True:
        result = check()
        install_pending_ok=args.allow_pending_modem and result.get('installation_ready') and result.get('modem_approval_pending')
        if result['ready'] or install_pending_ok or time.monotonic() >= deadline:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['ready'] or install_pending_ok else 1
        time.sleep(.5)


if __name__ == '__main__':
    raise SystemExit(main())
