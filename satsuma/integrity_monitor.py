"""Database-independent application integrity reports; never approve changed bytes."""
import json
import os
import time


def assess_runtime(verifier=None):
    if verifier is None:
        from .self_guard import verify
        verifier = verify
    try:
        return {'status': 'HEALTHY', 'files': verifier(), 'checked_at': time.time()}
    except Exception as exc:
        return {'status': 'UNTRUSTED', 'diagnostic_status':getattr(exc,'code','INTEGRITY_CHECK_FAILED'),
                'error': str(exc)[:2000], 'checked_at': time.time()}


def run_once(store=None, guard=None, verdict_writer=None, report_writer=None, store_factory=None):
    from .early_guard import run_guard, write_verdict
    from .protected_storage import RootDataStore
    result = (guard or run_guard)()
    (verdict_writer or write_verdict)(result)
    configuration_failed = result.get('state') in ('POLICY_INVALID', 'CONFIG_UNSUPPORTED')
    report = {**result, 'updated_at': time.time(), 'approved_baseline_replaced': False,
              'diagnostic_status':result['state'] if configuration_failed else
                    (result.get('checks',{}).get('application',{}).get('status') or
                     ('HEALTHY' if result['response_unlocked'] else 'INTEGRITY_CHECK_FAILED')),
              'status': 'HEALTHY' if result['response_unlocked'] else
                        result['state'] if configuration_failed else 'UNTRUSTED'}
    writer = report_writer or (lambda path, data: RootDataStore(path).replace(data))
    # Publish evidence before opening SQLite; DB corruption cannot stop verification.
    writer('integrity/status.json', report)
    owned = store is None
    try:
        if store is None:
            from .store import Store
            store = (store_factory or Store)()
        previous = store.get('integrity_runtime', {}) or {}
        store.set('integrity_runtime', {'status': report['status'], 'checked_at': report['updated_at'],
                                     'failure_reasons': result['failure_reasons'], 'checks': result.get('checks', {}),
                                     'host_cleanliness_verified': False})
        store.set('early_boot', result)
        if report['status'] != 'HEALTHY' and previous.get('status') != report['status']:
            finding = {'timestamp': time.time(), 'source': 'integrity_monitor', 'severity': 'critical',
                       'title': ('Satsuma politikası geçersiz; müdahale kilitli' if configuration_failed
                                 else 'Satsuma dosya doğrulaması başarısız; müdahale kilitli'),
                       'action': 'configuration.warning' if configuration_failed else 'integrity.warning',
                       'status': report['status'],
                       'rule_id': 'SATSUMA-CONFIG-001' if configuration_failed else 'SATSUMA-INTEGRITY-001',
                       'classification': 'indicator',
                       'details': result['failure_reasons']}
            store.add('findings', finding); store.add('actions', finding)
        report['database'] = {'status': 'AVAILABLE'}
    except Exception as exc:
        report['database'] = {'status': 'UNAVAILABLE', 'error': str(exc)[:1000]}
    finally:
        if owned and store is not None: store.close()
    writer('integrity/status.json', report)
    return report


def main():
    if os.geteuid() != 0: raise PermissionError('Integrity monitor requires root')
    os.umask(0o077)
    report = run_once()
    print(json.dumps(report))
    return 0 if report['status'] == 'HEALTHY' and report['database']['status'] == 'AVAILABLE' else 1
