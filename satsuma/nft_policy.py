"""Satsuma-owned nftables policy reconciliation.

Never flushes/rebuilds the ruleset and never creates the retired satsuma_policy table.
It validates the configured block sets and restores only Satsuma's persisted elements.
"""
import ipaddress
import json
import subprocess
import time


class NftPolicyManager:
    def __init__(self, store, config, runner=subprocess.run):
        self.store = store
        self.config = config
        self.runner = runner

    def _run(self, args):
        try:
            result = self.runner(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, timeout=5)
            return result.returncode, result.stdout, result.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            return -1, '', str(exc)

    def _target(self, version):
        return (self.config['nft_family'], self.config['nft_table'],
                self.config['nft_set'] if version == 4 else self.config.get('nft_set_v6', 'blocked_ips_v6'))

    def _validate_set(self, version):
        family, table, name = self._target(version)
        code, out, err = self._run(['nft', '-j', 'list', 'set', family, table, name])
        if code != 0:
            return False, 'set_unavailable: ' + err[:180]
        try:
            data = json.loads(out)
            sets = [x['set'] for x in data.get('nftables', []) if 'set' in x]
            expected = 'ipv4_addr' if version == 4 else 'ipv6_addr'
            if not sets or sets[0].get('type') != expected:
                return False, 'set_type_mismatch'
        except (ValueError, KeyError, TypeError):
            return False, 'invalid_nft_json'
        return True, 'ok'

    def reconcile(self):
        """Validate targets and restore missing persisted elements, idempotently.

        Persistent state lives in the root-owned core.db ``state`` table under
        ``persistent_blocks``.  The method never flushes the live ruleset; it
        only lists/validates the configured sets and adds/verifies individual
        Satsuma-owned elements.  Every mutation is followed by a readback and
        an audit record.
        """
        report = {'timestamp': time.time(), 'status': 'ok', 'restored': 0,
                  'already_present': 0, 'failed': 0, 'sets': {},
                  'restored_ips': [], 'validation': 'readback_after_add',
                  'state_source': 'core.db:state/persistent_blocks',
                  'firewall_mutation': False}
        try:
            blocks = self.store.get('persistent_blocks', {}) or {}
        except Exception as exc:
            report['status'] = 'degraded'
            report['errors'] = [{
                'ip': None,
                'error': f'persistent_state_unavailable: {type(exc).__name__}: {exc}'[:180],
            }]
            return report
        if not isinstance(blocks, dict):
            report['status'] = 'degraded'
            report['errors'] = [{'ip': None, 'error': 'invalid_persistent_block_state'}]
            return report

        valid = {}
        for version in (4, 6):
            ok, detail = self._validate_set(version)
            valid[version] = ok
            report['sets']['ipv%d' % version] = detail
            if not ok:
                report['status'] = 'degraded'
        for ip, meta in list(blocks.items()):
            try:
                obj = ipaddress.ip_address(ip)
            except ValueError:
                report['failed'] += 1
                report.setdefault('errors', []).append({'ip': str(ip), 'error': 'invalid_persistent_ip'})
                continue
            if not valid.get(obj.version):
                report['failed'] += 1
                report.setdefault('errors', []).append({'ip': str(obj), 'error': 'set_unavailable'})
                continue
            family, table, name = self._target(obj.version)
            args = [family, table, name, '{', str(obj), '}']
            code, _, _ = self._run(['nft', 'get', 'element', *args])
            if code == 0:
                report['already_present'] += 1
                continue
            add_code, _, add_err = self._run(['nft', 'add', 'element', *args])
            verify, _, verify_err = self._run(['nft', 'get', 'element', *args])
            if add_code == 0 and verify == 0:
                report['restored'] += 1
                report['restored_ips'].append(str(obj))
                report['firewall_mutation'] = True
                self.store.add('actions', {
                    'timestamp': time.time(),
                    'status': 'nft_element_restored',
                    'ip': str(obj),
                    'nft_family': family,
                    'nft_table': table,
                    'nft_set': name,
                    'readback': 'ok',
                    'reason': (meta or {}).get('reason') if isinstance(meta, dict) else None,
                })
            else:
                report['failed'] += 1
                report.setdefault('errors', []).append({'ip': str(obj), 'error': (add_err or verify_err)[:180]})
        if report['failed']:
            report['status'] = 'degraded'
        try:
            self.store.set('nft_policy', report)
            self.store.add('policy_events', {'component': 'nftables', **report})
        except Exception as exc:
            report['status'] = 'degraded'
            report.setdefault('errors', []).append({
                'ip': None,
                'error': f'audit_state_write_failed: {type(exc).__name__}'[:180],
            })
        return report
