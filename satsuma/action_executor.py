"""Typed privileged action executor.

There is intentionally no shell/string command endpoint.  Every supported
mutation is a typed method with structured arguments.  Authentication/policy is
owned by PrivilegedBroker; this module only executes already-authorized calls.
"""
from __future__ import annotations

import time

from .process_identity import capture_process_identity
from .response import ResponseWorker


SUPPORTED_ACTIONS = {
    'network.block',
    'network.unblock',
    'file.quarantine',
    'file.restore',
    'process.capture_evidence',
    'process.terminate',
    'bpf.inventory',
    'bpf.unload',
    'bpf.pin_remove',
    'memory.snapshot',
}


class TypedActionExecutor:
    def __init__(self, store, config=None, *, response_worker=None):
        self.store = store
        self.config = config or {}
        self.response = response_worker or ResponseWorker(store, self.config)

    def execute(self, action: str, args: dict | None = None, *, finding: dict | None = None) -> dict:
        if action not in SUPPORTED_ACTIONS:
            return {'ok': False, 'status': 'unsupported_action', 'action': action}
        args = dict(args or {})
        finding = finding or {}
        if action == 'network.block':
            ip = args.get('ip') or finding.get('target_ip') or finding.get('dst_ip')
            result = self.response.block_ip(ip, args.get('reason', 'broker-authorized'), manual=True)
        elif action == 'network.unblock':
            result = self.response.unblock_ip(args.get('ip'), args.get('reason', 'broker-authorized'), manual=True)
        elif action == 'file.quarantine':
            try:
                from .quarantine_manager import quarantine
            except ModuleNotFoundError as exc:
                if exc.name != 'satsuma.quarantine_manager':
                    raise
                return {'ok': False, 'status': 'ACTION_UNSUPPORTED', 'action': action,
                        'reason': 'quarantine_manager is not installed'}
            path = args.get('path') or finding.get('file_path') or (finding.get('file') or {}).get('path')
            result = quarantine(path, reason=args.get('reason', 'broker-authorized'), engine='broker', automatic=False)
        elif action == 'file.restore':
            try:
                from .quarantine_manager import restore
            except ModuleNotFoundError as exc:
                if exc.name != 'satsuma.quarantine_manager':
                    raise
                return {'ok': False, 'status': 'ACTION_UNSUPPORTED', 'action': action,
                        'reason': 'quarantine_manager is not installed'}
            result = restore(str(args.get('quarantine_id') or ''))
        elif action == 'process.capture_evidence':
            pid = args.get('pid') or finding.get('pid') or (finding.get('process') or {}).get('pid')
            identity = capture_process_identity(pid)
            if not identity:
                result = {'status': 'process_not_found', 'pid': pid}
            else:
                rid = self.store.add('process_evidence', {
                    'timestamp': time.time(), 'finding_id': finding.get('finding_id'),
                    'identity': identity, 'reason': args.get('reason', 'manual_capture'),
                })
                result = {'status': 'captured', 'pid': identity['pid'], 'record_id': rid, 'identity': identity}
        elif action == 'process.terminate':
            pid = args.get('pid') or finding.get('pid') or (finding.get('process') or {}).get('pid')
            evidence = args.get('evidence') or finding
            result = self.response.kill_process(pid, args.get('reason', 'broker-authorized'), evidence=evidence, context={'rule_id':finding.get('rule_id'),'finding':finding})
        elif action == 'bpf.inventory':
            from .bpf_inventory import inventory
            data = inventory()
            result = {'status':'ok' if data.get('status')=='COMPLETED' else 'failed','inventory':data}
        elif action == 'bpf.unload':
            from .bpf_inventory import unload_program
            prog_id = args.get('id') or args.get('prog_id')
            try:
                prog_id = int(prog_id)
            except (TypeError, ValueError):
                return {'ok': False, 'action': action, 'result': {'status': 'invalid_id'}}
            result = unload_program(prog_id)
        elif action == 'bpf.pin_remove':
            from .bpf_inventory import remove_pin
            path = str(args.get('path') or '')
            result = remove_pin(path)
        elif action == 'memory.snapshot':
            from .memory_monitor import MemoryMonitor
            mon = MemoryMonitor(self.store, self.config)
            result = {'status': 'ok', 'snapshot': mon.collect()}
        else:  # pragma: no cover
            result = {'status': 'unsupported_action'}
        ok = str(result.get('status', '')).lower() in {
            'blocked', 'unblocked', 'quarantined', 'restored', 'captured',
            'terminated', 'killed', 'ok', 'unloaded', 'removed',
        }
        if result.get('status') == 'set_membership_confirmed':
            ok = (result.get('persisted') is True and result.get('drop_rule_linked') is True
                  and not result.get('audit_write_failed'))
        elif result.get('status') == 'set_absence_confirmed':
            ok = result.get('persisted') is True and not result.get('audit_write_failed')
        return {'ok': ok, 'action': action, 'result': result}
