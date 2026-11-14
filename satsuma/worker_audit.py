"""Satsuma Core — Audit worker.

Audit kayıtlarını serial bazında birleştirir. PATH olayına ilgili SYSCALL/EXECVE
bağlamını ve mümkün olduğunda read/write/execute operation bilgisini ekler.
Tek bir audit satırını saldırı olarak yorumlamaz; yalnızca normalize edilebilir
kanıt üretir.
"""
from __future__ import annotations

from .worker_delivery import delivered_tick
from .worker_log import read_batch
import re
import time
from pathlib import Path


class WorkerAudit:
    name = "audit"

    SYSCALL_NAMES = {
        '0': 'read', '1': 'write', '2': 'open', '3': 'close',
        '41': 'socket', '42': 'connect', '43': 'accept',
        '44': 'sendto', '45': 'recvfrom', '46': 'sendmsg', '47': 'recvmsg',
        '49': 'bind', '50': 'listen', '57': 'fork', '58': 'vfork', '59': 'execve',
        '62': 'kill', '85': 'creat', '86': 'link', '87': 'unlink',
        '90': 'chmod', '92': 'chown', '105': 'setuid', '106': 'setgid',
        '257': 'openat', '258': 'mkdirat', '263': 'unlinkat', '264': 'renameat',
        '268': 'fchmodat', '322': 'execveat',
    }
    WRITE_SYSCALLS = {'write', 'creat', 'unlink', 'link', 'chmod', 'chown', 'unlinkat', 'renameat', 'mkdirat', 'fchmodat'}
    READ_SYSCALLS = {'read'}
    EXEC_SYSCALLS = {'execve', 'execveat'}

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.raw_key = 'worker.audit.raw'
        self.cursor_key = 'worker.audit.cursor'
        self.health_key = 'worker.audit.health'
        self.log_path = Path(self.config.get('audit_log_path', '/var/log/audit/audit.log'))

    def _read_new_lines(self):
        lines, cursor = read_batch(self.log_path, self.store.get(self.cursor_key), limit=5000)
        self.store.set(self.cursor_key, cursor)
        return lines

    @staticmethod
    def _parse_line(line):
        match = re.match(r'type=(\w+)\s+msg=audit\((\d+)\.(\d+):(\d+)\):\s*(.*)', line)
        if not match:
            return None
        record_type = match.group(1)
        timestamp = int(match.group(2))
        serial = match.group(4)
        body = match.group(5)
        fields = {}
        for item in re.finditer(r'(\w+)=((?:"(?:\\.|[^"])*")|\S+)', body):
            key = item.group(1)
            value = item.group(2)
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            fields[key] = value
        return {
            'record_type': record_type,
            'timestamp': timestamp,
            'serial': serial,
            'raw': line.strip()[:4000],
            'fields': fields,
        }

    def collect(self, max_lines=5000):
        lines = self._read_new_lines()
        records = []
        for line in lines:
            if not line.strip():
                continue
            parsed = self._parse_line(line)
            if parsed:
                records.append(parsed)
        return {'timestamp': int(time.time()), 'records': records, 'total_lines': len(lines)}

    @staticmethod
    def _parse_open_flags(value):
        if value is None:
            return None
        text = str(value).strip().lower()
        try:
            # audit a1/a2 alanları çoğunlukla hexadecimal, 0x öneki olmadan gelir.
            return int(text, 16)
        except ValueError:
            try:
                return int(text, 10)
            except ValueError:
                return None

    def _operation_from_syscall(self, fields):
        syscall = str(fields.get('syscall', ''))
        name = self.SYSCALL_NAMES.get(syscall, f'syscall_{syscall}')
        if name in self.WRITE_SYSCALLS:
            return 'write'
        if name in self.READ_SYSCALLS:
            return 'read'
        if name in self.EXEC_SYSCALLS:
            return 'execute'
        if name in {'open', 'openat'}:
            flag_key = 'a1' if name == 'open' else 'a2'
            flags = self._parse_open_flags(fields.get(flag_key))
            if flags is None:
                return 'access'
            # Linux: O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200, O_APPEND=0x400
            if flags & (0x1 | 0x2 | 0x40 | 0x200 | 0x400):
                return 'write'
            return 'read'
        if name in {'connect', 'sendto', 'sendmsg'}:
            return 'network'
        return name

    @staticmethod
    def _cmd_from_execve(records):
        for rec in records:
            if rec['record_type'] != 'EXECVE':
                continue
            fields = rec['fields']
            args = []
            try:
                argc = min(int(fields.get('argc', 0)), 64)
            except (TypeError, ValueError):
                argc = 0
            for idx in range(argc):
                value = fields.get(f'a{idx}')
                if value is not None:
                    args.append(str(value))
            if args:
                return ' '.join(args)[:2000]
        return ''

    def _raw_to_events(self, raw):
        groups = {}
        for rec in raw.get('records', []):
            groups.setdefault(rec['serial'], []).append(rec)

        events = []
        for serial, records in groups.items():
            syscall_rec = next((r for r in records if r['record_type'] == 'SYSCALL'), None)
            syscall_fields = syscall_rec['fields'] if syscall_rec else {}
            operation = self._operation_from_syscall(syscall_fields) if syscall_rec else 'access'
            syscall = str(syscall_fields.get('syscall', ''))
            syscall_name = self.SYSCALL_NAMES.get(syscall, f'syscall_{syscall}') if syscall else ''
            timestamp = min((r['timestamp'] for r in records), default=int(time.time()))
            cmd = self._cmd_from_execve(records)
            common = {
                'pid': syscall_fields.get('pid'),
                'ppid': syscall_fields.get('ppid'),
                'uid': syscall_fields.get('uid'),
                'auid': syscall_fields.get('auid'),
                'exe': syscall_fields.get('exe'),
                'comm': syscall_fields.get('comm'),
                'success': syscall_fields.get('success'),
                'serial': serial,
                'operation': operation,
            }

            if syscall_rec and syscall in ('2', '59', '257', '322', '42', '44', '46', '87', '90', '92', '105', '263', '264', '268'):
                events.append({
                    'source': 'audit', 'kind': 'syscall', 'action': 'syscall',
                    'timestamp': timestamp, 'category': 'host', 'severity': 'info',
                    'syscall': syscall, 'syscall_name': syscall_name, **common,
                    'metadata': {'extensions': {
                        'host.pid': common['pid'], 'host.ppid': common['ppid'], 'host.uid': common['uid'],
                        'host.exe': common['exe'], 'host.operation': operation, 'host.syscall': syscall_name,
                        'host.cmd': cmd,
                    }},
                })

            if cmd:
                events.append({
                    'source': 'audit', 'kind': 'execve', 'action': 'execve',
                    'timestamp': timestamp, 'category': 'host', 'severity': 'info',
                    'cmd': cmd, **common,
                    'metadata': {'extensions': {
                        'host.pid': common['pid'], 'host.ppid': common['ppid'], 'host.uid': common['uid'],
                        'host.exe': common['exe'], 'host.operation': 'execute', 'host.cmd': cmd,
                    }},
                })

            for rec in records:
                if rec['record_type'] != 'PATH':
                    continue
                fields = rec['fields']
                path_val = fields.get('name') or fields.get('path')
                if not path_val or path_val == '(null)' or path_val.startswith('('):
                    continue
                path_op = operation
                nametype = str(fields.get('nametype', '')).upper()
                if nametype in {'CREATE', 'DELETE'}:
                    path_op = 'write'
                events.append({
                    'source': 'audit', 'kind': 'file_access', 'action': 'file_access',
                    'timestamp': timestamp, 'category': 'host', 'severity': 'info',
                    **common,
                    'path': path_val, 'file_path': path_val, 'inode': fields.get('inode'),
                    'nametype': fields.get('nametype'), 'operation': path_op,
                    'metadata': {'extensions': {
                        'host.pid': common['pid'], 'host.ppid': common['ppid'], 'host.uid': common['uid'],
                        'host.exe': common['exe'], 'host.cmd': cmd, 'host.path': path_val,
                        'host.file_path': path_val, 'host.operation': path_op, 'host.inode': fields.get('inode'),
                    }},
                })

            for rec in records:
                if rec['record_type'] not in ('USER_AUTH', 'USER_LOGIN', 'USER_ACCT'):
                    continue
                fields = rec['fields']
                events.append({
                    'source': 'audit', 'kind': 'user_event', 'action': 'user_event',
                    'subtype': rec['record_type'], 'timestamp': rec['timestamp'],
                    'category': 'user', 'severity': 'info',
                    'uid': fields.get('uid'), 'acct': fields.get('acct'), 'result': fields.get('res'),
                    'serial': serial,
                    'metadata': {'extensions': {
                        'host.uid': fields.get('uid'), 'host.acct': fields.get('acct'),
                        'host.result': fields.get('res'), 'host.subtype': rec['record_type'],
                    }},
                })
        return events

    @delivered_tick()
    def tick(self, pipeline=None):
        started = time.time()
        raw = self.collect()
        self.store.set(self.raw_key, raw)

        raw_stored = 0
        for rec in raw.get('records', []):
            try:
                self.store.add('audit_raw', rec)
                raw_stored += 1
            except Exception:
                raise

        events = self._raw_to_events(raw)
        errors = 0
        if pipeline:
            for event in events:
                try:
                    if hasattr(pipeline, 'ingest_audit'):
                        pipeline.ingest_audit(event)
                    else:
                        pipeline.ingest_host(event)
                except Exception as exc:
                    errors += 1
                    self.store.add('errors', {
                        'component': 'worker_audit', 'error': str(exc)[:200],
                        'serial': event.get('serial'), 'action': event.get('action'),
                    })

        elapsed = time.time() - started
        self.store.set(self.health_key, {
            'updated_at': int(time.time()), 'elapsed_ms': int(elapsed * 1000),
            'status': 'DEGRADED' if errors else 'RUNNING', 'record_count': len(raw['records']),
            'raw_stored': raw_stored, 'event_count': len(events), 'errors': errors,
        })
        return {'ok': errors == 0, 'records': len(raw['records']), 'events': len(events), 'errors': errors, 'elapsed_ms': int(elapsed * 1000)}
