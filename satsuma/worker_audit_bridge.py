"""Bridge dedicated Audit worker evidence from host.db into Core normalized events.

Design goal: /var/log/audit/audit.log has a single reader: workers/audit/worker.py.
This bridge never opens audit.log. It tails the dedicated worker's HostStore database
with a durable cursor and adapts each audit record into the Core event contract.
Commands are kept up to 1024 arguments and 64 KB, so padding cannot push a
payload out of view.

Ayrılmış audit işçisinin host.db kanıtını Core'un normalize olaylarına taşır.
audit.log'un tek okuyucusu workers/audit/worker.py'dir; bu köprü onu hiç
açmaz, kalıcı bir imleçle host.db'yi izler. Komutlar 1024 argüman ve 64 KB'a
kadar tutulur; dolgu yükü görüş dışına itemez.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class WorkerAuditBridge:
    name = "audit_bridge"

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
        self.cursor_key = 'worker.audit_bridge.cursor.v1'
        self.health_key = 'worker.audit_bridge.health'
        self.host_db = Path(self.config.get('audit_host_db_path', '/var/lib/satsuma-core/host/host.db'))
        self.batch_limit = max(1, min(int(self.config.get('audit_bridge_batch_limit', 1000)), 10000))

    @staticmethod
    def _parse_flags(value):
        if value is None:
            return None
        text = str(value).strip().lower()
        try:
            # Linux audit syscall arguments are normally hexadecimal without 0x.
            return int(text, 16)
        except ValueError:
            try:
                return int(text, 10)
            except ValueError:
                return None

    def _operation(self, record):
        syscall = str(record.get('syscall') or '')
        name = self.SYSCALL_NAMES.get(syscall, f'syscall_{syscall}' if syscall else 'access')
        if name in self.WRITE_SYSCALLS:
            return 'write'
        if name in self.READ_SYSCALLS:
            return 'read'
        if name in self.EXEC_SYSCALLS:
            return 'execute'
        if name in {'open', 'openat'}:
            flags = self._parse_flags(record.get('a1') if name == 'open' else record.get('a2'))
            if flags is None:
                return 'access'
            if flags & (0x1 | 0x2 | 0x40 | 0x200 | 0x400):
                return 'write'
            return 'read'
        if name in {'connect', 'sendto', 'sendmsg'}:
            return 'network'
        return name

    @staticmethod
    def _cmd(record):
        execve = record.get('execve') if isinstance(record.get('execve'), dict) else {}
        args = []
        try:
            argc = min(int(execve.get('argc', 0)), 1024)
        except (TypeError, ValueError):
            argc = 0
        for idx in range(argc):
            value = execve.get(f'a{idx}')
            if value is not None:
                args.append(str(value))
        # Long enough that padding cannot push a payload out of view (K1 keeps
        # the engine fast on long input).
        if args:
            return ' '.join(args)[:65536]
        return str(record.get('proctitle') or '')[:65536]

    def _events(self, record):
        operation = self._operation(record)
        syscall = str(record.get('syscall') or '')
        syscall_name = self.SYSCALL_NAMES.get(syscall, f'syscall_{syscall}' if syscall else '')
        cmd = self._cmd(record)
        timestamp = record.get('timestamp', int(time.time()))
        common = {
            'pid': record.get('pid'),
            'ppid': record.get('ppid'),
            'uid': record.get('uid'),
            'auid': record.get('auid'),
            'exe': record.get('exe'),
            'comm': record.get('comm'),
            'success': record.get('success'),
            'serial': record.get('serial'),
            'operation': operation,
        }
        events = []

        if syscall:
            events.append({
                'source': 'audit', 'kind': 'syscall', 'action': 'syscall',
                'timestamp': timestamp, 'category': 'host', 'severity': 'info',
                'syscall': syscall, 'syscall_name': syscall_name, **common,
                'metadata': {'extensions': {
                    'host.pid': common['pid'], 'host.ppid': common['ppid'], 'host.uid': common['uid'],
                    'host.exe': common['exe'], 'host.operation': operation,
                    'host.syscall': syscall_name, 'host.cmd': cmd,
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

        for item in record.get('paths', []) or []:
            path = item.get('path') or item.get('name')
            if not path or path == '(null)' or str(path).startswith('('):
                continue
            path_op = operation
            if str(item.get('nametype', '')).upper() in {'CREATE', 'DELETE'}:
                path_op = 'write'
            events.append({
                'source': 'audit', 'kind': 'file_access', 'action': 'file_access',
                'timestamp': timestamp, 'category': 'host', 'severity': 'info',
                **common,
                'path': path, 'file_path': path, 'inode': item.get('inode'),
                'nametype': item.get('nametype'), 'operation': path_op,
                'metadata': {'extensions': {
                    'host.pid': common['pid'], 'host.ppid': common['ppid'], 'host.uid': common['uid'],
                    'host.exe': common['exe'], 'host.cmd': cmd,
                    'host.path': path, 'host.file_path': path,
                    'host.operation': path_op, 'host.inode': item.get('inode'),
                }},
            })

        for item in record.get('user_events', []) or []:
            events.append({
                'source': 'audit', 'kind': 'user_event', 'action': 'user_event',
                'subtype': item.get('type'), 'timestamp': timestamp,
                'category': 'user', 'severity': 'info',
                'uid': item.get('uid'), 'auid': item.get('auid'),
                'acct': item.get('acct'), 'result': item.get('res'),
                'serial': record.get('serial'),
                'metadata': {'extensions': {
                    'host.uid': item.get('uid'), 'host.auid': item.get('auid'),
                    'host.acct': item.get('acct'), 'host.result': item.get('res'),
                    'host.subtype': item.get('type'),
                }},
            })
        return events

    def _connect(self):
        if not self.host_db.exists():
            return None
        # Read-only so the bridge cannot mutate the dedicated evidence database.
        uri = f"file:{self.host_db}?mode=ro"
        return sqlite3.connect(uri, uri=True, timeout=2)

    def tick(self, pipeline=None):
        started = time.time()
        if pipeline is None:
            health = {'ok': False, 'status': 'DEGRADED', 'events': 0, 'error': 'Pipeline unavailable; cursor retained', 'updated_at': started}
            self.store.set(self.health_key, health)
            return health
        conn = self._connect()
        if conn is None:
            health = {'ok': False, 'status': 'WAITING_FOR_HOST_DB', 'events': 0, 'records': 0, 'elapsed_ms': int((time.time()-started)*1000)}
            self.store.set(self.health_key, {**health, 'updated_at': int(time.time())})
            return health

        emitted = errors = 0
        records = 0
        try:
            cursor = self.store.get(self.cursor_key, None)
            if cursor is None:
                cursor = 0
            rows = conn.execute(
                "SELECT id, body FROM records WHERE kind='audit' AND id>? ORDER BY id ASC LIMIT ?",
                (int(cursor), self.batch_limit),
            ).fetchall()
            last_id = int(cursor)
            for rid, body in rows:
                records += 1
                try:
                    record = json.loads(body)
                    if pipeline:
                        for event in self._events(record):
                            pipeline.ingest_audit(event)
                            emitted += 1
                    last_id = int(rid)
                except Exception as exc:
                    errors += 1
                    self.store.add('errors', {
                        'component': 'worker_audit_bridge', 'record_id': rid,
                        'error': str(exc)[:300],
                    })
                    break
            if rows:
                self.store.set(self.cursor_key, last_id)
            status = 'RUNNING' if errors == 0 else 'DEGRADED'
            health = {
                'ok': errors == 0, 'status': status,
                'events': emitted, 'records': records, 'errors': errors,
                'cursor': last_id, 'backlog_remaining': len(rows) >= self.batch_limit,
                'elapsed_ms': int((time.time()-started)*1000),
            }
            self.store.set(self.health_key, {**health, 'updated_at': int(time.time())})
            return health
        finally:
            conn.close()
