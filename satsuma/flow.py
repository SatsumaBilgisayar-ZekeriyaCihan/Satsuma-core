"""Event flow: host events stream to the rule engine instead of the database.

User decision 2026-11-04: only events that end in a termination are
recorded; everything else continues in the flow. A failed termination
(the process had already ended, a protected program, a policy refusal) is
recorded too. A 30-minute in-memory history follows each process so that,
when a termination happens, the process chain and its recent events are
written as evidence; nothing else reaches the disk.

- FlowSender: collectors in other services (satsuma-core's process and
  memory watchers, the audit service) send each normalized event as one
  datagram to /run/satsuma-flow/flow.sock. If the rule engine is not
  listening, the event is written to the database as before, so a restart
  never leaves a blind spot; the engine catches up from there.
- FlowReceiver: the rule engine (satsuma-teams) receives them in a thread
  into a bounded queue; a full queue drops and counts, never blocks.
- ProcessFlow: the in-memory history. Each process is keyed by pid and
  start time (a reused pid is a different process); its parent link and
  last events are kept for 30 minutes, then forgotten. The team rules read
  their recent window from here instead of the database. Satsuma's own
  events (satsuma.self_events) stay in the process chain but never enter
  the rules' window.

Olay akışı: ana makine olayları veritabanı yerine kural motoruna akar.
Kullanıcı kararı 2026-11-04: yalnızca sonlandırmayla biten olaylar kaydedilir;
geri kalan her şey akışta devam eder. Başarısız sonlandırma (süreç önceden
bitmiş, korunan program, politika reddi) da kaydedilir. Her süreci 30
dakikalık bellek içi geçmiş izler; sonlandırma olunca süreç zinciri ve son
olayları kanıt olarak yazılır, başka hiçbir şey diske ulaşmaz. Diğer
servislerdeki toplayıcılar her olayı /run/satsuma-flow/flow.sock'a tek
datagram olarak gönderir; kural motoru dinlemiyorsa olay eskisi gibi
veritabanına yazılır, yeniden başlatma kör nokta bırakmaz. Kural motoru
olayları sınırlı bir kuyruğa alır; kuyruk dolarsa olayı düşürür ve sayar, asla
beklemez. Her süreç pid ve başlangıç zamanıyla anahtarlanır (yeniden
kullanılan pid başka süreçtir); üst süreç bağı ve son olayları 30 dakika
tutulur, sonra unutulur. Ekip kuralları yakın penceresini veritabanı yerine
buradan okur. Satsuma'nın kendi olayları süreç zincirinde kalır, ama
kuralların penceresine hiç girmez.
"""
from collections import OrderedDict, deque
import itertools
import json
import os
from pathlib import Path
import queue
import socket
import threading
import time

SOCKET = Path('/run/satsuma-flow/flow.sock')
MAX_DATAGRAM = 60000
WINDOW_SECONDS = 1800
MAX_PROCESSES = 50000
EVENTS_PER_PROCESS = 300
WINDOW_EVENTS = 200000
_ids = itertools.count(1)


def flow_id():
    """A stream event's id: unique within this boot, never a database row id."""
    return f'flow-{os.getpid()}-{next(_ids)}'


def _trim(event):
    """Keep a datagram under the size limit by shortening long strings."""
    text = json.dumps(event, ensure_ascii=False, default=str)
    if len(text.encode()) <= MAX_DATAGRAM:
        return text
    def cut(value):
        if isinstance(value, str):
            return value[:1000]
        if isinstance(value, dict):
            return {k: cut(v) for k, v in value.items()}
        if isinstance(value, list):
            return [cut(v) for v in value[:50]]
        return value
    return json.dumps(cut(event), ensure_ascii=False, default=str)[:MAX_DATAGRAM]


class FlowSender:
    def __init__(self, path=SOCKET):
        self.path = str(path)
        self.sock = None
        self.sent = self.failed = 0

    def send(self, event):
        try:
            if self.sock is None:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                self.sock.setblocking(False)
            self.sock.sendto(_trim(event).encode(), self.path)
            self.sent += 1
            return True
        except OSError:
            self.failed += 1
            if self.sock is not None:
                self.sock.close()
                self.sock = None
            return False


class FlowReceiver:
    def __init__(self, path=SOCKET, capacity=100000, group='satsuma-core'):
        self.path, self.group = Path(path), group
        self.queue = queue.Queue(maxsize=capacity)
        self.received = self.dropped = self.malformed = 0
        self.sock = None
        self.thread = None
        self.stopped = threading.Event()

    def start(self):
        self.path.parent.mkdir(mode=0o770, parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(self.path))
        try:
            import grp
            gid = grp.getgrnam(self.group).gr_gid
            os.chown(self.path.parent, 0, gid)
            os.chown(self.path, 0, gid)
        except (KeyError, PermissionError, OSError):
            pass
        os.chmod(self.path, 0o660)
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._run, name='satsuma-flow', daemon=True)
        self.thread.start()
        return self

    def _run(self):
        while not self.stopped.is_set():
            try:
                data = self.sock.recv(MAX_DATAGRAM + 1)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                event = json.loads(data)
            except ValueError:
                self.malformed += 1
                continue
            self.put(event)

    def put(self, event):
        try:
            self.queue.put_nowait(event)
            self.received += 1
        except queue.Full:
            self.dropped += 1

    def drain(self, limit=20000):
        out = []
        while len(out) < limit:
            try:
                out.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return out

    def close(self):
        self.stopped.set()
        if self.sock is not None:
            self.sock.close()

    def health(self):
        return {'received': self.received, 'dropped': self.dropped, 'malformed': self.malformed,
                'queued': self.queue.qsize()}


def _identity(event):
    ext = ((event.get('metadata') or {}).get('extensions') or {}) if isinstance(event.get('metadata'), dict) else {}
    def pick(key):
        value = event.get(key)
        return value if value not in (None, '') else ext.get('host.' + key)
    return pick('pid'), pick('starttime'), pick('ppid')


class ProcessFlow:
    """30-minute in-memory history of processes and their events."""

    def __init__(self, window=WINDOW_SECONDS, clock=time.time):
        self.window, self.clock = window, clock
        self.processes = OrderedDict()
        self.latest = {}
        self.recent = deque(maxlen=WINDOW_EVENTS)
        self.by_id = {}

    @staticmethod
    def _key(pid, starttime):
        return f'{pid}:{starttime if starttime not in (None, "") else "?"}'

    def add(self, body):
        """Record one flow body {'raw_id', 'event' (normalized), 'raw'}."""
        now = self.clock()
        if len(self.recent) == self.recent.maxlen:
            self._forget(self.recent[0][1])
        self.recent.append((now, body))
        if isinstance(body.get('raw_id'), str):
            self.by_id[body['raw_id']] = body
        raw = body.get('raw') if isinstance(body.get('raw'), dict) else None
        source = raw if raw is not None else (body.get('event') or {})
        pid, starttime, ppid = _identity(source)
        if pid in (None, ''):
            return None
        key = self._key(pid, starttime)
        if key not in self.processes and starttime in (None, '') and str(pid) in self.latest:
            key = self.latest[str(pid)]
        entry = self.processes.get(key)
        if entry is None:
            entry = {'pid': str(pid), 'starttime': starttime, 'ppid': None if ppid in (None, '') else str(ppid),
                     'exe': None, 'cmd': None, 'uid': None, 'first_seen': now, 'events': deque(maxlen=EVENTS_PER_PROCESS)}
            self.processes[key] = entry
            self.latest[str(pid)] = key
        for field in ('exe', 'cmd', 'uid'):
            value = source.get(field) or ((source.get('metadata') or {}).get('extensions') or {}).get('host.' + field)
            if value not in (None, ''):
                entry[field] = str(value)[:1000]
        if ppid not in (None, ''):
            entry['ppid'] = str(ppid)
        entry['last_seen'] = now
        if body.get('own'):
            entry['satsuma'] = True
        entry['events'].append({'ts': now, 'own': bool(body.get('own')), 'source': source.get('source'), 'action': source.get('action'),
                                'cmd': (source.get('cmd') or '')[:300] or None, 'path': source.get('path') or source.get('file_path'),
                                'dest': source.get('dest_ip') or source.get('target_ip')})
        self.processes.move_to_end(key)
        self.prune(now)
        return key

    def prune(self, now=None):
        now = self.clock() if now is None else now
        while self.processes:
            key, entry = next(iter(self.processes.items()))
            if now - entry.get('last_seen', entry['first_seen']) <= self.window and len(self.processes) <= MAX_PROCESSES:
                break
            self.processes.popitem(last=False)
            if self.latest.get(entry['pid']) == key:
                del self.latest[entry['pid']]
        while self.recent and now - self.recent[0][0] > self.window:
            self._forget(self.recent.popleft()[1])

    def _forget(self, body):
        if self.by_id.get(body.get('raw_id')) is body:
            del self.by_id[body['raw_id']]

    def get(self, raw_id):
        """The flow body for a stream event id, while it is in the window."""
        return self.by_id.get(raw_id)

    def window_rows(self, since):
        """(raw_id, body JSON) pairs newer than ``since`` (epoch), shaped like
        normalized database rows, for the team rules and the correlation engine."""
        return [(body.get('raw_id'), json.dumps({'raw_id': body.get('raw_id'), 'event': body.get('event')}, default=str))
                for ts, body in self.recent if ts >= since and not body.get('own')]

    def snapshot(self, pid, starttime=None, depth=8):
        """The process, its ancestors and their recent events, for termination evidence."""
        chain, seen = [], set()
        key = self._key(pid, starttime) if starttime not in (None, '') else self.latest.get(str(pid))
        while key and key not in seen and len(chain) < depth:
            seen.add(key)
            entry = self.processes.get(key)
            if entry is None:
                break
            chain.append({k: v for k, v in entry.items() if k != 'events'} | {'events': list(entry['events'])[-60:]})
            parent = entry.get('ppid')
            key = self.latest.get(parent) if parent else None
        return {'window_seconds': self.window, 'chain': chain}

    def health(self):
        own = sum(1 for _, body in self.recent if body.get('own'))
        return {'processes': len(self.processes), 'recent_events': len(self.recent) - own, 'own_events': own,
                'window_seconds': self.window}


ACTIVE = None  # the rule engine's ProcessFlow, set in satsuma-teams
