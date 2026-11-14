"""Bounded, coalescing read cache. Socket IO never runs in the GUI thread."""
import copy
import json
import queue
import threading
import time
from collections import OrderedDict


class AsyncReader:
    def __init__(self, client, on_update=lambda: None, ttl=2.0, retry=5.0, capacity=128):
        self.client, self.on_update = client, on_update
        self.ttl, self.retry, self.capacity = ttl, retry, capacity
        self._cache = OrderedDict()
        self._pending = set()
        self._queue = queue.Queue(maxsize=capacity)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.last_error = None
        self._thread = threading.Thread(target=self._run, name='satsuma-reader', daemon=True)
        self._thread.start()

    def call(self, method, **params):
        key = (method, json.dumps(params, sort_keys=True, ensure_ascii=False))
        with self._lock:
            if self._stop.is_set():
                raise ConnectionError('Okuyucu kapalı')
            entry = self._cache.get(key)
            fresh = entry is not None and time.monotonic() < entry[0]
            if not fresh and key not in self._pending:
                try:
                    self._queue.put_nowait((key, method, params))
                    self._pending.add(key)
                except queue.Full:
                    pass
            if entry:
                self._cache.move_to_end(key)
                if entry[2]:
                    raise ConnectionError(entry[2])
                return copy.deepcopy(entry[1])
        raise ConnectionError('Veri arka planda yükleniyor')

    def ping(self):
        try:
            return self.call('ping') == 'pong'
        except ConnectionError:
            return False

    def _run(self):
        while not self._stop.is_set():
            try:
                key, method, params = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if self._stop.is_set():
                break
            try:
                result, error = self.client.call(method, **params), None
            except Exception as exc:
                result, error = None, str(exc)
            with self._lock:
                self._pending.discard(key)
                self.last_error = error
                self._cache[key] = (time.monotonic() + (self.retry if error else self.ttl), result, error)
                self._cache.move_to_end(key)
                while len(self._cache) > self.capacity:
                    self._cache.popitem(last=False)
            if not self._stop.is_set():
                self.on_update()

    def close(self):
        self._stop.set()
