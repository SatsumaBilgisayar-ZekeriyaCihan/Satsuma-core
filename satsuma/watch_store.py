"""Satsuma Core — Dosya yakin takip (watch-list) deposu.

file sensor tek basina bir dosyayi isaretlediginde (yanlis pozitif olabilir) dosya
karantinaya alinmaz; bunun yerine "yakin takip" listesine eklenir.  Takip
edilen bir dosya:

  - calistirilirsa (sys_proc exe/cmd eslesmesi) -> yeni finding
  - icerigi degisirse (sha256 farki) -> yeni finding

Boylece file sensor'nin isaret ettigi dosyanin yaptigi/yapacagi islemler riskli
olarak izlenir; tek basina karantina tetiklenmez.

Depolama: core.db state anahtari ``watch_files`` (JSON sozluk).
Sinir: en fazla MAX_WATCH_ENTRIES kayit; en eski kayitlar dusurulur.
"""
from __future__ import annotations

import hashlib
import os
import stat
import shlex
import time
from pathlib import Path

WATCH_KEY = 'watch_files'
MAX_WATCH_ENTRIES = 4096
DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 gun


def _sha256_file(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        if not stat.S_ISREG(os.lstat(path).st_mode):return None
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>64*1024*1024:
                return None
            remaining=64*1024*1024+1
            while remaining:
                chunk=stream.read(min(65536,remaining))
                if not chunk:break
                digest.update(chunk);remaining-=len(chunk)
            if not remaining:return None
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


class WatchStore:
    """Dosya yakin takip listesi (core.db state uzerinde)."""

    def __init__(self, store, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.store = store
        self.ttl_seconds = ttl_seconds

    def _load(self) -> dict:
        data = self.store.get(WATCH_KEY, {}) or {}
        if not isinstance(data,dict):raise ValueError('Corrupt watch-list state')
        return data

    def _save(self, data: dict) -> None:
        # TTL temizligi + kapasite siniri
        now = time.time()
        fresh = {
            path: entry for path, entry in data.items()
            if isinstance(entry, dict) and now - entry.get('added_at', 0) < self.ttl_seconds
        }
        if len(fresh) > MAX_WATCH_ENTRIES:
            ordered = sorted(fresh.items(), key=lambda kv: kv[1].get('added_at', 0))
            fresh = dict(ordered[-MAX_WATCH_ENTRIES:])
        self.store.set(WATCH_KEY, fresh)

    def add(self, path: str, reason: str, *, rule_id: str | None = None,
            source: str = 'file_sensor') -> dict:
        """Bir dosyayi yakin takibe al. Ayni yol varsa guncellenir."""
        if not isinstance(path, str) or not path.startswith('/'):
            return {'ok': False, 'error': 'invalid_path'}
        data = self._load()
        entry = data.get(path) or {}
        entry.update({
            'path': path,
            'reason': reason,
            'rule_id': rule_id,
            'source': source,
            'added_at': entry.get('added_at') or time.time(),
            'last_seen': time.time(),
            'sha256': _sha256_file(path),
            'hits': int(entry.get('hits', 0)),
        })
        data[path] = entry
        self._save(data)
        self.store.add('actions', {
            'timestamp': time.time(),
            'status': 'watch_added',
            'path': path,
            'reason': reason,
            'rule_id': rule_id,
        })
        return {'ok': True, 'path': path, 'entry': entry}

    def remove(self, path: str) -> dict:
        data = self._load()
        existed = data.pop(path, None) is not None
        self._save(data)
        return {'ok': True, 'removed': existed, 'path': path}

    def entries(self) -> dict:
        return self._load()

    def is_watched(self, path: str) -> bool:
        return path in self._load()

    def match_process(self, exe: str, cmd: str) -> list[dict]:
        """Calisan bir process takip listesindeki bir dosyaya uyuyor mu?

        ``exe`` tam yol eslesmesi; ``cmd`` icinde takip edilen yolun gecmesi
        (ornek: ``bash /home/user/x.sh``) kontrol edilir.
        """
        data = self._load()
        hits = []
        for path, entry in data.items():
            if exe and exe == path:
                hits.append(entry)
            elif cmd:
                try:argv=shlex.split(cmd)
                except ValueError:continue
                interpreter=Path(argv[0]).name if argv else ''
                if interpreter in {'bash','sh','dash','zsh','python','python3','node','perl','ruby','php'}:
                    if any(arg in {'-c','-m','-e','--eval'} for arg in argv[1:]):continue
                    script=next((arg for arg in argv[1:] if not arg.startswith('-')),None)
                    if script==path:hits.append(entry)
        return hits

    def check_changed(self) -> list[dict]:
        """Takip edilen dosyalardan icerigi degisenleri dondurur."""
        data = self._load()
        changed = []
        for path, entry in data.items():
            current = _sha256_file(path)
            previous = entry.get('sha256')
            if current is None:
                # Dosya silinmis/erisilemez: degisiklik olarak isaretle.
                if previous is not None:
                    changed.append({**entry, 'current_sha256': None, 'change': 'missing'})
                continue
            if previous and current != previous:
                changed.append({**entry, 'current_sha256': current, 'change': 'modified'})
        return changed

    def record_hit(self, path: str) -> None:
        data = self._load()
        entry = data.get(path)
        if entry is not None:
            entry['hits'] = int(entry.get('hits', 0)) + 1
            entry['last_seen'] = time.time()
            self._save(data)
