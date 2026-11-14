"""Continuously watch essential paths; never delete real system files in tests."""
import os
import stat
import time

CRITICAL_PATHS = ('/opt/satsuma-core/main.py', '/opt/satsuma-core/satsuma', '/etc/satsuma-core')


REASONS = {
    'critical_path_missing': 'Dosya veya dizin bulunamadı',
    'critical_path_replaced': 'Dosya veya dizin kimliği değişti',
    'critical_path_world_writable': 'Herkese yazma izni açık',
    'critical_path_unreadable': 'Dosya veya dizin okunamadı',
}


def failure_text(failure):
    return REASONS.get(failure.get('reason'), 'Bütünlük denetimi başarısız') + ': ' + failure.get('path', '?')


class CriticalGuardian:
    def __init__(self, store, paths=CRITICAL_PATHS, interval=5):
        self.store, self.paths, self.interval = store, tuple(paths), interval
        self.last = 0
        self.previous = None
        self.baseline = store.get('critical_paths_baseline', {}) or {}

    def tick(self, force=False):
        if not force and time.monotonic() - self.last < self.interval:
            return
        self.last = time.monotonic()
        self.baseline = self.store.get('critical_paths_baseline', {}) or {}
        failures = []
        if self.paths == CRITICAL_PATHS:
            from .early_guard import current_boot_id
            boot_id = current_boot_id()
            if self.store.get('critical_paths_boot_id') != boot_id:
                from .self_guard import verify
                try:
                    verify()
                    self.baseline = {}
                    self.store.set('critical_paths_boot_id', boot_id)
                except Exception as exc:
                    failures.append({'path': '/opt/satsuma-core', 'reason': 'application_verification_failed', 'error': str(exc)[:200]})
        for path in self.paths:
            try:
                info = os.stat(path)
                identity = {'device': info.st_dev, 'inode': info.st_ino, 'type': stat.S_IFMT(info.st_mode)}
                old = self.baseline.get(path)
                if old and old != identity:
                    failures.append({'path': path, 'reason': 'critical_path_replaced'})
                elif not old:
                    self.baseline[path] = identity
                if info.st_mode & 0o002:
                    failures.append({'path': path, 'reason': 'critical_path_world_writable'})
            except FileNotFoundError:
                failures.append({'path': path, 'reason': 'critical_path_missing'})
            except OSError as exc:
                failures.append({'path': path, 'reason': 'critical_path_unreadable', 'error': str(exc)[:200]})
        self.store.set('critical_paths_baseline', self.baseline)
        from .early_guard import read_verdict
        self.store.set('early_boot', read_verdict())
        state = {'status': 'CRITICAL' if failures else 'HEALTHY', 'failures': failures, 'checked_at': time.time()}
        self.store.set('critical_integrity', state)
        if failures != self.previous:
            for failure in failures:
                finding = {'timestamp': time.time(), 'title': failure_text(failure),
                           'severity': 'critical', 'classification': 'confirmed', 'source': 'critical_guardian', **failure}
                self.store.add('findings', finding)
                self.store.add('actions', {'action': 'integrity.alert', 'status': 'critical_path_failure',
                                          'target': failure['path'], 'reason': failure['reason'], 'timestamp': time.time()})
                print('SATSUMA CRITICAL: ' + finding['title'], flush=True)
        self.previous = failures
        return state


def run():
    from .store import Store
    store = Store()
    guardian = CriticalGuardian(store)
    try:
        while True:
            guardian.tick()
            time.sleep(1)
    finally:
        store.close()


if __name__ == '__main__':
    run()
