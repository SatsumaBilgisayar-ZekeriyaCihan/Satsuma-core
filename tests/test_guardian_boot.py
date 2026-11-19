"""2.2.53: a reboot no longer raises a critical "identity changed: /etc/satsuma-core".

Field 2026-11-19: Olanlar → Bulgular listed a critical, confirmed pair at every
boot ("Bütünlük denetimi başarısız" and "Dosya veya dizin kimliği değişti:
/etc/satsuma-core") with process and PID "Bilinmiyor".
"""
from satsuma import critical_guardian as guardian


class Store:
    def __init__(self):
        self.state, self.records = {}, []

    def get(self, key, default=None):
        return self.state.get(key, default)

    def set(self, key, value):
        self.state[key] = value

    def add(self, kind, body):
        self.records.append((kind, body))


def run_boot(monkeypatch, tmp_path, verify_results, clock_steps, boot='boot-2'):
    """One boot: /etc/satsuma-core already has a different inode than the previous boot's baseline."""
    paths = {p: tmp_path / p.strip('/').replace('/', '_') for p in guardian.CRITICAL_PATHS}
    for path in paths.values():
        path.mkdir()
    store = Store()
    store.set('critical_paths_boot_id', 'boot-1')
    store.set('critical_paths_baseline', {str(paths['/etc/satsuma-core']): {'device': 1, 'inode': 1, 'type': 0o040000}})
    results = iter(verify_results)

    def verify():
        if not next(results):
            raise RuntimeError('image not mounted yet')
    import satsuma.self_guard as self_guard
    import satsuma.early_guard as early_guard
    monkeypatch.setattr(self_guard, 'verify', verify)
    monkeypatch.setattr(early_guard, 'current_boot_id', lambda: boot)
    monkeypatch.setattr(early_guard, 'read_verdict', lambda: {})
    monkeypatch.setattr(guardian, 'CRITICAL_PATHS', tuple(str(p) for p in paths.values()))
    g = guardian.CriticalGuardian(store, paths=guardian.CRITICAL_PATHS)
    now = [1000.0]
    g.clock = lambda: now[0]
    for step in clock_steps:
        now[0] += step
        g.tick(force=True)
    return store


def findings(store):
    return [body for kind, body in store.records if kind == 'findings']


def test_first_verification_failing_at_boot_raises_nothing(monkeypatch, tmp_path):
    store = run_boot(monkeypatch, tmp_path, [False, False, True, True], [0, 5, 5, 5])
    assert findings(store) == []
    assert store.get('critical_paths_boot_id') == 'boot-2'


def test_a_verification_that_keeps_failing_is_reported_after_the_grace(monkeypatch, tmp_path):
    store = run_boot(monkeypatch, tmp_path, [False] * 10, [0, 60, 61])
    reported = findings(store)
    assert [f['reason'] for f in reported] == ['application_verification_failed']
    assert reported[0]['title'] == 'Satsuma uygulama doğrulaması başarısız: /opt/satsuma-core'
    assert reported[0]['rule_id'] == 'SATSUMA-GUARD-PATH' and reported[0]['type'] == 'file_integrity'


def test_a_path_replaced_during_the_boot_is_still_critical(monkeypatch, tmp_path):
    store = run_boot(monkeypatch, tmp_path, [True, True], [0, 5])
    target = next(p for p in guardian.CRITICAL_PATHS if p.endswith('etc_satsuma-core'))
    import os
    os.rename(target, target + '.old')
    os.mkdir(target)
    g = guardian.CriticalGuardian(store, paths=guardian.CRITICAL_PATHS)
    g.tick(force=True)
    assert [f['reason'] for f in findings(store)] == ['critical_path_replaced']


def test_finding_rows_show_no_process_as_a_dash_and_read_in_turkish():
    from satsuma import dashboard_api as api
    row = api._normalize_host_finding({'title': 'Dosya veya dizin kimliği değişti: /etc/satsuma-core',
                                       'source': 'critical_guardian', 'severity': 'critical',
                                       'classification': 'confirmed'}, 'x', {})
    assert (row['process_name'], row['pid']) == ('—', '—')
    assert (row['rule_id'], row['confidence_label'], row['status_label'], row['event_label']) == \
        ('SATSUMA-GUARD-PATH', 'Orta', 'Yeni', 'Dosya bütünlüğü')
