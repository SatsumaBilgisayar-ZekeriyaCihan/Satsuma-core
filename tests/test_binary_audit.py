"""2.2.13: /usr/bin and /usr/sbin are checked against the RPM database.

2.2.13: /usr/bin ve /usr/sbin RPM veritabanıyla karşılaştırılır.
"""
import hashlib
from types import SimpleNamespace as NS

from satsuma import binary_audit
from satsuma.host_store import HostStore


def _tree(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    (bin_dir / 'ls').write_bytes(b'real ls')
    (bin_dir / 'sudo').write_bytes(b'replaced sudo')
    (bin_dir / 'implant').write_bytes(b'dropped tool')
    (bin_dir / 'nmap').write_bytes(b'nmap binary')
    (bin_dir / 'link').symlink_to(bin_dir / 'ls')
    digest = lambda data: hashlib.sha256(data).hexdigest()
    rpm_out = ''.join(f'{bin_dir}/{name}\t{digest(data)}\t8\t{pkg}\n' for name, data, pkg in (
        ('ls', b'real ls', 'coreutils'), ('sudo', b'original sudo', 'sudo'), ('nmap', b'nmap binary', 'nmap')))
    rpm_out += f'{bin_dir}/link\t\t8\tcoreutils\n/etc/other\tx\t8\tsetup\n'
    runner = lambda *a, **k: NS(returncode=0, stdout=rpm_out, stderr='')
    return bin_dir, runner


def test_unowned_modified_and_attack_tools_are_found(tmp_path):
    bin_dir, runner = _tree(tmp_path)
    items = {i['path'].rsplit('/', 1)[1]: i for i in binary_audit.audit(binary_audit.rpm_inventory(runner, (bin_dir,)), (bin_dir,))}
    assert set(items) == {'sudo', 'implant', 'nmap'}
    assert items['sudo']['kinds'] == ['modified'] and items['sudo']['package'] == 'sudo'
    assert items['implant']['kinds'] == ['unowned'] and items['implant']['package'] is None
    assert items['nmap']['kinds'] == ['attack_tool'] and items['nmap']['tool'] == 'ağ tarayıcı'


def test_only_confirmed_malware_is_quarantined_and_hashes_go_to_virustotal(tmp_path):
    bin_dir, runner = _tree(tmp_path)
    store = HostStore(tmp_path / 'host', test=True)
    asked, moved = [], []
    def lookup(sha, key):
        asked.append((sha, key))
        return {'known': True, 'malicious': 40 if sha == hashlib.sha256(b'dropped tool').hexdigest() else 0}
    try:
        state = binary_audit.run(store, manual=True, runner=runner, key='k', lookup=lookup,
                                 quarantine=lambda s, item: moved.append(item['path']) or {'status': 'quarantined'},
                                 dirs=(bin_dir,))
        assert moved == [str(bin_dir / 'implant')]
        assert len(asked) == 2 and all(len(sha) == 64 and key == 'k' for sha, key in asked)
        assert state['counts'] == {'modified': 1, 'unowned': 1, 'attack_tool': 1, 'local': 0}
        assert state['quarantined'] == [str(bin_dir / 'implant')]
        rows = [r[0] for r in store.db.execute('SELECT body FROM findings')]
        assert len(rows) == 3 and any('SATSUMA-BIN-MODIFIED' in r for r in rows)
        # Cached: a second run asks VirusTotal nothing new; daily runs are skipped.
        asked.clear()
        binary_audit.run(store, manual=True, runner=runner, key='k', lookup=lookup,
                         quarantine=lambda s, item: {'status': 'quarantined'}, dirs=(bin_dir,))
        assert asked == []
        assert binary_audit.run(store, manual=False, runner=runner, key='k', lookup=lookup, dirs=(bin_dir,)) == store.get('binary_audit')
    finally:
        store.close()


def test_without_a_key_nothing_leaves_the_machine_and_nothing_is_moved(tmp_path):
    bin_dir, runner = _tree(tmp_path)
    store = HostStore(tmp_path / 'host', test=True)
    try:
        state = binary_audit.run(store, manual=True, runner=runner, key='', lookup=lambda *a: (_ for _ in ()).throw(AssertionError('no lookup')),
                                 quarantine=lambda *a: (_ for _ in ()).throw(AssertionError('no move')), dirs=(bin_dir,))
        assert state['virustotal'] == 'no_key' and state['quarantined'] == []
    finally:
        store.close()


def test_clamav_detection_also_confirms_but_never_for_essential_programs(tmp_path):
    bin_dir, runner = _tree(tmp_path)
    store = HostStore(tmp_path / 'host', test=True)
    moved = []
    try:
        state = binary_audit.run(store, manual=True, runner=runner, key='',
                                 clamav_paths=[str(bin_dir / 'sudo'), str(bin_dir / 'implant')],
                                 quarantine=lambda s, item: moved.append(item['path']) or {'status': 'quarantined'},
                                 dirs=(bin_dir,))
        assert moved == [str(bin_dir / 'implant')]
        sudo = next(i for i in state['items'] if i['path'].endswith('/sudo'))
        assert sudo['quarantine']['status'] == 'not_quarantined' and 'dnf reinstall sudo' in sudo['quarantine']['reason']
        assert 'quarantine_proposal' not in sudo
    finally:
        store.close()


def test_suspicious_programs_get_a_proposal_not_a_move(tmp_path):
    bin_dir, runner = _tree(tmp_path)
    store = HostStore(tmp_path / 'host', test=True)
    try:
        state = binary_audit.run(store, manual=True, runner=runner, key='', dirs=(bin_dir,),
                                 quarantine=lambda *a: (_ for _ in ()).throw(AssertionError('no move')))
        implant = next(i for i in state['items'] if i['path'].endswith('/implant'))
        assert implant['quarantine_proposal']['command'] == 'sudo satsuma-admin karantina al ' + str(bin_dir / 'implant')
        body = next(b for (b,) in store.db.execute('SELECT body FROM findings') if 'BIN-UNOWNED' in b)
        assert 'kendiliğinden geri alınır' in body and (bin_dir / 'implant').exists()
    finally:
        store.close()


def test_usr_local_programs_are_informational():
    assert binary_audit.unowned_kind('/usr/local/bin/mytool') == 'local'
    assert binary_audit.unowned_kind('/usr/bin/mytool') == 'unowned'
    assert binary_audit.FINDINGS['local'][1] == 'info'


def test_system_programs_need_confirmation_to_be_quarantined():
    import pytest
    from satsuma import scan_quarantine as q
    with pytest.raises(PermissionError):
        q.quarantine_target({'path': '/usr/bin/implant'}, lambda r: None)
    with pytest.raises(PermissionError):
        q.quarantine_target({'path': '/opt/satsuma-core/main.py'}, lambda r: None, system_ok=True)


def test_merged_sbin_is_read_once_under_its_real_name(tmp_path):
    bin_dir, runner = _tree(tmp_path)
    (tmp_path / 'sbin').symlink_to(bin_dir)
    owned = binary_audit.rpm_inventory(runner, (bin_dir, tmp_path / 'sbin'))
    paths = [i['path'] for i in binary_audit.audit(owned, (bin_dir, tmp_path / 'sbin'))]
    assert len(paths) == len(set(paths)) == 3 and all(p.startswith(str(bin_dir)) for p in paths)


def test_sbin_recorded_programs_are_owned_under_their_real_bin_name(tmp_path):
    # Field log 2026-10-26: rpm records /usr/sbin/ldconfig, the file is /usr/bin/ldconfig.
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    (tmp_path / 'sbin').symlink_to(bin_dir)
    (bin_dir / 'ldconfig').write_bytes(b'ldconfig')
    digest = hashlib.sha256(b'ldconfig').hexdigest()
    rpm_out = (f"{tmp_path / 'sbin'}/ldconfig\t{digest}\t8\tglibc\n"
               f"{bin_dir}/ldconfig\t\t8\tglibc\n")
    runner = lambda *a, **k: NS(returncode=0, stdout=rpm_out, stderr='')
    owned = binary_audit.rpm_inventory(runner, (bin_dir, tmp_path / 'sbin'))
    assert owned[str(bin_dir / 'ldconfig')] == ('glibc', digest, '8')
    assert binary_audit.audit(owned, (bin_dir, tmp_path / 'sbin')) == []


def test_a_query_that_does_not_match_the_disk_writes_no_findings(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for n in range(binary_audit.UNOWNED_SANITY_LIMIT + 1):
        (bin_dir / f'prog{n}').write_bytes(b'x')
    runner = lambda *a, **k: NS(returncode=0, stdout='/etc/x\tx\t8\tsetup\n', stderr='')
    store = HostStore(tmp_path / 'host', test=True)
    try:
        state = binary_audit.run(store, manual=True, runner=runner, key='', dirs=(bin_dir,),
                                 quarantine=lambda *a: (_ for _ in ()).throw(AssertionError('no move')))
        assert 'güvenilmez' in state['error'] and 'silmeyin' in state['error']
        assert store.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0] == 0
    finally:
        store.close()


def test_every_finding_says_do_not_delete_or_how_to_repair(tmp_path):
    bin_dir, runner = _tree(tmp_path)
    store = HostStore(tmp_path / 'host', test=True)
    try:
        binary_audit.run(store, manual=True, runner=runner, key='', dirs=(bin_dir,))
        bodies = [r[0] for r in store.db.execute('SELECT body FROM findings')]
        assert any('SİLMEYİN' in b and 'dnf reinstall sudo' in b for b in bodies)
        assert any('SİLMEYİN' in b and 'rpm -qf' in b for b in bodies)
    finally:
        store.close()


def test_findings_that_are_fine_now_are_cleared(tmp_path):
    import json
    bin_dir, runner = _tree(tmp_path)
    store = HostStore(tmp_path / 'host', test=True)
    try:
        binary_audit.run(store, manual=True, runner=runner, key='', dirs=(bin_dir,))
        (bin_dir / 'implant').unlink()
        binary_audit.run(store, manual=True, runner=runner, key='', dirs=(bin_dir,))
        bodies = {json.loads(b)['rule_id']: json.loads(b) for (b,) in store.db.execute('SELECT body FROM findings')}
        assert bodies['SATSUMA-BIN-UNOWNED']['status'] == 'CLEARED'
        assert bodies['SATSUMA-BIN-MODIFIED']['status'] == 'REVIEW'
    finally:
        store.close()


def test_dashboard_quarantines_only_what_the_audit_proposed(tmp_path, monkeypatch):
    from satsuma.operator_service import OperatorController
    from satsuma.store import Store
    from satsuma import host_store
    class Auth:
        def login(self, *a, **k): return {'ok': True, 'token': 't'}
        def validate_session(self, *a): return True
    proposed = {'path': '/usr/bin/implant', 'sha256': 'a' * 64, 'package': None,
                'quarantine_proposal': {'path': '/usr/bin/implant', 'sha256': 'a' * 64}}
    class FakeHost:
        def __init__(self, *a, **k): pass
        def get(self, key, default=None): return {'items': [proposed]} if key == 'binary_audit' else default
        def close(self): pass
    monkeypatch.setattr(host_store, 'HostStore', FakeHost)
    calls = []
    from satsuma import scan_quarantine as q
    monkeypatch.setattr(q, 'inspect_target', lambda path: {'path': path, 'sha256': 'a' * 64})
    monkeypatch.setattr(q, 'quarantine_target', lambda target, audit, **k: calls.append((target['path'], k)) or
                        {'status': 'quarantined', 'quarantine_id': 'b' * 32})
    store = Store(tmp_path / 'data', test=True)
    try:
        controller = OperatorController(store, auth=Auth(), boot_provider=lambda: {})
        controller.dispatch(1000, 'login', {})
        import pytest
        with pytest.raises(ValueError, match='onay'):
            controller.dispatch(1000, 'quarantine_system_file', {'token': 't', 'path': '/usr/bin/implant', 'sha256': 'a' * 64})
        with pytest.raises(ValueError, match='öneri'):
            controller.dispatch(1000, 'quarantine_system_file', {'token': 't', 'path': '/usr/bin/ls', 'sha256': 'a' * 64, 'confirmed': True})
        assert not calls
        ok = controller.dispatch(1000, 'quarantine_system_file', {'token': 't', 'path': '/usr/bin/implant', 'sha256': 'a' * 64, 'confirmed': True})
        assert ok.get('status') == 'quarantined' and calls == [('/usr/bin/implant', {'system_ok': True})]
    finally:
        store.close()
