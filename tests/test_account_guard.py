"""System accounts hold no usable password; found, evidenced, locked. Sistem hesabında parola kalmaz."""
from satsuma import account_guard, kernel_guard

PASSWD = ("root:x:0:0::/root:/bin/bash\nsystemd-x:x:975:975::/:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin\n"
          "svc:x:970:970::/:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n")
SHADOW = ("root:$6$abc:1::::::\nsystemd-x:$y$j9T$abcdefghij:1::::::\nnobody:!:1::::::\n"
          "svc:!$6$zz:1::::::\nalice:$6$q:1::::::\n")


class Done:
    returncode = 0
    stderr = ''


def files(tmp_path):
    (tmp_path / 'passwd').write_text(PASSWD)
    (tmp_path / 'shadow').write_text(SHADOW)
    return {'passwd': tmp_path / 'passwd', 'shadow': tmp_path / 'shadow', 'evidence': tmp_path / 'ev'}


def test_only_system_accounts_with_a_real_hash_are_found(tmp_path):
    paths = files(tmp_path)
    found = account_guard.find(paths['passwd'], paths['shadow'])
    assert [e['name'] for e in found] == ['systemd-x']   # not root, not alice, not locked "!$6$"
    assert found[0]['interactive_shell'] is True


def test_guard_keeps_evidence_then_locks_and_rechecks_clean(tmp_path):
    paths, calls = files(tmp_path), []
    guard = kernel_guard.Guard(state_dir=tmp_path / 'st', can_write=True, echo=lambda line: None,
                               runner=lambda cmd, **kw: (calls.append(cmd), Done())[1], account_paths=paths)
    guard.check_accounts()
    assert calls == [['/usr/sbin/usermod', '-L', '-s', '/usr/sbin/nologin', 'systemd-x']]
    assert guard.accounts['status'] == 'LOCKED'
    kept = list((tmp_path / 'ev').iterdir())
    assert len(kept) == 1 and kept[0].read_text().startswith('systemd-x:$y$')
    assert oct(kept[0].stat().st_mode & 0o777) == '0o600'


def test_without_write_rights_nothing_is_changed(tmp_path):
    paths, calls = files(tmp_path), []
    guard = kernel_guard.Guard(state_dir=tmp_path / 'st', can_write=False, echo=lambda line: None,
                               runner=lambda cmd, **kw: (calls.append(cmd), Done())[1], account_paths=paths)
    guard.check_accounts()
    assert calls == [] and guard.accounts['status'] == 'AT_RISK'


def test_no_evidence_no_change(tmp_path):
    paths = files(tmp_path)
    (tmp_path / 'ev').write_text('a file, not a folder')
    calls = []
    result = account_guard.lock(account_guard.find(paths['passwd'], paths['shadow']),
                                lambda cmd, **kw: (calls.append(cmd), Done())[1], paths['shadow'], paths['evidence'])
    assert calls == [] and result[0]['locked'] is False and 'evidence_not_kept' in result[0]['error']
