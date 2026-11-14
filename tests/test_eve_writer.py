"""EVE identity comes from the verified process, not arbitrary file ownership."""
import stat
from types import SimpleNamespace
import pytest
from satsuma.source_guard import resolve_writer_uid, validate_stat
from satsuma.config import validate
from satsuma.policy import validate as validate_policy, from_legacy
from satsuma.ips import process_writer_uid
from satsuma.ips import wait_for_eve

@pytest.mark.parametrize('configured',['managed_suricata',0,971])
def test_nonroot_managed_writer_and_legacy_zero_default(configured):
    assert resolve_writer_uid(configured,lambda:{'ready':True,'writer_uid':971})==971

def test_explicit_nonroot_pin_must_match_real_writer():
    with pytest.raises(PermissionError):resolve_writer_uid(970,lambda:{'ready':True,'writer_uid':971})

@pytest.mark.parametrize('status',[{'ready':False,'writer_uid':971},{'ready':True},{'ready':True,'writer_uid':True},{'ready':True,'writer_uid':-1}])
def test_unverified_or_malformed_service_identity_is_not_adopted(status):
    with pytest.raises(PermissionError):resolve_writer_uid(provider=lambda:status)

def test_actual_root_writer_still_supported():
    assert resolve_writer_uid(provider=lambda:{'ready':True,'writer_uid':0})==0

@pytest.mark.parametrize('uid,mode,links,allowed',[(971,0o640,1,True),(0,0o640,1,True),(1000,0o640,1,False),(971,0o660,1,False),(971,0o640,2,False)])
def test_only_root_or_verified_writer_can_own_safe_eve(uid,mode,links,allowed):
    info=SimpleNamespace(st_uid=uid,st_mode=stat.S_IFREG|mode,st_nlink=links)
    if allowed:validate_stat(info,971)
    else:
        with pytest.raises(PermissionError):validate_stat(info,971)

def test_filesystem_uid_is_read_from_process_status(tmp_path):
    (tmp_path/'status').write_text('Name:\tsuricata\nUid:\t0\t970\t0\t971\n')
    assert process_writer_uid(tmp_path)==971
    (tmp_path/'status').write_text('Uid:\t0\tunknown\t0\t0\n')
    with pytest.raises(RuntimeError):process_writer_uid(tmp_path)

@pytest.mark.parametrize('uid',['managed_suricata',0,971])
def test_configuration_and_policy_support_managed_or_explicit_writer(uid):
    cfg=validate({'eve_writer_uid':uid})
    policy=validate_policy(from_legacy(cfg))
    assert policy['workers']['suricata_collector']['writer_uid']==uid


def test_wait_for_eve_only_retries_missing_file(tmp_path):
    path = tmp_path / 'eve.json'
    clock = iter([0, 0, 1])
    calls = []
    def open_later(path, uid):
        calls.append(uid)
        if len(calls) == 1:
            raise FileNotFoundError(path)
        return open(__file__, 'rb')
    wait_for_eve(path, 971, opener=open_later, clock=lambda:next(clock), sleep=lambda _:None)
    assert calls == [971, 971]
    def unsafe(*_):
        raise PermissionError('Untrusted EVE owner')
    with pytest.raises(PermissionError):
        wait_for_eve(path, 971, opener=unsafe)


def test_missing_eve_produces_actionable_failure(tmp_path):
    path = tmp_path / 'missing-eve.json'
    with pytest.raises(RuntimeError, match='EVE was not created'):
        wait_for_eve(path, 0, timeout=0, opener=lambda p,_:open(p,'rb'))
