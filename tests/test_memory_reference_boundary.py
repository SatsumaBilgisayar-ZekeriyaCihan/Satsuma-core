"""Independent reference boundary failures must not corrupt RAM-read evidence.

Bağımsız referans sınırı hataları RAM okuma kanıtını bozmamalıdır.
"""
import pytest
from test_memory_scope_bounded import fixture_proc
from satsuma.memory_scope import scan_executable_regions


@pytest.mark.parametrize('error',[PermissionError('reference denied'),OSError('reference missing'),RuntimeError('untrusted origin')])
def test_reference_failure_preserves_real_read_and_disjoint_counts(tmp_path,error):
    root,data=fixture_proc(tmp_path,[('1000-1100','r-xp','/fixture/lib.so')])
    def unavailable(region,size):raise error
    report=scan_executable_regions(root,time_limit=.25,trusted_reference_reader=unavailable)
    assert report['bytes_read']==256 and report['valid_snapshot_read_bytes']==256
    assert report['access_denied_bytes']==0 and report['access_denied_regions']==0
    assert report['reference_verified_bytes']==report['reference_compared_bytes']==0
    assert report['category_totals_consistent'] and not report['clean_result_claimed']


@pytest.mark.parametrize('match',[True,False])
def test_reference_match_and_difference_have_separate_counters_without_stop(tmp_path,match):
    root,data=fixture_proc(tmp_path,[('1000-1100','r-xp','/fixture/lib.so')])
    report=scan_executable_regions(root,time_limit=.25,trusted_reference_reader=lambda region,size:data[:size] if match else b'\0'*size)
    assert report['reference_compared_bytes']==256
    assert report['reference_match_bytes']==(256 if match else 0)
    assert report['reference_difference_bytes']==(0 if match else 256)
    assert not report['intervention_authorized'] and not report['clean_result_claimed']


def test_jit_memfd_deleted_never_ask_provider_or_claim_trust(tmp_path):
    root,_=fixture_proc(tmp_path,[('1000-1100','rwxp',''),('2000-2100','r-xp','/memfd:jit'),('3000-3100','r-xp','/fixture/app (deleted)')])
    def forbidden(*args):raise AssertionError('Unverifiable mapping must not ask for a trusted file reference')
    report=scan_executable_regions(root,time_limit=.25,trusted_reference_reader=forbidden)
    assert report['bytes_read']==768 and report['reference_compared_bytes']==0


def test_changed_mapping_invalidates_previously_compared_reference(tmp_path,monkeypatch):
    root,data=fixture_proc(tmp_path,[('1000-1100','r-xp','/fixture/lib.so')])
    def changing(region,size):
        (root/'maps').write_text((root/'maps').read_text().replace('r-xp','rwxp'))
        return data[:size]
    report=scan_executable_regions(root,time_limit=.25,trusted_reference_reader=changing)
    assert report['status']=='MAPPINGS_CHANGED'
    assert report['reference_verified_bytes']==report['reference_compared_bytes']==report['reference_match_bytes']==0
    assert not report['intervention_authorized']


def test_worker_reading_and_reference_pending_are_separate_ui_states():
    import time
    from satsuma.dashboard_qt.panels.defense_sections import memory_status
    text=memory_status({'status':'RUNNING','updated_at':time.time(),'inspected':1,
        'validation_counts':{'CODE_MATCH':1},'extended_scope':{
        'engine_state':'OBSERVATION_ONLY','coverage':'BOUNDED_PARTIAL',
        'trusted_reference_provider_configured':False,
        'totals':{'valid_snapshot_read_bytes':8388608,'bytes_read':8388608,'reference_verified_bytes':0}}})
    assert 'Bellek worker: Çalışıyor' in text and 'RAM okuması: başarılı' in text
    assert 'BOUNDED_PARTIAL' in text and 'Güvenilir referans doğrulaması: bekliyor' in text
