"""Synthetic /proc-style fixtures only: no process kill or policy changes."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import Mock
import pytest
from satsuma.memory_scope import scan_executable_regions,access_model
from satsuma import ai_rule_package as pkg
from test_deepseek_secure_workflow import proposal


def fixture_proc(tmp_path,mappings=None):
    root=tmp_path/'4242';root.mkdir()
    (root/'stat').write_text('4242 (java fixture) '+' '.join(['0']*19+['1234']))
    (root/'exe').symlink_to('/fixture/java')
    data=os.urandom(256)
    mappings=mappings or [('1000-1100','rwxp',''),('2000-2100','r-xp','/memfd:jit (deleted)'),('3000-3100','r-xp','/fixture/lib.so')]
    lines=[]
    with (root/'mem').open('wb') as stream:
        for address,perms,name in mappings:
            start,end=(int(v,16) for v in address.split('-'))
            if start<2**63:
                stream.seek(start);stream.write((data*((end-start)//len(data)+1))[:end-start])
            lines.append(f'{address} {perms} 00000000 00:00 0 {name}'.strip())
    (root/'maps').write_text('\n'.join(lines)+'\n')
    return root,data


def test_anon_memfd_and_file_mappings_read_but_never_reported_clean(tmp_path):
    root,data=fixture_proc(tmp_path)
    report=scan_executable_regions(root,time_limit=.25)
    assert report['bytes_read']==768 and report['regions_read']==3
    assert report['anonymous_regions']==report['memfd_regions']==report['file_backed_regions']==1
    assert report['coverage']=='COMPLETE_BYTE_READ' and report['status']=='OBSERVED_UNVERIFIED'
    assert report['reference_verified_bytes']==0 and not report['intervention_authorized']
    assert data.hex() not in json.dumps(report)
    assert all('content' not in row for row in report['regions'])
    assert all(row['jit_possible'] for row in report['regions'][:2])


def test_denied_memory_is_not_clean_and_does_not_change_permissions(tmp_path,monkeypatch):
    root,data=fixture_proc(tmp_path);original=Path.open;before=(root/'mem').stat().st_mode
    def opening(path,*args,**kwargs):
        if path==root/'mem':raise PermissionError()
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',opening)
    report=scan_executable_regions(root,time_limit=.25)
    assert report['status']=='ACCESS_DENIED' and report['bytes_read']==0
    assert report['access_denied_regions']==3 and report['coverage']=='NONE'
    assert (root/'mem').stat().st_mode==before


def test_identity_change_invalidates_comparison(tmp_path,monkeypatch):
    root,data=fixture_proc(tmp_path);original=os.pread;changed=False
    def reading(*args):
        nonlocal changed
        result=original(*args)
        if not changed:
            (root/'stat').write_text('4242 (java fixture) '+' '.join(['0']*19+['9999']));changed=True
        return result
    monkeypatch.setattr(os,'pread',reading)
    report=scan_executable_regions(root,time_limit=.25)
    assert report['status']=='IDENTITY_CHANGED' and report['coverage']=='UNVERIFIED'
    assert not report['intervention_authorized']
    assert report['invalidated_read_bytes']==report['bytes_read']
    assert report['valid_snapshot_read_bytes']==0 and report['read_coverage_percent'] is None
    assert report['identity_changed_bytes']==report['candidate_bytes'] and report['category_totals_consistent']


def test_budget_partial_scan_resumes_inside_large_region(tmp_path):
    root,data=fixture_proc(tmp_path,[('1000-2000','r-xp','/fixture/large.so')])
    first=scan_executable_regions(root,byte_limit=128,time_limit=.25)
    assert first['coverage']=='PARTIAL' and first['bytes_read']==128
    second=scan_executable_regions(root,byte_limit=128,time_limit=.25,region_offset=first['next_region_offset'],
        region_byte_offset=first['next_region_byte_offset'],resume_identity=first['scan_identity'])
    assert second['regions'][0]['sample_offset']==128 and second['bytes_read']==128
    assert first['candidate_bytes']==4096


def test_changed_identity_cannot_reuse_resume_cursor(tmp_path):
    root,data=fixture_proc(tmp_path)
    report=scan_executable_regions(root,byte_limit=128,time_limit=.25,region_byte_offset=128,resume_identity='stale')
    assert report['regions'][0]['sample_offset']==0


def test_trusted_reference_difference_is_not_automatic_malware_or_stop(tmp_path):
    root,data=fixture_proc(tmp_path,[('1000-1100','r-xp','/fixture/lib.so')])
    report=scan_executable_regions(root,time_limit=.25,trusted_reference_reader=lambda region,size:b'\0'*size)
    assert report['reference_verified_bytes']==256
    assert report['regions'][0]['reference_status']=='TRUSTED_REFERENCE_DIFFERENCE_REQUIRES_RELOCATION_REVIEW'
    assert report['status']=='OBSERVED_UNVERIFIED' and not report['intervention_authorized']


def test_ptrace_three_remains_unchanged_and_unknown_access_is_explicit(tmp_path):
    path=tmp_path/'sys/kernel/yama';path.mkdir(parents=True)
    (path/'ptrace_scope').write_text('3\n')
    model=access_model(tmp_path)
    assert model['ptrace_scope']=='3' and model['cross_process_access']=='potentially_denied'
    assert not model['policy_changed'] and not model['selinux_changed']
    assert (path/'ptrace_scope').read_text()=='3\n'


def test_zero_budget_and_no_executable_regions_are_distinct(tmp_path):
    root,data=fixture_proc(tmp_path)
    report=scan_executable_regions(root,byte_limit=0,time_limit=.25)
    assert report['bytes_read']==0 and report['coverage']=='PARTIAL'
    (root/'maps').write_text('1000-1100 rw-p 00000000 00:00 0\n')
    report=scan_executable_regions(root,time_limit=.25)
    assert report['status']=='NO_EXECUTABLE_REGIONS' and report['coverage']=='NOT_APPLICABLE'


def test_deepseek_memory_rule_uses_supported_sensor_and_isolated_engine():
    package=proposal();rule=package['detection']
    rule['base_match']={'source':'memory','action':'memfd_mapping'}
    package['response_proposal']['detection_sha256']=pkg.digest(rule)
    package['test_cases']={
        'positive':[{'source':'memory','cmd':'','action':'memfd_mapping'}],
        'negative':[{'source':'memory','cmd':'','action':'normal_memory_activity'}],
        'wrong_source':[{'source':'sys_proc','cmd':'','action':'memfd_mapping'}]}
    assert pkg.validate_package(package)==[] and pkg.test_package(package)['passed']
    rule['base_match']['action']='imaginary_full_ram_malware_verdict'
    assert pkg.validate_package(package)


def test_byte_categories_are_disjoint_and_sum_to_known_snapshot(tmp_path):
    root,data=fixture_proc(tmp_path)
    report=scan_executable_regions(root,byte_limit=128,time_limit=.25)
    assert report['metadata_only_bytes']==0
    assert report['budget_skipped_bytes']==640
    assert report['valid_snapshot_read_bytes']==128
    assert sum(report['coverage_categories'].values())==report['candidate_bytes']==768
    assert report['category_totals_consistent']
    assert report['read_coverage_percent']==round(100*128/768,4)


def test_kernel_metadata_only_is_not_budget_or_read_memory(tmp_path):
    root,data=fixture_proc(tmp_path,[('ffffffffff600000-ffffffffff601000','--xp','[vsyscall]')])
    report=scan_executable_regions(root,time_limit=.25)
    assert report['metadata_only_bytes']==4096 and report['bytes_read']==0
    assert report['budget_skipped_bytes']==0 and report['read_coverage_percent']==0
    assert report['category_totals_consistent']


def test_short_read_classifies_unreadable_remainder_without_double_count(tmp_path,monkeypatch):
    root,data=fixture_proc(tmp_path,[('1000-1100','r-xp','/fixture/lib.so')]);original=os.pread
    monkeypatch.setattr(os,'pread',lambda fd,size,offset:original(fd,min(32,size),offset))
    report=scan_executable_regions(root,time_limit=.25)
    assert report['bytes_read']==32 and report['unreadable_bytes']==224
    assert report['metadata_only_bytes']==0 and report['budget_skipped_bytes']==0
    assert report['category_totals_consistent']


def test_unreadable_memory_is_separate_from_access_denied(tmp_path,monkeypatch):
    root,data=fixture_proc(tmp_path)
    def reading(*args):raise OSError('synthetic I/O error')
    monkeypatch.setattr(os,'pread',reading)
    report=scan_executable_regions(root,time_limit=.25)
    assert report['unreadable_bytes']==768 and report['access_denied_bytes']==0
    assert report['valid_snapshot_read_bytes']==0 and report['category_totals_consistent']


def test_mapping_change_invalidates_all_read_coverage(tmp_path,monkeypatch):
    root,data=fixture_proc(tmp_path);original=os.pread
    def reading(*args):
        output=original(*args)
        with (root/'maps').open('a') as stream:stream.write('9000-9100 r--p 00000000 00:00 0\n')
        return output
    monkeypatch.setattr(os,'pread',reading)
    report=scan_executable_regions(root,time_limit=.25)
    assert report['status']=='MAPPINGS_CHANGED' and report['bytes_read']>0
    assert report['invalidated_read_bytes']==report['bytes_read']
    assert report['valid_snapshot_read_bytes']==report['reference_verified_bytes']==0
    assert report['read_coverage_percent'] is None and report['partial_observed_coverage_percent'] is None
    assert report['mapping_changed_bytes']==report['candidate_bytes'] and report['category_totals_consistent']


def test_incomplete_mapping_denominator_has_only_explicit_partial_percentage(tmp_path):
    root,data=fixture_proc(tmp_path)
    with (root/'maps').open('a') as stream:stream.write('unparseable mapping\n')
    report=scan_executable_regions(root,time_limit=.25)
    assert report['mapping_denominator_incomplete']
    assert report['read_coverage_percent'] is None
    assert report['partial_observed_coverage_percent']==100
    assert report['unclassified_regions']==1


def test_qt_memory_status_never_presents_partial_percentage_as_complete():
    from satsuma.dashboard_qt.panels.defense_sections import memory_status
    text=memory_status({'inspected':1,'updated_at':__import__('time').time(),'validation_counts':{},
        'extended_scope':{'mapping_denominator_incomplete':True,'partial_observed_coverage_percent':25,
                          'read_coverage_percent':None,'totals':{'bytes_read':256,'metadata_only_bytes':0,'budget_skipped_bytes':768}}})
    assert 'KISMİ GÖZLENEN KAPSAM' in text and 'Payda eksik' in text and '25%' in text
    assert 'Bütçe atlanan: 768' in text and 'tüm RAM değildir' in text


def test_access_denied_bytes_never_enter_read_coverage(tmp_path,monkeypatch):
    root,data=fixture_proc(tmp_path)
    def reading(*args):raise PermissionError()
    monkeypatch.setattr(os,'pread',reading)
    report=scan_executable_regions(root,time_limit=.25)
    assert report['access_denied_bytes']==768 and report['bytes_read']==0
    assert report['metadata_only_bytes']==report['budget_skipped_bytes']==0
    assert report['category_totals_consistent'] and report['read_coverage_percent']==0
