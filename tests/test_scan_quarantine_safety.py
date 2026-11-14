"""No host mutations: fake quarantine backend and in-memory audit store."""
from unittest.mock import patch
from satsuma.security_scan import quarantine_files

class Store:
    def __init__(self): self.events=[]
    def add(self, key, row): self.events.append((key,row))


def test_refused_system_file_does_not_interrupt_other_findings():
    calls=[]
    def fake(target, audit):
        calls.append(target['path'])
        if target['path']=='/etc/important.conf':
            raise PermissionError('system path protected')
        audit({'status':'quarantined'})
        return {'status':'quarantined','source':target['path']}
    store=Store()
    files=[{'path':'/etc/important.conf','sha256':'a'*64},
           {'path':'/home/person/eicar.fixture','sha256':'b'*64}]
    with patch('satsuma.scan_quarantine.quarantine_target',fake):
        result=quarantine_files(store,files)
    assert [r['status'] for r in result]==['not_quarantined','quarantined']
    assert calls==['/etc/important.conf','/home/person/eicar.fixture']
    assert len(store.events)==1


def test_duplicate_finding_is_not_quarantined_twice():
    calls=[]
    def fake(target,audit):
        calls.append(target['path'])
        return {'status':'quarantined','source':target['path']}
    target={'path':'/home/person/same','sha256':'c'*64,'device':1,'inode':42}
    with patch('satsuma.scan_quarantine.quarantine_target',fake):
        result=quarantine_files(Store(),[target,target.copy()])
    assert calls==[target['path']]
    assert [r['status'] for r in result]==['quarantined','skipped']


def test_unverified_file_is_not_moved():
    with patch('satsuma.scan_quarantine.quarantine_target',side_effect=AssertionError('called')):
        result=quarantine_files(Store(),[{'path':'/home/person/changed'}])
    assert result[0]['status']=='skipped'
