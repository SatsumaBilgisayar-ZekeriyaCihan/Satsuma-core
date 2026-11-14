"""Regression tests for command boundaries, metadata collection and defense views."""
from pathlib import Path
import tempfile,os
import pytest
from satsuma.smart_rules import SmartRuleEngine,_term_in_command
from satsuma.worker_memory import inspect_process,WorkerMemory
from satsuma.store import Store

@pytest.mark.parametrize('cmd,term,wanted',[
 ('echo id','id',False),('grep modprobe README','modprobe',False),('sudo -s id','sudo -S',False),('sudo -r role id','sudo -R',False),('curl -t ftp example','curl -T',False),('sudo -u root -n id','sudo -n',True),('sudo\t-n id','sudo -n',True),('find / -type f -perm -4000','find / -perm -4000',True),('shred -v -f -z demo','shred -vfz',True),('identity','id',False)])
def test_argv_boundaries(cmd,term,wanted):assert _term_in_command(cmd,term)==wanted

def test_absolute_path():
 assert SmartRuleEngine._path_match('/etc/passwd','/etc/passwd')
 assert not SmartRuleEngine._path_match('/tmp/etc/passwd','/etc/passwd')

def test_memory_metadata_and_worker():
 with tempfile.TemporaryDirectory() as tmp:
  root=Path(tmp);proc=root/'proc';p=proc/'12345';p.mkdir(parents=True)
  os.symlink('/memfd:demo (deleted)',p/'exe')
  (p/'maps').write_text('1000-2000 rwxp 0 00:00 0\n2000-3000 r-xp 0 00:00 0 /memfd:demo (deleted)\n')
  (p/'stat').write_text('12345 (demo) '+' '.join(['0']*22))
  assert set(inspect_process(p))=={'anonymous_rwx','memfd_executable','memfd_mapping','deleted_executable'}
  store=Store(root/'data',test=True)
  try:
   events=[]
   class Pipeline:
    def ingest_host(self,e):events.append(e)
   worker=WorkerMemory(store,proc_root=proc);worker.tick(Pipeline())
   assert len(events)==4
   engine=SmartRuleEngine()
   assert all(any(f['rule_id'].startswith('SATSUMA-RAM-') for f in engine.match(e)) for e in events)
   worker.last=0;worker.tick(Pipeline());assert len(events)==4
   assert store.get('worker.memory.health')['unreadable']==0
  finally:store.close()

def test_defense_panels_filter():
 from satsuma.dashboard_qt.panels.defense_sections import MemoryDefensePanel,NetworkDefensePanel
 assert MemoryDefensePanel._rows_from(MemoryDefensePanel.__new__(MemoryDefensePanel),{'items':[{'rule_id':'SATSUMA-RAM-001'},{'rule_id':'SATSUMA-DISC-001'}]})==[{'rule_id':'SATSUMA-RAM-001'}]
 assert NetworkDefensePanel.PREFIXES

@pytest.mark.parametrize('source,action,path,rid',[
 ('sys_proc','new_port','','SATSUMA-NET-201'),
 ('audit','file_access','/etc/nftables.conf','SATSUMA-NET-202'),
 ('audit','file_access','/etc/resolv.conf','SATSUMA-NET-203')])
def test_network_observations(source,action,path,rid):
 findings=SmartRuleEngine().match(dict(source=source,action=action,file_path=path,operation='write'))
 assert any(rid in f.get('matched_rules',[f['rule_id']]) for f in findings)
 assert all(not {'kill_process','block_ip'} & set(f['actions']) for f in findings)

def test_env_names_and_worker_shape():
 from satsuma.worker_sys_proc import WorkerSysProc
 with tempfile.TemporaryDirectory() as tmp:
  store=Store(Path(tmp)/'data',test=True)
  try:
   worker=WorkerSysProc(store);worker._baseline_initialized=True
   events=worker._raw_to_events({'processes':{12345:dict(cmd='demo',exe='/usr/bin/demo',uid=1000,ppid=1,start_seconds=1,env='LD_PRELOAD=present')}})
   engine=SmartRuleEngine()
   assert any('SATSUMA-EVAS-010' in f.get('matched_rules',[f['rule_id']]) for e in events for f in engine.match(e))
   assert not any('SATSUMA-EVAS-010' in f.get('matched_rules',[f['rule_id']]) for f in engine.match(dict(source='sys_proc',env='MY_LD_PRELOAD_NOTE=1')))
  finally:store.close()

def test_memory_normalized_contract():
 import json
 from satsuma.pipeline import Pipeline
 from run_satsuma_teams import _smart_event
 with tempfile.TemporaryDirectory() as tmp:
  store=Store(Path(tmp)/'data',test=True)
  try:
   # Host normalization uses no network operations.
   pipeline=object.__new__(Pipeline)
   raw=dict(source='memory',kind='memory',action='memfd_executable',pid=12345,category='memory',timestamp=1)
   normalized=pipeline._build_host_normalized(raw)
   ev=_smart_event(1,json.dumps({'event':normalized,'raw_id':1}))
   assert any(f['rule_id']=='SATSUMA-RAM-002' for f in SmartRuleEngine().match(ev))
  finally:store.close()

def test_crontab_listing_is_not_persistence():
 assert not any('SATSUMA-PERSIST-003' in f.get('matched_rules',[f['rule_id']]) for f in SmartRuleEngine().match(dict(source='sys_proc',cmd='crontab -l')))

def test_builtin_rules_never_directly_kill_or_block():
 stats=SmartRuleEngine().stats()
 assert stats['destructive_actions']=={}
 assert stats['invalid_files']==0

@pytest.mark.parametrize('path',['/dev/sdz','/dev/nvme0n1p1'])
def test_disk_format_device_coverage(path):
 findings=SmartRuleEngine().match(dict(source='sys_proc',cmd='mkfs.ext4 '+path))
 assert any('SATSUMA-IMP-002' in f.get('matched_rules',[f['rule_id']]) for f in findings)


def test_program_updated_on_disk_is_not_a_deleted_executable(tmp_path):
 # Field 2026-11-04: running programs of an updated package looked deleted.
 p=tmp_path/'proc'/'4242';p.mkdir(parents=True)
 os.symlink('/usr/bin/firefox (deleted)',p/'exe');(p/'maps').write_text('')
 assert inspect_process(p,replaced=lambda exe:True)==['replaced_executable']
 assert inspect_process(p,replaced=lambda exe:False)==['deleted_executable']
 from satsuma.worker_memory import _replaced_by_update
 assert not _replaced_by_update('/tmp/payload (deleted)')
 assert not _replaced_by_update('/memfd:x (deleted)')


@pytest.mark.parametrize('cmd,term,wanted', [
 # Field 2026-11-04: options of the command a wrapper or shell runs are not its own.
 ('sh -c -- ps --no-header -p 28956 o pid', 'sh -p', False),
 ('sudo journalctl -u satsuma-core-dns -n 30 --no-pager', 'sudo -n', False),
 ('sudo chattr -i /etc/hosts', 'sudo -i', False),
 ('sudo ssh -R 8080:x:80 h', 'sudo -R', False),
 ('sudo find / -perm -g=s', 'sudo -e', False),
 ('/bin/sh -p', '/bin/sh -p', True), ('sudo -u root -n id', 'sudo -n', True),
 ('sudo -i', 'sudo -i', True), ('sudo su -', 'sudo su -', True), ('bash -c "sh -p"', 'sh -p', True)])
def test_wrapper_options_stop_at_the_command(cmd, term, wanted):
 assert _term_in_command(cmd, term) == wanted
