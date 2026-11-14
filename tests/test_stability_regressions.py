"""Failure injection and real SQLite/pipe tests; no host network changes."""
import ctypes as C
import errno
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace as NS

import pytest

from satsuma import nfqueue
from satsuma.store import Store
from satsuma.worker_journal import WorkerJournal
from test_nfqueue_observability import fixture


@pytest.mark.parametrize('code', [errno.EINTR, errno.EAGAIN, errno.ENOBUFS])
def test_temporary_verdict_failure_retries_identical_drop_without_accept(code):
    q, _, *buffers = fixture(lambda raw: False)
    sent=[]
    def send(handle, packet_id, verdict, *rest):
        sent.append((packet_id, verdict))
        C.set_errno(code if len(sent)==1 else 0)
        return -1 if len(sent)==1 else 0
    q.lib.nfq_set_verdict=send
    assert q._packet(None,None,None,None)==0
    assert sent==[(42,0),(42,0)]
    assert q.observability['verdict_retries']==1


def test_persistent_verdict_failure_is_bounded_and_not_reported_successful():
    q, _, *buffers = fixture(lambda raw: False)
    calls=[]
    def send(*args):
        calls.append(args);C.set_errno(errno.ENOBUFS);return -1
    q.lib.nfq_set_verdict=send
    assert q._packet(None,None,None,None)==-1
    assert len(calls)==3 and all(x[2]==0 for x in calls)
    assert q.observability['last_verdict_errno']==errno.ENOBUFS


def test_stale_packet_does_not_kill_consumer_or_submit_replacement_accept():
    q, _, *buffers = fixture(lambda raw: False)
    calls=[]
    def send(*args):
        calls.append(args);C.set_errno(errno.ENOENT);return -1
    q.lib.nfq_set_verdict=send
    assert q._packet(None,None,None,None)==0
    assert len(calls)==1 and calls[0][2]==0
    assert q.observability['stale_verdicts']==1
    assert q.observability['verdict_failures']==1


def test_unclassified_handler_failure_preserves_errno_and_stays_fatal(monkeypatch):
    q=object.__new__(nfqueue.Queue)
    q.fd=12;q.handle=None;q.number=201;q.prepare=None;q.finish=None
    def handle(*args):
        C.set_errno(errno.EPERM);return -1
    q.lib=NS(nfq_handle_packet=handle)
    ready=iter([([12],[],[]),([],[],[])])
    monkeypatch.setattr(nfqueue.select,'select',lambda *args:next(ready))
    monkeypatch.setattr(nfqueue.os,'read',lambda *args:b'fixture')
    with pytest.raises(nfqueue.QueueFailure) as error:q.poll(0)
    assert error.value.errno==errno.EPERM and error.value.phase=='handle-packet'
    assert 'queue=201' in str(error.value) and 'errno=1' in str(error.value)


def test_event_and_cursor_are_one_durable_transaction_or_neither(tmp_path):
    store=Store(tmp_path/'data',test=True)
    try:
        with pytest.raises(RuntimeError):
            with store.atomic():
                store.add('events',{'message':'must replay'})
                store.set('cursor','bad')
                raise RuntimeError('delivery failed')
        assert store.recent('events')==[] and store.get('cursor') is None
        with store.atomic():
            store.add('events',{'message':'saved'})
            store.add('normalized',{'message':'saved'})
            store.set('cursor','good')
        other=Store(tmp_path/'data',test=True)
        try:
            assert other.get('cursor')=='good' and len(other.recent('events'))==1
        finally:other.close()
    finally:store.close()


def test_journal_flood_yields_and_resumes_without_skipping_records(tmp_path,monkeypatch):
    script=tmp_path/'journal.py'
    script.write_text('import sys,json\nstart=0\nfor a in sys.argv:\n if a.startswith("--after-cursor="):start=int(a.split("=",1)[1])+1\nfor i in range(start,400):\n print(json.dumps({"__CURSOR":str(i),"MESSAGE":"repeated error","PRIORITY":"3","__REALTIME_TIMESTAMP":"1000000"}))\n')
    popen=subprocess.Popen
    monkeypatch.setattr('satsuma.worker_journal.subprocess.Popen',lambda args,**kw:popen([sys.executable,str(script),*args],**kw))
    store=Store(tmp_path/'data',test=True)
    class Pipeline:
        def ingest_host(self,event):
            store.add('events',event);store.add('normalized',event)
    worker=WorkerJournal(store)
    try:
        batches=[]
        for _ in range(12):
            result=worker.tick(Pipeline());assert result['ok'],result
            batches.append(result['events'])
            assert result['events']<=128
            if store.get(worker.cursor_key)=='399':break
        rows=store.recent('events',1000)
        assert len(rows)==400
        assert len({r['journal_cursor'] for r in rows})==400
        assert len(batches)>=4 and store.get(worker.cursor_key)=='399'
        assert store.db.execute('PRAGMA synchronous').fetchone()[0]==2
    finally:store.close()


def test_install_automatically_checks_integrity_before_functional_health():
    root=Path(__file__).parents[1]
    spec=(root/'packaging/satsuma-core.spec').read_text()
    post=spec.split('%posttrans\n',1)[1].split('%postun\n',1)[0]
    assert post.index('systemctl start satsuma-integrity-check.service')<post.index('systemctl start satsuma-self-health.service')
    assert post.index('-m satsuma.configuration_reload')<post.index('systemctl start satsuma-self-health.service')
    assert '-m satsuma.self_health --report' in post
    unit=(root/'systemd/satsuma-self-health.service').read_text()
    assert 'Wants=satsuma-integrity-check.service' in unit
    assert 'After=local-fs.target satsuma-integrity-check.service' in unit
    for timer in ('satsuma-self-health.timer','satsuma-integrity-check.timer'):
        text=(root/'systemd'/timer).read_text()
        assert 'OnBootSec=' in text and 'OnUnitActiveSec=' in text


def test_files_passed_does_not_fake_functional_success():
    from satsuma.status_view import health_summary
    runtime={'status':'HEALTHY','checked_at':100,'checks':{'application':{'ok':True},'configuration':{'ok':True}}}
    summary=health_summary(runtime,{}, {'status':'RUNNING','updated_at':100},now=101)
    assert summary['files']=='Sağlıklı' and summary['protection']!='Sağlıklı'
    assert summary['protection_status']=='RUNNING' and summary['overall']!='Sağlıklı'


def test_errno_less_handler_failure_keeps_the_consumer_alive(monkeypatch):
    # Field log 2026-10-25: "QueueFailure: NFQUEUE handle-packet failure:
    # queue=201, result=-1, errno=0" restarted app-control for one packet.
    q=object.__new__(nfqueue.Queue)
    q.fd=12;q.handle=None;q.number=201;q.prepare=None;q.finish=None;q.observability={}
    results=iter([-1,0])
    def handle(*args):
        C.set_errno(0);return next(results)
    q.lib=NS(nfq_handle_packet=handle)
    ready=iter([([12],[],[]),([12],[],[]),([],[],[])])
    monkeypatch.setattr(nfqueue.select,'select',lambda *args:next(ready))
    monkeypatch.setattr(nfqueue.os,'read',lambda *args:b'fixture')
    q.poll(0)
    assert q.observability['unexplained_handler_failures']==1
    assert q.observability['consecutive_unexplained_failures']==0


def test_endless_errno_less_failures_still_end_the_consumer(monkeypatch):
    q=object.__new__(nfqueue.Queue)
    q.fd=12;q.handle=None;q.number=201;q.prepare=None;q.finish=None;q.observability={}
    def handle(*args):
        C.set_errno(0);return -1
    q.lib=NS(nfq_handle_packet=handle)
    monkeypatch.setattr(nfqueue.select,'select',lambda *args:([12],[],[]))
    monkeypatch.setattr(nfqueue.os,'read',lambda *args:b'fixture')
    with pytest.raises(nfqueue.QueueFailure):
        for _ in range(nfqueue.UNEXPLAINED_LIMIT):q.poll(0)
