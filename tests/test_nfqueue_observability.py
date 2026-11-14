import ctypes as C
from types import SimpleNamespace as NS
from satsuma.nfqueue import Queue


def fixture(decide,verdict_result=0,size=6):
    header=C.create_string_buffer((42).to_bytes(4,'big'))
    payload=C.create_string_buffer(b'packet')
    outcomes=[]
    def get_payload(data,target):
        C.cast(target,C.POINTER(C.c_void_p))[0]=C.addressof(payload)
        return size
    def verdict(*args):outcomes.append(args[2]);return verdict_result
    q=object.__new__(Queue);q.decide=decide;q.receive_overruns=0;q.observability={}
    q.lib=NS(nfq_get_msg_packet_hdr=lambda data:C.addressof(header),
        nfq_get_payload=get_payload,nfq_set_verdict=verdict)
    return q,outcomes,header,payload


def test_callback_exception_is_counted_and_only_drop_is_submitted():
    def broken(raw):raise RuntimeError('failure')
    q,outcomes,*buffers=fixture(broken)
    assert q._packet(None,None,None,None)==0
    assert outcomes==[0] and q.observability['callback_errors']==1


def test_invalid_payload_and_verdict_failure_are_counted():
    q,outcomes,*buffers=fixture(lambda raw:True,size=-1,verdict_result=-1)
    assert q._packet(None,None,None,None)==-1
    assert outcomes==[0]
    assert q.observability['invalid_payloads']==1
    assert q.observability['verdict_failures']==1


def test_missing_header_never_submits_an_accept():
    q,outcomes,*buffers=fixture(lambda raw:True)
    q.lib.nfq_get_msg_packet_hdr=lambda data:None
    assert q._packet(None,None,None,None)==-1
    assert not outcomes and q.observability['missing_headers']==1
