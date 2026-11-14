"""Real Operator wire protocol + peer UID + GPG lifecycle in isolated storage.

Administrator sessions and public trust ownership are explicit test fixtures;
SO_PEERCRED, bounded framing and controller transitions are real. No real API,
Fedora service or private product key is used.
"""
import json
import os
import socket
import struct
import threading
import uuid
from unittest.mock import Mock
from satsuma.operator_service import OperatorController,read_exact
from satsuma.dashboard_api_client import ReaderClient
from satsuma.store import Store
from test_deepseek_secure_workflow import proposal,gpg_key,trusted


def test_real_operator_socket_signed_lifecycle_and_unauthorized_refusal(tmp_path,trusted):
    sign,active=trusted;path=tmp_path/'operator.sock';ready=threading.Event();stop=threading.Event();errors=[]
    uid=os.getuid();session='isolated-session';directory=tmp_path/'store'
    def serve():
        store=Store(directory,test=True);server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            auth=Mock();auth.validate_session.return_value=True
            controller=OperatorController(store,auth=auth,config={'deepseek_enabled':True,'rule_adapter_enabled':True})
            controller.owners[session]=uid
            server.bind(str(path));server.listen();server.settimeout(.1);ready.set()
            while not stop.is_set():
                try:conn,_=server.accept()
                except socket.timeout:continue
                with conn:
                    conn.settimeout(10)
                    _,peer_uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    size=struct.unpack('>I',read_exact(conn,4))[0]
                    assert size<=65536
                    request=json.loads(read_exact(conn,size))
                    try:response={'result':controller.dispatch(peer_uid,request['method'],request.get('params') or {})}
                    except Exception:response={'error':'operator_request_refused'}
                    data=json.dumps(response).encode();conn.sendall(struct.pack('>I',len(data))+data)
        except Exception as exc:errors.append(type(exc).__name__);ready.set()
        finally:server.close();store.close()
    worker=threading.Thread(target=serve,daemon=True);worker.start();assert ready.wait(5)
    client=ReaderClient(str(path),timeout=15);package=proposal('SATSUMA-AI-SOCKET-001');rid=package['rule_id']
    def call(method,**params):return client.call(method,token=session,request_id=uuid.uuid4().hex,**params)
    try:
        try:client.call('deepseek_submit',token='unauthorized',request_id=uuid.uuid4().hex,package=package)
        except RuntimeError:pass
        else:raise AssertionError('unauthorized controller request accepted')
        assert call('deepseek_list')['items']==[]
        ident=uuid.uuid4().hex
        first=client.call('deepseek_submit',token=session,request_id=ident,package=package)
        assert first['queued'] and first==client.call('deepseek_submit',token=session,request_id=ident,package=package)
        approved=call('deepseek_approve',rule_id=rid)
        assert approved['approved'] and not approved['activated']
        payload=call('deepseek_export',rule_id=rid)['signing_payload']
        assert json.loads(payload)['approval']['operator_uid']==uid
        assert call('deepseek_verify_signature',rule_id=rid,signature=sign(payload.encode()))['valid']
        assert call('deepseek_activate',rule_id=rid,confirmed=True)['loader_verified']
        state=call('deepseek_activation_status',rule_id=rid)
        assert state['installed_integrity_valid'] and not state['runtime_loaded']
        assert not state['intervention_executed']
    finally:
        stop.set();worker.join(5)
    assert not errors and not worker.is_alive()
