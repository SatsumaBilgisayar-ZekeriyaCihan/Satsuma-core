"""Deep engine must cross a privilege/process boundary without action IPC."""
import json
import os
import socket
import tempfile
from pathlib import Path
from satsuma_engine.process_ipc import DeepProcessClient, _compact_event, _credentials

ROOT=Path(__file__).resolve().parents[1]

def test_compact_drops_secrets():
    result = _compact_event({'id':'x','pid':12,'env':'secret','token':'no', 'cmd':'x'*900})
    assert 'env' not in result and 'token' not in result
    assert len(result['cmd']) == 512


def test_missing_id_rejected():
    assert _compact_event({'pid':10}) is None


def test_ipc_sends_and_filters_untrusted_result():
    with tempfile.TemporaryDirectory() as tmp:
        event=str(Path(tmp)/'events.sock')
        result=str(Path(tmp)/'results.sock')
        server=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        server.bind(event)
        client=DeepProcessClient(event_socket=event, result_socket=result, expected_uid=os.geteuid())
        try:
            assert client.submit({'id':'e1','pid':3,'env':'DO_NOT_FORWARD'})
            data,_=server.recvfrom(8192)
            assert json.loads(data)=={'id':'e1','pid':3}
            server.sendto(json.dumps({'authorization':'none','evidence_type':'deep_engine_observation','finding_id':'abc'}).encode(),result)
            assert client.drain()[0]['finding_id']=='abc'
            server.sendto(json.dumps({'authorization':'kill','evidence_type':'deep_engine_observation','finding_id':'abc'}).encode(),result)
            assert client.drain()==[]
            assert client.health()['invalid_results']==1
        finally:
            client.close(); server.close()


def test_no_server_is_drop_not_block():
    with tempfile.TemporaryDirectory() as tmp:
        client=DeepProcessClient(event_socket=str(Path(tmp)/'absent.sock'), result_socket=str(Path(tmp)/'results.sock'),expected_uid=os.geteuid())
        try:
            assert not client.submit({'id':'x'})
            assert client.health()['input_dropped']==1
        finally: client.close()


def test_service_is_rootless_and_not_action_capable():
    unit=(ROOT/'systemd/satsuma-deep-engine.service').read_text()
    assert 'User=satsuma-engine' in unit
    assert 'CapabilityBoundingSet=\n' in unit
    assert 'RestrictAddressFamilies=AF_UNIX' in unit
    source=(ROOT/'run_satsuma_teams.py').read_text()
    assert 'DeepProcessClient()' in source
    assert 'DeepEvidenceLane.from_bundled_rules().start()' not in source


def test_findings_independent_of_network_startup():
    unit=(ROOT/'systemd/satsuma-core-finding.service').read_text()
    assert 'Requires=satsuma-network.service' not in unit
    teams=(ROOT/'systemd/satsuma-teams.service').read_text()
    assert 'Requires=satsuma-core-finding.service' not in teams
