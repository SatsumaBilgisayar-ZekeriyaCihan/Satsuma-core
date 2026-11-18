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


# 2.2.38 (owner, 2026-11-18): "deep engine bağlantısı inactive kalıyor".
def test_results_socket_is_in_the_teams_runtime_folder_not_the_engines():
    from satsuma_engine import process_ipc
    assert process_ipc.RESULT_SOCKET == '/run/satsuma-deep-results/results.sock'
    teams=(ROOT/'systemd/satsuma-teams.service').read_text()
    assert 'RuntimeDirectory=satsuma-flow satsuma-deep-results' in teams
    assert 'ProtectSystem=strict' in teams


def test_a_restarted_teams_service_reconnects_over_its_own_stale_socket():
    with tempfile.TemporaryDirectory() as tmp:
        event=str(Path(tmp)/'events.sock'); result=str(Path(tmp)/'results.sock')
        server=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); server.bind(event)
        first=DeepProcessClient(event_socket=event, result_socket=result, expected_uid=os.geteuid())
        first.in_sock.close(); first.out_sock.close()   # crash: no close(), socket file stays
        assert Path(result).exists()
        second=DeepProcessClient(event_socket=event, result_socket=result, expected_uid=os.geteuid())
        try:
            assert second.health()['running'] is True
            server.sendto(json.dumps({'authorization':'none','evidence_type':'deep_engine_observation','finding_id':'f2'}).encode(),result)
            assert second.drain()[0]['finding_id']=='f2'
        finally:
            second.close(); server.close()


def test_a_foreign_file_at_the_results_path_is_never_removed():
    import pytest
    with tempfile.TemporaryDirectory() as tmp:
        result=Path(tmp)/'results.sock'; result.write_text('not a socket')
        with pytest.raises(RuntimeError, match='not our socket'):
            DeepProcessClient(event_socket=str(Path(tmp)/'e.sock'), result_socket=str(result), expected_uid=os.geteuid())
        assert result.read_text()=='not a socket'


def test_integrity_check_runs_as_root_before_the_rootless_service():
    unit=(ROOT/'systemd/satsuma-deep-engine.service').read_text()
    assert 'ExecStartPre=+/usr/bin/python3 -I -B /opt/satsuma-core/run_deep_engine.py --verify' in unit
    assert 'User=satsuma-engine' in unit
    entry=(ROOT/'run_deep_engine.py').read_text()
    main=entry.split('def main():',1)[1]
    assert 'verify' not in main.split('if __name__',1)[0]   # the rootless part never reads the root-only key


def test_verify_mode_refuses_to_run_without_root():
    import subprocess, sys, pwd
    try:nobody=pwd.getpwnam('nobody').pw_uid
    except KeyError:
        import pytest;pytest.skip('no nobody user')
    if os.geteuid()!=0:
        import pytest;pytest.skip('needs root to drop to nobody')
    done=subprocess.run([sys.executable,'-I','-B',str(ROOT/'run_deep_engine.py'),'--verify'],
                        capture_output=True,text=True,preexec_fn=lambda:os.setuid(nobody))
    assert done.returncode!=0 and 'needs root' in done.stderr


def test_teams_retries_the_deep_engine_link():
    source=(ROOT/'run_satsuma_teams.py').read_text()
    assert 'def connect_deep_lane' in source
    assert 'deep_lane is None and time.monotonic() - deep_lane_tried >= 30' in source
