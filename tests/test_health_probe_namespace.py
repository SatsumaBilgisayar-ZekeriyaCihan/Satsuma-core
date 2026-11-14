import importlib.util
from pathlib import Path
import pytest

path=Path(__file__).parents[1]/'integrations/network_health_probe.py'
spec=importlib.util.spec_from_file_location('health_probe_under_test',path)
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)


@pytest.mark.parametrize('reference',[None,'','invalid','net:[12]'])
def test_probe_never_mutates_original_namespace(reference,monkeypatch):
    monkeypatch.setattr('os.readlink',lambda path:'net:[12]')
    monkeypatch.setattr(probe,'run',lambda *a,**k:pytest.fail('must not execute nft/ip in parent namespace'))
    with pytest.raises(RuntimeError):probe.probe(reference)


def test_probe_checks_own_namespace_without_reading_pid1(monkeypatch):
    reads=[]
    def link(path):
        reads.append(path)
        if path!='/proc/self/ns/net':raise PermissionError('ptrace denied')
        return 'net:[13]'
    monkeypatch.setattr('os.readlink',link)
    def stop(args,*a):raise RuntimeError('isolated namespace reached')
    monkeypatch.setattr(probe,'run',stop)
    with pytest.raises(RuntimeError,match='isolated namespace reached'):probe.probe('net:[12]')
    assert reads==['/proc/self/ns/net']


def test_health_command_retains_final_error_instead_of_traceback_prefix():
    from satsuma.self_health import command
    import sys
    with pytest.raises(RuntimeError,match='actual final cause'):
        command([sys.executable,'-c',"import sys;sys.stderr.write('traceback '*100+'actual final cause');sys.exit(1)"])


@pytest.mark.parametrize('status,code',[('PASSED',0),('DEGRADED',1),('FAILED',1),('NOT_RUN',1)])
def test_report_exit_status_never_claims_failed_or_pending_check_passed(monkeypatch,status,code,capsys):
    from satsuma import self_health as health
    monkeypatch.setattr('sys.argv',['self_health','--report'])
    monkeypatch.setattr(health,'read_report',lambda:{'status':status})
    assert health.main()==code
    assert status in capsys.readouterr().out
