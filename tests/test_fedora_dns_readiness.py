"""DNS path and startup regressions; fixtures never change the host network.

DNS yolu ve başlangıç regresyonları; ana makinenin ağı değiştirilmez.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import struct
import pytest
from satsuma import dns_readiness as wire, dnsmasq_control as dns
from installer import network_modes_setup as setup


class Store:
    def __init__(self):self.data={'dns_policy':{'enabled':True},'satsuma_dns_state':{'enabled':True}}
    def get(self,key,default=None):return self.data.get(key,default)
    def set(self,key,value):self.data[key]=value


def reply(ident=123, flags=0x8180, address=b'\x5d\xb8\xd8\x22'):
    return (struct.pack('!6H',ident,flags,1,1,0,0)+wire.QUESTION+
            b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+address)


def test_useful_answer_required_not_just_root_ns_header():
    assert wire.validate_reply(reply(),123)==['93.184.216.34']
    with pytest.raises(RuntimeError):wire.validate_reply(struct.pack('!6H',123,0x8180,1,0,0,0)+wire.QUESTION,123)


@pytest.mark.parametrize('packet',[reply(ident=999),reply(flags=0x8182),reply(flags=0x8380),reply(address=b'\0'*4),reply()[:-1],b'bad'])
def test_bad_or_filtered_reply_is_not_readiness(packet):
    with pytest.raises(RuntimeError):wire.validate_reply(packet,123)


def test_system_probe_uses_configured_port_53_udp_and_tcp(tmp_path,monkeypatch):
    resolv=tmp_path/'resolv.conf';resolv.write_text('nameserver 208.67.220.220\n')
    query=Mock(return_value=['93.184.216.34']);monkeypatch.setattr(wire,'query',query)
    report=wire.probe_system(resolv_path=resolv)
    assert report['system_ready'] and [call.args for call in query.call_args_list]==[('208.67.220.220',53)]*2
    assert [call.kwargs['transport'] for call in query.call_args_list]==['udp','tcp']


def test_local_success_system_failure_cannot_be_green(monkeypatch):
    store=Store();monkeypatch.setattr(wire,'probe_system',Mock(side_effect=TimeoutError('system DNS timeout')))
    with pytest.raises(TimeoutError):dns.record_readiness(store)
    health=store.get('dns_filter_health')
    assert health['local_ready'] and not health['system_ready'] and not health['ok'] and health['status']=='FAILED'


def test_local_only_is_explicitly_pending_system_check():
    store=Store();store.data.pop('satsuma_dns_state')
    result=dns.record_readiness(store)
    assert result['status']=='LOCAL_READY' and not result['ok'] and not result['system_ready']


@pytest.mark.parametrize('fail_local',[True,False])
def test_startup_failure_preserves_policy_and_existing_redirect(monkeypatch,fail_local):
    store=Store();modes=Mock()
    monkeypatch.setattr(dns,'probe',Mock(side_effect=RuntimeError('timeout') if fail_local else None))
    monkeypatch.setattr(wire,'probe_system',Mock(side_effect=RuntimeError('system timeout')))
    with pytest.raises(RuntimeError):setup.configure(store,modes)
    calls=[call.args for call in modes.apply.call_args_list]
    assert ('satsuma_dns',False) not in calls
    assert store.get('dns_policy')['enabled'] and store.get('satsuma_dns_state')['enabled']
    assert store.get('dns_filter_health')['status']=='FAILED'


def test_bounded_timeout_is_safe_and_does_not_apply_any_redirect(monkeypatch,tmp_path):
    resolv=tmp_path/'resolv.conf';resolv.write_text('nameserver 208.67.220.220\n')
    query=Mock(side_effect=TimeoutError('fixture timeout'));monkeypatch.setattr(wire,'query',query)
    with pytest.raises(RuntimeError,match='System DNS readiness failed'):wire.probe_system(timeout=0,resolv_path=resolv)
    query.assert_not_called()


def test_posttrans_starts_consumers_before_dns_and_retains_failed_status():
    text=(Path(__file__).parents[1]/'packaging/satsuma-core.spec').read_text().split('%posttrans\n',1)[1].split('%postun\n',1)[0]
    consumers='systemctl start satsuma-network.service satsuma-suricata-ips.service satsuma-app-control.service || exit 1'
    assert text.index(consumers)<text.index('/installer/dns_setup.py')
    assert '/installer/dns_setup.py || dns_setup_failed=1' in text
    assert 'if [ "$dns_setup_failed" -ne 0 ]; then' in text


def test_dns_is_not_held_by_app_control_and_does_not_fail_the_package():
    """2.2.26: queue 201 ran before the DNS redirect and held every unapproved resolver call."""
    from satsuma.app_firewall import nft_script
    script = nft_script(True)
    assert script.index('th dport 53 accept') < script.index('queue num')
    text=(Path(__file__).parents[1]/'packaging/satsuma-core.spec').read_text().split('%posttrans\n',1)[1].split('%postun\n',1)[0]
    block=text.split('if [ "$dns_setup_failed" -ne 0 ]; then',1)[1].split(' fi',1)[0]
    assert 'exit 1' not in block
