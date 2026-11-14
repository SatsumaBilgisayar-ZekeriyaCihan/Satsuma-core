import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import pytest

spec=importlib.util.spec_from_file_location('direction_guard',Path(__file__).parents[1]/'integrations/satsuma_guard.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)


@pytest.mark.parametrize('src,dst,family',[
    ('45.33.32.10','192.168.1.3','ipv4'),
    ('2606:4700:4700::1111','fd00::2','ipv6'),
    ('2606:4700:4700:0:0:0:0:1111','FD00:0:0:0:0:0:0:2','ipv6'),
])
def test_complete_original_tuple_is_required_for_each_family(monkeypatch,src,dst,family):
    import ipaddress
    s,d=str(ipaddress.ip_address(src)),str(ipaddress.ip_address(dst))
    alert={'protocol':'tcp','source_ip':src,'dest_ip':dst,'source_port':4000,'dest_port':443}
    original=f'tcp 6 100 ESTABLISHED src={s} dst={d} sport=4000 dport=443 src={d} dst={s} sport=443 dport=4000 [ASSURED] mark=0 use=1'
    calls=[]
    def command(args):calls.append(args);return NS(returncode=0,stdout=original)
    monkeypatch.setattr(guard,'command',command)
    assert guard.inbound_connection(alert)
    assert family in calls[0]
    assert not guard.inbound_connection({**alert,'source_ip':dst,'dest_ip':src,'source_port':443,'dest_port':4000})
    assert not guard.inbound_connection({**alert,'source_port':4001})


def test_mixed_address_families_never_query_conntrack(monkeypatch):
    monkeypatch.setattr(guard,'command',lambda *a:pytest.fail('invalid family tuple'))
    assert not guard.inbound_connection({'protocol':'tcp','source_ip':'45.33.32.10',
        'dest_ip':'fd00::2','source_port':4000,'dest_port':443})


ASSURED='tcp 6 100 ESTABLISHED src=45.33.32.10 dst=192.168.1.3 sport=4000 dport=443 src=192.168.1.3 dst=45.33.32.10 sport=443 dport=4000 [ASSURED] mark=0 use=1'
SYN_ONLY='tcp 6 118 SYN_SENT src=45.33.32.10 dst=192.168.1.3 sport=4000 dport=443 [UNREPLIED] src=192.168.1.3 dst=45.33.32.10 sport=443 dport=4000 mark=0 use=1'
ALERT={'protocol':'tcp','source_ip':'45.33.32.10','dest_ip':'192.168.1.3','source_port':4000,'dest_port':443}


def test_k2_forged_udp_is_never_an_incoming_connection(monkeypatch):
    # One forged UDP packet creates exactly this ORIGINAL entry; it must not count.
    udp='udp 17 29 src=45.33.32.10 dst=192.168.1.3 sport=4000 dport=443 src=192.168.1.3 dst=45.33.32.10 sport=443 dport=4000 mark=0 use=1'
    monkeypatch.setattr(guard,'command',lambda args:NS(returncode=0,stdout=udp))
    assert not guard.inbound_connection({**ALERT,'protocol':'udp'})


def test_k2_unfinished_handshake_is_not_enough(monkeypatch):
    monkeypatch.setattr(guard,'command',lambda args:NS(returncode=0,stdout=SYN_ONLY))
    assert not guard.inbound_connection(ALERT)
    monkeypatch.setattr(guard,'command',lambda args:NS(returncode=0,stdout=ASSURED))
    assert guard.inbound_connection(ALERT)


def test_k2_reply_on_a_connection_this_host_completed_is_verified(monkeypatch):
    opened_here='tcp 6 100 ESTABLISHED src=192.168.1.3 dst=45.33.32.10 sport=50000 dport=443 src=45.33.32.10 dst=192.168.1.3 sport=443 dport=50000 [ASSURED] mark=0 use=1'
    calls=[]
    monkeypatch.setattr(guard,'command',lambda args:calls.append(args) or NS(returncode=0,stdout=opened_here))
    reply={'protocol':'tcp','source_ip':'45.33.32.10','dest_ip':'192.168.1.3','source_port':443,'dest_port':50000}
    assert guard.assured_reply_connection(reply)
    assert calls[0][calls[0].index('-s')+1]=='192.168.1.3'  # queried in the direction this host opened
    assert not guard.assured_reply_connection({**reply,'protocol':'udp'})
