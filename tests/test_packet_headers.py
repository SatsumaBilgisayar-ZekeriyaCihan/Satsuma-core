import ipaddress
import struct
import pytest
from satsuma.app_firewall import parse_packet


def ipv6(next_header,body):
    header=bytearray(40);header[0]=0x60;header[4:6]=len(body).to_bytes(2,'big');header[6]=next_header
    header[8:24]=ipaddress.ip_address('2001:db8::1').packed
    header[24:40]=ipaddress.ip_address('2001:db8::2').packed
    return bytes(header)+body


@pytest.mark.parametrize('kind',[0,43,60])
def test_supported_ipv6_extension_keeps_exact_udp_tuple(kind):
    flow=parse_packet(ipv6(kind,bytes([17,0])+bytes(6)+struct.pack('!HHHH',1234,53,8,0)))
    assert flow==(6,17,'2001:db8::1',1234,'2001:db8::2',53)


@pytest.mark.parametrize('body',[
    ipv6(44,bytes(16)),
    ipv6(50,bytes(16)),
    ipv6(0,bytes([17,10])+bytes(6)),
    ipv6(0,(bytes([0,0])+bytes(6))*9+bytes(8)),
])
def test_fragmented_encrypted_or_unbounded_ipv6_is_explicitly_rejected(body):
    with pytest.raises(ValueError):parse_packet(body)
