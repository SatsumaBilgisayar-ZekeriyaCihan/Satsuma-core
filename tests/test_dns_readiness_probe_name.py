"""The DNS filter never blocks its own readiness probe name (2.2.19).

DNS filtresi kendi hazırlık testi adını hiçbir zaman engellemez (2.2.19).
"""
from satsuma import dnsmasq_control as dns
from satsuma.dns_readiness import NAME


def test_probe_name_is_answered_even_when_a_list_blocks_it():
    rules = dns.render({'upstream': '208.67.222.222'}, {NAME, 'malware.example.net'}, [])
    assert f'address=/{NAME}/#' not in rules
    assert f'server=/{NAME}/208.67.222.222' in rules
    assert 'address=/malware.example.net/#' in rules  # other blocks stay
