"""The system resolver must be one Satsuma lets DNS reach (field log 2026-10-25).

Sistem çözücüsü, Satsuma'nın DNS'e izin verdiği adreslerden biri olmalı.
"""
import pytest

from satsuma.self_health import dns_resolver_alignment, resolv_conf_nameservers


def test_parser_reads_only_nameserver_lines():
    text = '# generated\nsearch lan\nnameserver 195.175.39.39\nnameserver fe80::1%wlp2s0\nnameserver bogus\n'
    assert resolv_conf_nameservers(text) == ['195.175.39.39', 'fe80::1']


def test_field_case_is_reported_with_both_sides():
    result = dns_resolver_alignment({'upstream': '192.168.1.1'}, [], 'nameserver 195.175.39.39\n')
    assert result['ok'] is False and result['state'] == 'MISMATCH'
    assert result['system_resolvers'] == ['195.175.39.39'] and result['satsuma_resolvers'] == ['192.168.1.1']
    assert result['not_allowed'] == ['195.175.39.39']


@pytest.mark.parametrize('policy,expected,text,state', [
    ({'upstream': '195.175.39.39'}, [], 'nameserver 195.175.39.39\n', 'ALIGNED'),
    ({'upstream': '192.168.1.1'}, ['208.67.222.222'], 'nameserver 208.67.222.222\n', 'ALIGNED'),
    ({'upstream': '192.168.1.1'}, [], 'nameserver 127.0.0.1\n', 'ALIGNED'),
    ({}, [], 'nameserver 1.1.1.1\n', 'SATSUMA_DNS_NOT_CONFIGURED'),
    ({'upstream': '192.168.1.1'}, [], '# empty\n', 'NO_SYSTEM_RESOLVER'),
])
def test_states(policy, expected, text, state):
    assert dns_resolver_alignment(policy, expected, text)['state'] == state
