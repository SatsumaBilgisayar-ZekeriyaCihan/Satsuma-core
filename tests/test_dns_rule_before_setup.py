"""2.2.36: the OpenSnitch rule for the DNS filter exists before DNS setup probes dnsmasq.

2.2.36: OpenSnitch'in DNS filtresi kuralı, DNS kurulumu dnsmasq'ı sınamadan önce vardır.

Field 2026-11-04: on an upgrade the operator service wrote the new rule only after the
installer's DNS readiness probe had already timed out against the old one.
Saha 2026-11-04: yükseltmede yeni kuralı operatör servisi, kurulumun DNS hazır olma
sınaması eski kuralla zaman aşımına uğradıktan sonra yazıyordu.
"""
import json
from unittest.mock import Mock

from installer import dns_setup
from satsuma import opensnitch


def test_ensure_dns_rule_writes_the_unified_path_rule(tmp_path):
    written = opensnitch.ensure_dns_rule(directory=tmp_path, uid=990)
    assert written == ['satsuma-dns-filter.json']
    rule = json.loads((tmp_path / 'satsuma-dns-filter.json').read_text())
    path = [item for item in rule['operator']['list'] if item['operand'] == 'process.path'][0]
    assert path['type'] == 'regexp' and path['data'] == r'^/usr/s?bin/dnsmasq$'
    assert rule['action'] == 'allow'


def test_ensure_dns_rule_replaces_the_old_sbin_only_rule(tmp_path):
    opensnitch.sync_rules({'dns-filter': opensnitch.rule(
        'dns-filter', 'old', [('process.path', '/usr/sbin/dnsmasq'), ('user.id', 990), ('dest.port', 53)])}, tmp_path)
    opensnitch.ensure_dns_rule(directory=tmp_path, uid=990)
    rule = json.loads((tmp_path / 'satsuma-dns-filter.json').read_text())
    assert [i['data'] for i in rule['operator']['list'] if i['operand'] == 'process.path'] == [r'^/usr/s?bin/dnsmasq$']


def test_ensure_dns_rule_leaves_other_satsuma_and_user_rules_alone(tmp_path):
    keep = tmp_path / 'satsuma-wireguard-51820.json'
    keep.write_text('{"name":"satsuma-wireguard-51820"}')
    user = tmp_path / 'my-own-rule.json'
    user.write_text('{"name":"my-own-rule"}')
    opensnitch.ensure_dns_rule(directory=tmp_path, uid=990)
    assert keep.exists() and user.exists()


def test_ensure_dns_rule_without_the_dns_user_writes_nothing(tmp_path):
    assert opensnitch.ensure_dns_rule(directory=tmp_path, uid=None) == []
    assert list(tmp_path.iterdir()) == []


def test_ensure_dns_rule_without_opensnitch_directory_is_a_no_op(tmp_path):
    assert opensnitch.ensure_dns_rule(directory=tmp_path / 'absent', uid=990) == []


def test_dns_setup_writes_the_rule_before_refreshing_the_filter():
    order = []
    store = Mock()
    store.get.return_value = {'enabled': True, 'upstream': '208.67.222.222'}
    refresh = Mock(side_effect=lambda s: order.append('refresh') or {'ok': True})
    dns_setup.configure(store, resolver=lambda: '208.67.222.222', refresh=refresh,
                        rule=lambda: order.append('rule'))
    assert order == ['rule', 'refresh']


def test_dns_setup_still_refreshes_when_the_rule_cannot_be_written():
    store = Mock()
    store.get.return_value = {'enabled': True, 'upstream': '208.67.222.222'}
    refresh = Mock(return_value={'ok': True})

    def broken():
        raise OSError('read-only rules directory')

    assert dns_setup.configure(store, resolver=lambda: '208.67.222.222', refresh=refresh, rule=broken) == {'ok': True}
    refresh.assert_called_once()
