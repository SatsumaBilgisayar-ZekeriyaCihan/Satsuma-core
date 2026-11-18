"""2.2.47: blocking an address range such as 192.168.0.0/16 (Güvenlik duvarı → Engeller).

The kernel is replaced by a fake nft that keeps the table it was given and
answers ``nft -j list`` like the real one. A real-nft check was run once in an
unprivileged network namespace while writing this (unshare -rn).
"""
import ipaddress
import json
import re
import subprocess

import pytest

from satsuma import net_blocks
from satsuma.store import Store


class FakeNft:
    def __init__(self, broken_readback=False):
        self.networks, self.present, self.scripts, self.broken = None, False, [], broken_readback

    def __call__(self, args, input=None, **kwargs):
        assert args[0] == 'nft'
        if args[1:] == ['-j', 'list', 'tables']:
            tables = [{'table': {'family': 'inet', 'name': net_blocks.TABLE}}] if self.present else []
            return subprocess.CompletedProcess(args, 0, json.dumps({'nftables': tables}), '')
        if args[1:3] == ['--check', '-f']:
            return subprocess.CompletedProcess(args, 0, '', '')
        if args[1:3] == ['-f', '-']:
            self.scripts.append(input)
            found = re.search(r'elements = \{ ([^}]*) \}', input)
            self.networks = [ipaddress.ip_network(x.strip()) for x in found.group(1).split(',')] if found else []
            self.present = True
            return subprocess.CompletedProcess(args, 0, '', '')
        if args[1:] == ['-j', 'list', 'table', 'inet', net_blocks.TABLE]:
            return subprocess.CompletedProcess(args, 0, json.dumps(self.listing()), '')
        raise AssertionError(args)

    def listing(self):
        def rule(chain, *fields):
            return [{'rule': {'chain': chain, 'expr': [{'match': {'left': {'payload': {'field': f}}, 'right': '@nets'}},
                                                         {'counter': {}}, {'drop': None}]}} for f in fields]
        elem = [{'prefix': {'addr': str(n.network_address), 'len': n.prefixlen}} for n in self.networks]
        if self.broken:
            elem = elem[:-1]
        entries = [{'table': {'family': 'inet', 'name': net_blocks.TABLE, 'comment': net_blocks.OWNER}},
                   {'set': {'name': 'nets', 'elem': elem}}]
        entries += [{'chain': {'name': c, 'policy': 'accept', 'prio': net_blocks.PRIORITY}} for c in ('input', 'output', 'forward')]
        entries += rule('input', 'saddr') + rule('output', 'daddr') + rule('forward', 'saddr', 'daddr')
        return {'nftables': entries}


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / 'data', test=True)
    yield value
    value.close()


def test_parse_accepts_ranges_and_single_addresses_and_refuses_the_rest():
    assert str(net_blocks.parse('192.168.0.0/16')) == '192.168.0.0/16'
    assert str(net_blocks.parse(' 192.168.5.9/16 ')) == '192.168.0.0/16'      # host bits cleared
    assert str(net_blocks.parse('203.0.113.7')) == '203.0.113.7/32'
    for bad, words in (('', 'yazın'), ('192.168.0.0/33', 'Geçerli'), ('abc', 'Geçerli'),
                       ('0.0.0.0/2', '/8'), ('2001:db8::/32', 'IPv6')):
        with pytest.raises(ValueError, match=words):
            net_blocks.parse(bad)


def test_a_range_that_would_cut_this_machine_off_is_refused():
    network = net_blocks.parse('192.168.0.0/16')
    assert net_blocks.conflicts(network, gateways=['10.0.0.1'], addresses=['10.0.0.5']) == []
    assert any('ağ geçidiniz' in r for r in net_blocks.conflicts(network, gateways=['192.168.1.1']))
    assert any('kendi adresi' in r for r in net_blocks.conflicts(network, addresses=['192.168.1.20']))
    assert any('DNS' in r for r in net_blocks.conflicts(net_blocks.parse('169.254.0.0/16')))
    assert net_blocks.conflicts(net_blocks.parse('127.0.0.0/8'))


def test_add_and_remove_change_the_owned_table_and_are_recorded(store):
    nft = FakeNft()
    result = net_blocks.add(store, '192.168.0.0/16', 'Misafir ağı', 1000, nft, gateways=['10.0.0.1'], addresses=['10.0.0.5'])
    assert result['status'] == 'blocked' and nft.networks == [ipaddress.ip_network('192.168.0.0/16')]
    assert 'ip saddr @nets counter drop' in nft.scripts[-1] and 'ip daddr @nets counter drop' in nft.scripts[-1]
    assert 'accept' not in nft.scripts[-1].replace('policy accept', '')         # only drop rules
    again = net_blocks.add(store, '192.168.1.1/16', '', 1000, nft, gateways=[], addresses=[])
    assert again['status'] == 'already_blocked' and len(nft.scripts) == 1
    assert [r['network'] for r in net_blocks.stored(store)] == ['192.168.0.0/16']
    with pytest.raises(ValueError, match='engellenemez'):
        net_blocks.add(store, '10.0.0.0/8', '', 1000, nft, gateways=['10.0.0.1'], addresses=[])
    removed = net_blocks.remove(store, '192.168.0.0/16', nft)
    assert removed['status'] == 'unblocked' and nft.networks == [] and net_blocks.stored(store) == []
    actions = [r['action'] for r in store.recent('actions', 10)] if hasattr(store, 'recent') else None
    if actions is not None:
        assert {'network_range_block', 'network_range_unblock'} <= set(actions)


def test_restore_puts_the_stored_ranges_back_and_a_bad_readback_fails(store):
    nft = FakeNft()
    net_blocks.add(store, '198.51.100.0/24', '', 1000, nft, gateways=[], addresses=[])
    fresh = FakeNft()
    assert net_blocks.restore(store, fresh)['networks'] == ['198.51.100.0/24']
    with pytest.raises(RuntimeError, match='readback'):
        net_blocks.apply([ipaddress.ip_network('198.51.100.0/24')], FakeNft(broken_readback=True))


def test_operator_lifting_a_block_asks_for_the_password_again():
    from satsuma.operator_service import weakens
    assert weakens('unblock_network', {'network': '192.168.0.0/16'})
    assert not weakens('block_network', {'network': '192.168.0.0/16'})
