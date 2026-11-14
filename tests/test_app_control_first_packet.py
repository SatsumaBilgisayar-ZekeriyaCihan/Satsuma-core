"""App Control queues only a connection's first packet; WireGuard passes (2.2.30).

Field 2026-11-04: App Control lagged and stalled the internet; a WireGuard
profile could not connect under it.

App Control yalnızca bağlantının ilk paketini kuyruğa alır; WireGuard geçer.
"""
from satsuma import app_firewall, wireguard


def lines():
    return [l.strip() for l in app_firewall.nft_script(True).splitlines()]


def test_established_traffic_passes_before_the_queue():
    rules = lines()
    queue = rules.index('meta l4proto { tcp, udp } queue num 201')
    assert rules.index('ct state established,related accept') < queue


def test_wireguard_outer_packets_pass_by_satsuma_mark_only():
    rules = lines()
    assert app_firewall.WG_MARK == wireguard.FWMARK
    assert rules.index(f'meta mark {wireguard.FWMARK} accept') < rules.index('meta l4proto { tcp, udp } queue num 201')
    assert 'counter drop' in rules
