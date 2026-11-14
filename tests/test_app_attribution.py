"""App Control re-takes its socket snapshot when a new connection's owner is missing.

The first packet of a connection can be queued just after the batch's snapshot was
taken. It used to be denied as unattributed and only passed after TCP retried.

App Control, yeni bir bağlantının sahibi eksikse soket anlık görüntüsünü yeniden alır.
Bağlantının ilk paketi, yığının görüntüsünden hemen sonra kuyruğa girebilir. Eskiden
sahipsiz diye reddedilir ve ancak TCP yeniden deneyince geçerdi.
"""
import socket
from types import SimpleNamespace as NS

import pytest

from satsuma import app_firewall as firewall

FLOW = (4, 6, '192.0.2.10', 4000, '198.51.100.7', 443)
APP = {'key': 'k' * 64, 'application_key': 'a' * 64, 'pid': 123, 'executable': '/usr/bin/curl'}


def connection(pid=123, port=4000):
    return NS(family=socket.AF_INET, type=socket.SOCK_STREAM, pid=pid,
              laddr=NS(ip=FLOW[2], port=port), raddr=NS(ip=FLOW[4], port=FLOW[5]))


@pytest.fixture(autouse=True)
def fixed_identity(monkeypatch):
    monkeypatch.setattr(firewall, 'identity', lambda pid: APP)


def snapshots(*batches):
    """A scan() that returns one prepared snapshot per call, then repeats the last."""
    calls = []

    def scan():
        calls.append(1)
        index = min(len(calls), len(batches)) - 1
        return firewall.SocketOwners(batches[index])
    scan.calls = calls
    return scan


def test_a_socket_that_is_in_the_snapshot_needs_no_second_scan():
    scan = snapshots([connection()])
    attribution = firewall.Attribution(scan)
    attribution.begin()
    assert attribution.resolve(FLOW) == APP and len(scan.calls) == 1


def test_a_socket_opened_after_the_snapshot_is_found_by_a_new_scan():
    scan = snapshots([], [connection()])
    attribution = firewall.Attribution(scan)
    attribution.begin()
    assert attribution.resolve(FLOW) == APP
    assert len(scan.calls) == 2 and attribution.left == 2


def test_a_missing_owner_still_fails_closed_after_the_budget_is_spent():
    scan = snapshots([])
    attribution = firewall.Attribution(scan, rescans=3)
    attribution.begin()
    for _ in range(5):
        with pytest.raises(firewall.OwnerMissing):
            attribution.resolve(FLOW)
    assert len(scan.calls) == 1 + 3          # one per batch plus at most three re-scans


def test_an_ambiguous_owner_is_never_rescanned():
    scan = snapshots([connection(), connection(pid=999)], [connection()])
    attribution = firewall.Attribution(scan)
    attribution.begin()
    with pytest.raises(ValueError, match='ambiguous') as caught:
        attribution.resolve(FLOW)
    assert not isinstance(caught.value, firewall.OwnerMissing) and len(scan.calls) == 1


def test_each_batch_gets_a_fresh_budget_and_no_snapshot_outlives_it():
    scan = snapshots([])
    attribution = firewall.Attribution(scan, rescans=1)
    attribution.begin()
    with pytest.raises(firewall.OwnerMissing):
        attribution.resolve(FLOW)
    assert attribution.left == 0
    attribution.begin()
    assert attribution.left == 1
    attribution.end()
    with pytest.raises(ValueError, match='unavailable'):
        attribution.resolve(FLOW)


def test_a_failing_rescan_denies_the_packet_instead_of_guessing():
    state = {'n': 0}

    def scan():
        state['n'] += 1
        if state['n'] > 1:
            raise OSError('cannot read sockets')
        return firewall.SocketOwners([])
    attribution = firewall.Attribution(scan)
    attribution.begin()
    with pytest.raises(OSError):
        attribution.resolve(FLOW)


def test_socket_owners_tell_missing_from_ambiguous():
    with pytest.raises(firewall.OwnerMissing):
        firewall.SocketOwners([]).resolve(FLOW)
    with pytest.raises(ValueError, match='ambiguous'):
        firewall.SocketOwners([connection(), connection(pid=999)]).resolve(FLOW)
