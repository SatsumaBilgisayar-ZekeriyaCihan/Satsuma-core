import errno
import socket
from types import SimpleNamespace as NS

import pytest

from satsuma import app_firewall as firewall
from satsuma import nfqueue


def queue_fixture(monkeypatch, reads):
    queue = object.__new__(nfqueue.Queue)
    queue.fd = 12
    queue.handle = None
    queue.receive_overruns = 0
    events = []
    queue.prepare = lambda: events.append('prepare')
    queue.finish = lambda: events.append('finish')
    queue.lib = NS(nfq_handle_packet=lambda *args: events.append('packet') or 0)
    pending = iter(reads)
    def read(*args):
        item = next(pending)
        if isinstance(item, Exception):
            raise item
        return item
    monkeypatch.setattr(nfqueue.os, 'read', read)
    monkeypatch.setattr(nfqueue.select, 'select', lambda *args: ([12], [], []))
    return queue, events


def test_netlink_overrun_does_not_restart_firewall_and_next_poll_resumes(monkeypatch):
    queue, events = queue_fixture(monkeypatch, [OSError(errno.ENOBUFS, 'overrun'), b'packet', OSError(errno.ENOBUFS, 'overrun')])
    queue.poll(0)
    assert events == []
    queue.poll(0)
    assert events == ['prepare', 'packet', 'finish']
    assert queue.receive_overruns == 2


def test_non_overrun_errors_remain_visible(monkeypatch):
    queue, events = queue_fixture(monkeypatch, [OSError(errno.EBADF, 'closed')])
    with pytest.raises(OSError) as error:
        queue.poll(0)
    assert error.value.errno == errno.EBADF
    assert events == []


def connection(local, remote, pid=123):
    return NS(family=socket.AF_INET6, type=socket.SOCK_STREAM, pid=pid,
              laddr=NS(ip=local, port=4000), raddr=NS(ip=remote, port=443))


def test_dual_stack_ipv4_socket_is_attributed_without_granting_other_processes(monkeypatch):
    owners = firewall.SocketOwners([connection('::ffff:192.0.2.2', '::ffff:198.51.100.2')])
    monkeypatch.setattr(firewall, 'identity', lambda pid: {'pid': pid})
    assert owners.resolve((4, 6, '192.0.2.2', 4000, '198.51.100.2', 443)) == {'pid': 123}
    with pytest.raises(ValueError, match='ambiguous'):
        owners.resolve((4, 6, '192.0.2.2', 4000, '198.51.100.3', 443))


def test_mapped_ipv4_and_native_ipv4_ownership_conflict_is_denied(monkeypatch):
    native = NS(family=socket.AF_INET, type=socket.SOCK_STREAM, pid=456,
                laddr=NS(ip='192.0.2.2', port=4000), raddr=NS(ip='198.51.100.2', port=443))
    owners = firewall.SocketOwners([connection('::ffff:192.0.2.2', '::ffff:198.51.100.2'), native])
    monkeypatch.setattr(firewall, 'identity', lambda pid: pytest.fail('ambiguous owner must be rejected'))
    with pytest.raises(ValueError, match='ambiguous'):
        owners.resolve((4, 6, '192.0.2.2', 4000, '198.51.100.2', 443))


def test_native_ipv6_stays_separate(monkeypatch):
    owners = firewall.SocketOwners([connection('2001:db8::1', '2001:db8::2')])
    monkeypatch.setattr(firewall, 'identity', lambda pid: {'pid': pid})
    assert owners.resolve((6, 6, '2001:db8::1', 4000, '2001:db8::2', 443)) == {'pid': 123}


def _ipv6_available():
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ipv6_available(), reason='host kernel has no IPv6 sockets')
def test_real_linux_dual_stack_connection_has_a_resolvable_owner(monkeypatch):
    import os
    import psutil
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
            client.connect(('::ffff:127.0.0.1', port))
            peer, _ = listener.accept()
            with peer:
                owners = firewall.SocketOwners(psutil.net_connections(kind='inet'))
                monkeypatch.setattr(firewall, 'identity', lambda pid: {'pid': pid})
                flow = (4, 6, '127.0.0.1', client.getsockname()[1], '127.0.0.1', port)
                assert owners.resolve(flow) == {'pid': os.getpid()}
