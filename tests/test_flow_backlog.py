"""2.2.52: a busy or restarting rule engine no longer loses events.

Field 2026-11-19: "Akış bekçisi · Olay gönderilemedi" and "Toplayıcı olay
düşürdü" at the same second. Real Unix datagram sockets are used here.
"""
import json
import socket

from satsuma.flow import FlowSender


def receiver(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(str(path))
    sock.settimeout(0.005)
    return sock


def drain(sock):
    out = []
    while True:
        try:
            out.append(json.loads(sock.recv(70000))['n'])
        except (socket.timeout, BlockingIOError):
            return out


def test_a_full_receiver_queue_delays_events_in_order_instead_of_losing_them(tmp_path):
    path = tmp_path / 'flow.sock'
    sock = receiver(path)
    sender = FlowSender(path)
    total = 3000                       # far more than a Unix datagram queue holds
    assert all(sender.send({'n': n}) for n in range(total))
    assert sender.backlog and sender.dropped == 0 and sender.retried > 0
    got = drain(sock)
    while sender.backlog:
        sender.flush()
        got += drain(sock)
    assert got == list(range(total))
    sock.close()


def test_events_wait_while_the_receiver_restarts(tmp_path):
    path = tmp_path / 'flow.sock'
    sender = FlowSender(path)
    assert sender.send({'n': 0}) and sender.send({'n': 1})      # nobody listens yet
    assert len(sender.backlog) == 2 and sender.dropped == 0
    sock = receiver(path)
    assert sender.flush() and drain(sock) == [0, 1]
    sock.close()


def test_only_a_backlog_overflow_is_a_loss_and_it_is_counted_once(tmp_path):
    sender = FlowSender(tmp_path / 'nobody.sock', backlog=3)
    results = [sender.send({'n': n}) for n in range(5)]
    assert results == [True, True, True, False, False]
    assert sender.dropped == 2 and sender.health()['waiting'] == 3


def test_pipeline_reports_one_loss_counter(tmp_path):
    from satsuma.pipeline import Pipeline
    pipeline = Pipeline.__new__(Pipeline)
    pipeline._flow_sender = FlowSender(tmp_path / 'nobody.sock', backlog=1)
    pipeline._flow_sender.send({'n': 0})
    pipeline._flow_sender.send({'n': 1})
    health = pipeline.flow_health()
    assert health['failed'] == 0 and health['dropped'] == 1 and health['waiting'] == 1
