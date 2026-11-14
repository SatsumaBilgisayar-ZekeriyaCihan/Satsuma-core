"""An alert is acted on only if a live local process owns its flow.

Real sockets and real process memory; Satsuma's DNS records are a real
sqlite table.

Uyarı, yalnızca akışın sahibi canlı bir yerel süreç ise işleme alınır. Gerçek
soketler ve gerçek süreç belleği; Satsuma'nın DNS kayıtları gerçek bir sqlite
tablosudur.
"""
import json
import socket
import sqlite3
from types import SimpleNamespace

from satsuma.alert_verify import dns_names_for, verify_alert
from satsuma import peer_watch as pw


def pair():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    client = socket.create_connection(('127.0.0.1', port))
    accepted, _ = listener.accept()
    return listener, client, accepted, port


def alert(client, port):
    return {'source_ip': '127.0.0.1', 'source_port': client.getsockname()[1],
            'dest_ip': '127.0.0.1', 'dest_port': port}


def store_with(rows):
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE records(id INTEGER PRIMARY KEY, kind TEXT, body TEXT)')
    for row in rows:
        db.execute('INSERT INTO records(kind, body) VALUES(?,?)', ('dns', json.dumps(row)))
    return SimpleNamespace(db=db)


def test_alert_for_a_live_flow_is_verified_with_process_and_memory_read():
    listener, client, accepted, port = pair()
    try:
        report = verify_alert(alert(client, port))
        assert report['verdict'] == 'verified_live_process' and report['flow_seen'] is True
        assert report['processes'] and report['memory_verification'][0]['live'] is True
    finally:
        for s in (client, accepted, listener):
            s.close()


def test_alert_for_a_flow_that_does_not_exist_is_possible_forgery():
    forged = {'source_ip': '203.0.113.9', 'source_port': 443, 'dest_ip': '10.0.0.2', 'dest_port': 51234}
    report = verify_alert(forged)
    assert report['verdict'] == 'unverified_possible_forgery'
    assert report['flow_seen'] is False and report['processes'] == []


def test_flow_seen_by_the_watch_window_counts_even_after_the_socket_closed():
    watch = pw.PeerWatch(ptr=None, eligible=lambda *a: True)
    watch.flows[('10.0.0.2', 51234, '203.0.113.9', 443)] = (0, [pw.process_identity(__import__('os').getpid())])
    report = verify_alert({'source_ip': '203.0.113.9', 'source_port': 443,
                           'dest_ip': '10.0.0.2', 'dest_port': 51234}, watch=watch)
    assert report['verdict'] == 'verified_live_process'


def test_flow_seen_without_any_process_is_not_enough():
    watch = pw.PeerWatch(ptr=None, eligible=lambda *a: True)
    watch.flows[('10.0.0.2', 51234, '203.0.113.9', 443)] = (0, [])
    report = verify_alert({'source_ip': '203.0.113.9', 'source_port': 443,
                           'dest_ip': '10.0.0.2', 'dest_port': 51234}, watch=watch)
    assert report['verdict'] == 'flow_without_live_process' and report['flow_seen'] is True


def test_dead_process_memory_is_not_live():
    watch = pw.PeerWatch(ptr=None, eligible=lambda *a: True)
    watch.flows[('10.0.0.2', 51234, '203.0.113.9', 443)] = (0, [{'pid': 2 ** 22 + 99}])
    report = verify_alert({'source_ip': '203.0.113.9', 'source_port': 443,
                           'dest_ip': '10.0.0.2', 'dest_port': 51234}, watch=watch)
    assert report['verdict'] == 'flow_without_live_process'


def test_dns_records_give_the_domain_asked_for_the_peer():
    store = store_with([{'query': 'Example.org.', 'ips': ['203.0.113.9']},
                        {'query': 'other.net', 'ips': ['198.51.100.7']}, {'query': 'x', 'ips': 'bad'}])
    assert dns_names_for(store, '203.0.113.9') == {'example.org'}
    assert dns_names_for(store, '192.0.2.1') == set()
    assert dns_names_for(None, '203.0.113.9') == set()
    watch = pw.PeerWatch(ptr=None, eligible=lambda *a: True)
    watch.flows[('10.0.0.2', 51234, '203.0.113.9', 443)] = (0, [pw.process_identity(__import__('os').getpid())])
    report = verify_alert({'source_ip': '203.0.113.9', 'source_port': 443,
                           'dest_ip': '10.0.0.2', 'dest_port': 51234}, watch=watch, store=store)
    assert report['dns_domains'] == ['example.org'] and report['dns_backed'] is True
