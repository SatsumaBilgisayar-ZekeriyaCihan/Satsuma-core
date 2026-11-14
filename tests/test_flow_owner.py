"""Real sockets, real child process: no mocked /proc.

Gerçek soketler, gerçek alt süreç: /proc taklit edilmez.
"""
import socket
import subprocess
import sys
import time

from satsuma.flow_owner import find_owner
from satsuma.process_identity import read_proc_exe, read_proc_starttime

CHILD = ("import socket,sys,time\n"
         "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])))\n"
         "print(s.getsockname()[1],flush=True)\n"
         "time.sleep(60)\n")


def _server():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    return listener, listener.getsockname()[1]


def _start_child(port):
    child = subprocess.Popen([sys.executable, '-c', CHILD, str(port)], stdout=subprocess.PIPE, text=True)
    local_port = int(child.stdout.readline())
    return child, local_port


def test_finds_the_child_that_holds_the_connection_in_both_directions():
    listener, port = _server()
    child, local_port = _start_child(port)
    try:
        accepted, _ = listener.accept()
        # Both ends are on this host (loopback): two live sockets match the
        # flow, so the owner is ambiguous and nothing is returned.
        assert find_owner('127.0.0.1', local_port, '127.0.0.1', port, 'tcp') is None
        # Once the peer end is closed only the child still holds the flow.
        accepted.close()
        time.sleep(0.2)
        expected = {'pid': child.pid, 'starttime': read_proc_starttime(child.pid),
                    'exe': read_proc_exe(child.pid)}
        assert expected['starttime'] is not None and expected['exe']
        # Suricata may report the flow in either direction.
        assert find_owner('127.0.0.1', local_port, '127.0.0.1', port, 'tcp') == expected
        assert find_owner('127.0.0.1', port, '127.0.0.1', local_port, 'tcp') == expected
    finally:
        child.kill()
        child.wait(timeout=5)
        listener.close()


def test_port_alone_is_never_enough():
    listener, port = _server()
    child, local_port = _start_child(port)
    try:
        listener.accept()
        assert find_owner('127.0.0.1', local_port, '127.0.0.1', port + 1, 'tcp') is None
        assert find_owner('10.9.9.9', local_port, '127.0.0.1', port, 'tcp') is None
    finally:
        child.kill()
        child.wait(timeout=5)
        listener.close()


def test_closed_connection_gives_no_owner():
    listener, port = _server()
    child, local_port = _start_child(port)
    try:
        accepted, _ = listener.accept()
        accepted.close()
        child.kill()
        child.wait(timeout=5)
        time.sleep(0.3)
        # No live holder is left: the answer is None, never a stale guess.
        assert find_owner('127.0.0.1', local_port, '127.0.0.1', port, 'tcp') is None
    finally:
        listener.close()


def test_bad_input_is_rejected():
    for args in (('', 1, '127.0.0.1', 2, 'tcp'), ('127.0.0.1', 0, '127.0.0.1', 2, 'tcp'),
                 ('127.0.0.1', 1, '127.0.0.1', 70000, 'tcp'), ('127.0.0.1', 1, '127.0.0.1', 2, 'icmp'),
                 ('nonsense', 1, '127.0.0.1', 2, 'tcp')):
        assert find_owner(*args) is None


def test_socket_shared_by_two_processes_is_not_attributed():
    listener, port = _server()
    # The child inherits the connected socket: two holders -> no single owner.
    client = socket.create_connection(('127.0.0.1', port))
    local_port = client.getsockname()[1]
    child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],
                             pass_fds=[client.fileno()])
    try:
        listener.accept()
        time.sleep(0.2)
        assert find_owner('127.0.0.1', local_port, '127.0.0.1', port, 'tcp') is None
    finally:
        child.kill()
        child.wait(timeout=5)
        client.close()
        listener.close()
