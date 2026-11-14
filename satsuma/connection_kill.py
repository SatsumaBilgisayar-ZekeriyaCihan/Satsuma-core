"""Terminate exactly one TCP connection and verify that it is gone.

Blocking an address in nftables stops new packets but leaves the established
socket in place. This module closes the one connection named by its full
4-tuple using the kernel's socket destroy (``ss -K``, needs
CONFIG_INET_DIAG_DESTROY). The 4-tuple is tried in both orientations because
an alert does not say which end is local. A connection counts as terminated
only when it was seen first and a second look no longer finds it. Nothing
else is touched: not the process, not the address, not other connections.

Loopback, unspecified, multicast and non-TCP flows are refused. The runner is
injectable so the command lines and the verification can be tested.

Tam olarak tek bir TCP bağlantısını sonlandırır ve gittiğini doğrular.

nftables'ta adresi engellemek yeni paketleri durdurur ama kurulmuş soketi
yerinde bırakır. Bu modül tam 4'lüsüyle adı verilen tek bağlantıyı çekirdeğin
soket yok etme özelliğiyle (``ss -K``, CONFIG_INET_DIAG_DESTROY gerekir)
kapatır. Uyarı hangi ucun yerel olduğunu söylemediği için 4'lü iki yönde de
denenir. Bağlantı, ancak önce görülmüş ve ikinci bakışta artık bulunmuyorsa
sonlandırılmış sayılır. Başka hiçbir şeye dokunulmaz: ne sürece, ne adrese, ne
diğer bağlantılara.

Geri döngü (loopback), belirsiz, çok noktaya yayın ve TCP olmayan akışlar
reddedilir. Komut satırları ve doğrulama sınanabilsin diye çalıştırıcı
dışarıdan verilebilir.
"""
import ipaddress
import subprocess

TIMEOUT = 5


def _endpoint(ip, port):
    try:
        address = ipaddress.ip_address(str(ip))
        number = int(port)
    except (TypeError, ValueError):
        return None
    address = getattr(address, 'ipv4_mapped', None) or address
    if not 0 < number < 65536:
        return None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    return str(address), number


def _filter(local, remote):
    def side(endpoint):
        host, port = endpoint
        return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    return ['src', side(local), 'dst', side(remote)]


def _run(argv, runner):
    try:
        result = runner(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)[:200]
    return result, (result.stderr or '')[:200]


def _present(local, remote, runner):
    """True/False whether the connection exists; None when it cannot be read."""
    result, _ = _run(['ss', '-H', '-tn', 'state', 'all'] + _filter(local, remote), runner)
    if result is None or result.returncode:
        return None
    return bool((result.stdout or '').strip())


def kill_connection(src_ip, src_port, dst_ip, dst_port, proto='tcp', runner=subprocess.run):
    """Close the TCP connection; the result says what was verified."""
    report = {'action': 'tcp_connection_kill', 'terminated': False, 'verified': False, 'reason': None}
    if str(proto or '').lower() != 'tcp':
        report['reason'] = 'only_tcp_supported'
        return report
    first, second = _endpoint(src_ip, src_port), _endpoint(dst_ip, dst_port)
    if first is None or second is None:
        report['reason'] = 'invalid_or_protected_endpoint'
        return report
    for local, remote in ((first, second), (second, first)):
        seen = _present(local, remote, runner)
        if seen is None:
            report['reason'] = 'ss_unavailable'
            return report
        if not seen:
            continue
        result, detail = _run(['ss', '-K', '-H', '-tn', 'state', 'all'] + _filter(local, remote), runner)
        if result is None or result.returncode:
            report['reason'] = 'socket_destroy_failed'
            report['detail'] = detail
            return report
        gone = _present(local, remote, runner)
        report.update(local=f'{local[0]}:{local[1]}', remote=f'{remote[0]}:{remote[1]}')
        if gone is False:
            report.update(terminated=True, verified=True, reason=None)
        else:
            report['reason'] = 'connection_still_present_after_destroy'
        return report
    report['reason'] = 'connection_not_found'
    return report
