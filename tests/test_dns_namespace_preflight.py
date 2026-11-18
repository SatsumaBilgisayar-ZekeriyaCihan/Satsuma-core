import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('dns_namespace_preflight', ROOT / 'tools/dns_namespace_preflight.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_current_source_passes_the_source_checks_without_mutation():
    # 2.2.44: the namespace migration is done; only host verification remains.
    result = mod.assess(ROOT)
    assert result['blockers'] == [] and result['status'] == 'SOURCE_CHECKS_PASSED_NOT_HOST_VERIFIED'


def test_a_regression_to_loopback_or_direct_resolver_is_blocked(tmp_path):
    for relative in ('systemd/satsuma-core-dns.service', 'satsuma/dnsmasq_control.py', 'satsuma/network_modes.py',
                     'satsuma/network_control.py', 'packaging/root/etc/satsuma-core/nftables.nft'):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / relative).read_text())
    (tmp_path / 'satsuma/dnsmasq_control.py').write_text("config = 'port=53053\\nlisten-address=127.0.0.1\\n'")
    (tmp_path / 'satsuma/network_modes.py').write_text("udp dport 53 dnat ip to 208.67.222.222")
    rules = tmp_path / 'packaging/root/etc/satsuma-core/nftables.nft'
    rules.write_text(rules.read_text().replace('sport 53 counter queue num 100', 'sport 53 counter accept'))
    result = mod.assess(tmp_path)
    assert result['status'] == 'BLOCKED'
    assert any('loopback' in blocker for blocker in result['blockers'])
    assert any('public resolver' in blocker for blocker in result['blockers'])
    assert any('NFQUEUE' in blocker for blocker in result['blockers'])


def test_missing_sources_fail_closed(tmp_path):
    result = mod.assess(tmp_path)
    assert result['status'] == 'BLOCKED'
    assert any('Missing' in blocker for blocker in result['blockers'])
