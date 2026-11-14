"""Cloudflare is never Satsuma's DNS upstream, and no Satsuma code allows port 853.

Redirection to fake sites through Cloudflare was reported, and C2 traffic over
port 853 was proven on this machine (owner, 2026-11-14). A Cloudflare upstream
is refused from the panel and replaced by OpenDNS everywhere else, so the DNS
filter never goes off because of it.

Cloudflare asla Satsuma'nın DNS üst sunucusu olmaz ve hiçbir Satsuma kodu 853
portuna izin vermez. Cloudflare üzerinden sahte sitelere yönlendirme bildirildi,
853 üzerinden C2 trafiği bu makinede kanıtlandı. Cloudflare üst sunucusu panelde
reddedilir, başka her yerde OpenDNS ile değiştirilir; DNS filtresi bu yüzden
kapanmaz.
"""
import ast
import re
from pathlib import Path

import pytest

from satsuma import dnsmasq_control
from satsuma.dnsmasq_control import OPENDNS, is_cloudflare, safe_upstream, upstream_servers

ROOT = Path(__file__).resolve().parents[1]
CLOUDFLARE = ('1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.3', '2606:4700:4700::1111', '2606:4700:4700::1001')


@pytest.mark.parametrize('address', CLOUDFLARE)
def test_cloudflare_upstream_becomes_opendns(address):
    assert is_cloudflare(address)
    assert safe_upstream(address) == OPENDNS[0]
    assert upstream_servers(address) == list(OPENDNS)


@pytest.mark.parametrize('address', CLOUDFLARE)
def test_dnsmasq_never_forwards_to_cloudflare(address):
    text = dnsmasq_control.render({'upstream': address}, ['bad.example'], ['good.example'])
    assert address not in text and OPENDNS[0] in text


def test_other_upstreams_are_kept():
    assert not is_cloudflare('208.67.222.222') and not is_cloudflare('not-an-ip')
    assert safe_upstream('9.9.9.9') == '9.9.9.9'


def test_stored_cloudflare_upstream_moves_to_opendns_on_reload():
    from satsuma.configuration_reload import apply_features
    class Store:
        def __init__(self):
            self.values = {'dns_policy': {'upstream': '1.1.1.1', 'upstream_source': 'operator'}}
        def get(self, key, default=None):
            return self.values.get(key, default)
        def set(self, key, value):
            self.values[key] = value
    store = Store()
    # Only the DNS policy is under test; the firewall and app-control steps
    # that follow it call nft and write root storage, so they are stubbed.
    # Yalnız DNS politikası sınanır; ardından gelen güvenlik duvarı ve
    # uygulama denetimi adımları nft çağırır, bu yüzden taklit edilir.
    from unittest.mock import patch, MagicMock
    with patch('satsuma.dnsmasq_control.refresh'), \
         patch('satsuma.network_modes.NetworkModes', MagicMock()), \
         patch('satsuma.protected_storage.RootDataStore', MagicMock()), \
         patch('satsuma.app_firewall.policy', return_value={}):
        apply_features(store, {})
    assert store.values['dns_policy']['upstream'] == OPENDNS[0]
    assert store.values['dns_policy']['upstream_source'] == 'opendns_replaced_cloudflare'


def test_full_check_does_not_accept_cloudflare():
    from satsuma.full_check import _usable_upstream
    assert _usable_upstream('1.1.1.1') is None
    assert _usable_upstream('208.67.222.222') == '208.67.222.222'


def test_panel_refuses_cloudflare_upstream():
    source = (ROOT / 'satsuma/operator_service.py').read_text()
    assert 'is_cloudflare(resolver)' in source and 'Cloudflare DNS sunucusu kullanılamaz' in source


def test_no_satsuma_code_accepts_port_853():
    # Only comments and docstrings may name 853; no code literal may.
    for path in list((ROOT / 'satsuma').rglob('*.py')) + list((ROOT / 'installer').glob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value == 853:
                raise AssertionError(f'{path.relative_to(ROOT)}:{node.lineno} names port 853')
    for path in (ROOT / 'packaging/root').rglob('*'):
        if path.is_file():
            text = path.read_text(encoding='utf-8', errors='replace')
            assert not re.search(r'\b853\b.*accept|accept.*\b853\b', text), path
