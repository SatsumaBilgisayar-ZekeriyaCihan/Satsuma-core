"""2.2.44: no downloaded feed and no list address remain in the product.

İndirilen liste ve liste adresi üründe kalmadı (sahibi, 2026-11-13).
"""
from pathlib import Path

from satsuma import threat_domain_lists as feeds
from satsuma.dnsmasq_control import render

ROOT = Path(__file__).parents[1]


def test_feeds_are_gone_and_give_no_names():
    assert feeds.FEEDS == {} and feeds.blocked_domains(object()) == set()
    assert not (ROOT / 'data' / 'dns-feeds').exists()


def test_no_list_address_or_github_feed_left_in_product_code():
    for folder in ('satsuma', 'installer', 'workers', 'integrations'):
        for path in (ROOT / folder).rglob('*.py'):
            text = path.read_text(errors='replace')
            assert 'raw.githubusercontent.com' not in text, path
            assert 'hagezi/dns-blocklists' not in text and 'blocklistproject' not in text.lower(), path
    spec = (ROOT / 'packaging' / 'satsuma-core.spec').read_text()
    assert 'dns-feeds' not in spec


def test_allowlist_still_has_priority_over_blocked_names():
    rules = render({'upstream': '208.67.222.222'}, {'bad.example', 'ok.example'}, ['ok.example'])
    assert 'address=/bad.example/#' in rules and 'address=/ok.example/' not in rules
    assert 'server=/ok.example/208.67.222.222' in rules
