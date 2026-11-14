import hashlib
import json
import time
from pathlib import Path
import pytest
from satsuma import threat_domain_lists as feeds
from satsuma.dnsmasq_control import render


class Store:
    def __init__(self):self.values={}
    def get(self,key,default=None):return self.values.get(key,default)
    def set(self,key,value):self.values[key]=value


def bundled(tmp_path,age=0):
    cache=tmp_path/'cache';cache.mkdir()
    root=tmp_path/'bundled';root.mkdir();meta={}
    for name,url in feeds.FEEDS.items():
        raw=(name+'.example\nshared.example\n').encode()
        (root/(name+'.txt')).write_bytes(raw)
        meta[name]={'source':url,'sha256':hashlib.sha256(raw).hexdigest(),'updated_at':time.time()-age}
    (root/'sources.json').write_text(json.dumps(meta))
    return cache,root


def test_bundled_feeds_merge_offline_and_allowlist_has_priority(tmp_path):
    cache,root=bundled(tmp_path);store=Store()
    values=feeds.blocked_domains(store,cache,root,updater=lambda *a,**k:pytest.fail('fresh snapshot must work offline'))
    assert values=={'malware.example','ransomware.example','shared.example'}
    rules=render({'upstream':'192.0.2.53'},values,['ransomware.example'])
    assert 'address=/malware.example/#' in rules and 'address=/ransomware.example/' not in rules
    assert 'server=/ransomware.example/192.0.2.53' in rules


def test_failed_update_retains_snapshot_and_reports_failure(tmp_path):
    cache,root=bundled(tmp_path,age=feeds.REFRESH_SECONDS+1);store=Store()
    def fail(*a,**k):raise OSError('offline')
    assert 'ransomware.example' in feeds.blocked_domains(store,cache,root,updater=fail)
    assert store.get('dns_threat_feed.ransomware')['status']=='UPDATE_FAILED'
    assert (root/'ransomware.txt').read_text().startswith('ransomware.example')


def test_no_snapshot_never_silently_becomes_empty_list(tmp_path):
    store=Store()
    def fail(*a,**k):raise OSError('offline')
    with pytest.raises(RuntimeError,match='No usable'):
        feeds.blocked_domains(store,tmp_path,tmp_path/'missing',updater=fail)


def test_bundled_snapshot_checksum_is_verified(tmp_path):
    cache,root=bundled(tmp_path);(root/'malware.txt').write_text('altered.example\n')
    with pytest.raises(ValueError,match='checksum mismatch'):
        feeds.blocked_domains(Store(),cache,root)


def test_shipped_sources_parse_and_match_recorded_checksums():
    from satsuma.domain_lists import parse
    root=Path(__file__).parents[1]/'data/dns-feeds'
    meta=json.loads((root/'sources.json').read_text())
    for name,url in feeds.FEEDS.items():
        raw=(root/(name+'.txt')).read_bytes()
        assert meta[name]['source']==url
        assert hashlib.sha256(raw).hexdigest()==meta[name]['sha256']
        assert len(parse(raw.decode()))==meta[name]['count']>0
