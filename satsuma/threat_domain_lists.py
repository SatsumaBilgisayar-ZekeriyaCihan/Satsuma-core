"""Curated malware/C2 and ransomware domain feeds, with last-good snapshots."""
import hashlib
import json
from pathlib import Path
import time

from .domain_lists import parse, update

FEEDS = {
    'malware': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt',
    'ransomware': 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/ransomware-nl.txt',
}
CACHE = Path('/var/lib/satsuma-core/dns')
BUNDLED = Path('/usr/share/satsuma-core/dns-feeds')
REFRESH_SECONDS = 8 * 3600


def blocked_domains(store, cache=CACHE, bundled=BUNDLED, updater=update):
    names=set()
    for name,url in FEEDS.items():
        path=cache/(name+'.txt')
        key='dns_threat_feed.'+name
        info=store.get(key,{}) or {}
        snapshot=bundled/(name+'.txt')
        # Packaged data provides a reproducible initial list without requiring
        # a network connection during installation. Runtime updates stay in /var.
        if not path.exists() and snapshot.is_file():
            manifest=json.loads((bundled/'sources.json').read_text())
            raw=snapshot.read_bytes();entry=manifest[name]
            if entry['source']!=url or hashlib.sha256(raw).hexdigest()!=entry['sha256']:
                raise ValueError('Bundled DNS threat feed checksum mismatch: '+name)
            selected=snapshot
            updated_at=entry['updated_at']
        else:
            selected=path
            updated_at=info.get('updated_at',0)
        attempt_failed=info.get('status')=='UPDATE_FAILED' and time.time()-info.get('last_attempt',0)<900
        if not attempt_failed and (not selected.exists() or time.time()-updated_at>=REFRESH_SECONDS):
            try:
                info=updater(store,path,url=url,state_key=key)
                selected=path
            except Exception as exc:
                attempt_failed=True
                info={**info,'status':'UPDATE_FAILED','error':str(exc)[:300],
                      'source':url,'updated_at':updated_at,'last_attempt':time.time()}
                store.set(key,info)
                if not selected.exists():raise RuntimeError('No usable DNS threat feed: '+name) from exc
                # Explicitly retain the last good snapshot; never replace it
                # with an empty list on download or parsing errors.
        if not selected.exists():raise RuntimeError('No usable DNS threat feed: '+name)
        values=parse(selected.read_text())
        names.update(values)
        if not attempt_failed and (not info or selected==snapshot):
            store.set(key,{'source':url,'count':len(values),'updated_at':updated_at,
                           'status':'BUNDLED' if selected==snapshot else 'CACHED',
                           'sha256':hashlib.sha256(selected.read_bytes()).hexdigest()})
    return names
