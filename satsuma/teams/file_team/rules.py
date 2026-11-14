"""File identity is a path plus hash; unverified AV text is not dual proof."""
from satsuma.teams.host_team.rules import _BaseRule

def identity(event):
    ext=event.get('metadata',{}).get('extensions',{})
    target=ext.get('host.target') or ext.get('host.file')
    path=target.get('path') if isinstance(target,dict) else target
    digest=ext.get('host.hash') or (target.get('sha256') if isinstance(target,dict) else None)
    return path if isinstance(path,str) else None,digest

def groups(events,action):
    out={}
    for e in events:
        if e.get('action')==action:
            path,digest=identity(e)
            if path:out.setdefault((path,digest),[]).append(e)
    return out



class ClamavOnlyMatchRule(_BaseRule):
    name='clamav_match_alone';severity='high'
    def match(self,events):
        c=groups(events,'virus_detected')
        return [self._finding(self.name,es,f'ClamAV eslesmesi: {key[0]}',severity='high',confidence='medium',classification='suspicious',extra={'path':key[0]}) for key,es in c.items()]
