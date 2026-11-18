"""User-selected public HTTPS domain lists: fetched once on request, parsed as data, with rollback."""
import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
import urllib.parse
import urllib.request
from pathlib import Path
from .domain_lists import domain

MAX_BYTES=4*1024*1024
MAX_DOMAINS=200000
MAX_SOURCES=8


def validate_url(url):
    if not isinstance(url,str) or len(url)>2048 or any(c.isspace() for c in url):raise ValueError('Liste adresi geçersiz')
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None,443):
        raise ValueError('Liste adresi kullanıcı bilgisi içermeyen HTTPS adresi olmalı')
    host=parsed.hostname.encode('idna').decode('ascii')
    try:address=ipaddress.ip_address(host)
    except ValueError:domain(host)
    else:
        if not address.is_global or address.is_multicast:raise ValueError('Yerel/özel adresler liste kaynağı olamaz')
    return url


def public_addresses(host,port):
    rows=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
    addresses=[]
    for _,_,_,_,peer in rows:
        address=ipaddress.ip_address(peer[0])
        if not address.is_global or address.is_multicast or address in ipaddress.ip_network('64:ff9b::/96') or address in ipaddress.ip_network('64:ff9b:1::/48'):
            raise ValueError('Kaynak özel/yerel ağ adresine çözümlendi')
        if str(address) not in addresses:addresses.append(str(address))
    if not addresses:raise ValueError('Kaynak adresi çözümlenemedi')
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        addresses=public_addresses(self.host,self.port)
        # Resolve once, connect to that exact public IP and verify TLS for original hostname.
        raw=socket.create_connection((addresses[0],self.port),timeout=self.timeout)
        try:self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except BaseException:raw.close();raise


class PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self,request):return self.do_open(PinnedHTTPS,request,context=self._context)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Yönlendirme kabul edilmedi; listenin doğrudan adresini girin')


def download(url):
    """Download a list the user added, once, on the user's own request.

    2.2.44 (owner's decision 2026-11-13): the product downloads no list by
    itself and never refreshes one automatically; a user list is fetched only
    when the user adds or explicitly updates it, then kept as a read-only,
    signed copy. Kullanıcının eklediği liste yalnızca onun isteğiyle bir kez
    indirilir, otomatik yenilenmez; salt okunur ve imzalı kopyası saklanır.
    """
    validate_url(url)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),PublicHTTPSHandler(context=ssl.create_default_context()),NoRedirect())
    deadline=time.monotonic()+30;raw=bytearray()
    with opener.open(url,timeout=10) as response:
        while True:
            if time.monotonic()>deadline:raise TimeoutError('Liste indirme süresi aşıldı')
            chunk=response.read1(min(65536,MAX_BYTES+1-len(raw)))
            if not chunk:break
            raw.extend(chunk)
            if len(raw)>MAX_BYTES:raise ValueError('Liste 4 MiB sınırını aşıyor')
    return bytes(raw)


KEEP=Path('/var/lib/satsuma-core/dns/custom')


def keep_copy(identifier,names,directory=KEEP):
    """Store the verified names root-owned, 0444, with an HMAC signature beside them."""
    import os,tempfile
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=directory.lstat()
    if directory.is_symlink() or info.st_uid!=os.geteuid() or info.st_mode&0o022:
        raise PermissionError('Unsafe custom list directory')
    path=directory/(identifier+'.list')
    fd,temporary=tempfile.mkstemp(prefix='.list-',dir=directory)
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write('\n'.join(names)+'\n');stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,0o444)
        os.replace(temporary,path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    from installer.integrity import read_key,sign
    sign(path,read_key())
    return str(path)


def drop_copy(identifier,directory=KEEP):
    for path in (directory/(identifier+'.list'),directory/(identifier+'.list.sig')):
        if path.is_file() and not path.is_symlink():path.unlink()


def parse_data(raw):
    if len(raw)>MAX_BYTES:raise ValueError('Liste boyut sınırını aşıyor')
    names=set()
    for number,line in enumerate(raw.decode('utf-8-sig').splitlines(),1):
        line=line.strip()
        if not line or line.startswith(('#','!')) or line in ('[Adblock Plus 2.0]','[Adblock Plus 1.1]'):continue
        line=line.split('#',1)[0].strip()
        if not line:continue
        if line.startswith('||') and line.endswith('^'):tokens=[line[2:-1]]
        else:
            tokens=line.split()
            if tokens[0] in ('0.0.0.0','127.0.0.1','::','::1'):tokens=tokens[1:]
            elif len(tokens)!=1:raise ValueError('Satır '+str(number)+': alan adı/hosts/adblock listesi bekleniyor')
        for token in tokens:
            if token=='localhost':continue
            try:
                ipaddress.ip_address(token)
            except ValueError:pass
            else:raise ValueError('IP listesi DNS alan adı listesi olarak kullanılamaz')
            try:name=domain(token)
            except ValueError:raise ValueError('Satır '+str(number)+': desteklenmeyen kayıt') from None
            if name.endswith(('.local','.lan','.home.arpa','.arpa')):continue
            names.add(name)
            if len(names)>MAX_DOMAINS:raise ValueError('Liste alan adı sınırını aşıyor')
    if not names:raise ValueError('Listede kullanılabilir alan adı yok')
    return sorted(names)


def sources(store):return dict(store.get('custom_dns_sources',{}) or {})


def blocked_domains(store):
    if not store.get('custom_dns_lists_enabled',False):return set()
    names=set()
    for entry in sources(store).values():names.update(entry.get('domains',[]))
    if len(names)>MAX_DOMAINS:raise ValueError('Ek liste toplam sınırı aşıldı')
    return names


def status(store):
    return {'enabled':bool(store.get('custom_dns_lists_enabled',False)),
            'sources':[{key:value for key,value in item.items() if key!='domains'} for item in sources(store).values()],
            'dns_filter_enabled':bool((store.get('dns_policy',{}) or {}).get('enabled')),
            'format':'domain / hosts / ||domain^','network_ip_blocklist':False}


def _default_keep():
    import os
    if os.geteuid()==0 and KEEP.parent.parent.is_dir():
        return keep_copy,drop_copy
    return (lambda *a:None),(lambda *a:None)


def change(store,url,action,refresh,fetcher=download,keep=None):
    url=validate_url(url);identifier=hashlib.sha256(url.encode()).hexdigest()
    old=sources(store);previous_enabled=store.get('custom_dns_lists_enabled',False)
    updated=dict(old)
    if action=='remove':updated.pop(identifier,None)
    elif action=='update':
        if identifier not in updated and len(updated)>=MAX_SOURCES:raise ValueError('En çok 8 liste eklenebilir')
        raw=fetcher(url);names=parse_data(raw)
        updated[identifier]={'id':identifier,'url':url,'domains':names,'count':len(names),
                             'sha256':hashlib.sha256(raw).hexdigest(),'updated_at':time.time()}
        combined={name for entry in updated.values() for name in entry['domains']}
        if len(combined)>MAX_DOMAINS:raise ValueError('Ek listeler toplam 200000 alan adını aşamaz')
    else:raise ValueError('Desteklenmeyen liste işlemi')
    store.set('custom_dns_sources',updated)
    store.set('custom_dns_lists_enabled',bool(updated))
    try:result=refresh()
    except Exception as exc:
        store.set('custom_dns_sources',old);store.set('custom_dns_lists_enabled',previous_enabled)
        try:refresh()
        except Exception as rollback:
            store.add('errors',{'component':'custom_dns_lists','status':'ROLLBACK_FAILED','error':str(rollback)[:250]})
        raise RuntimeError('Liste uygulanamadı; önceki kaynaklar korundu: '+str(exc)[:250]) from exc
    store_copy,remove_copy=keep or _default_keep()
    try:
        if action=='remove':remove_copy(identifier)
        else:store_copy(identifier,updated[identifier]['domains'])
    except Exception as exc:
        store.add('errors',{'component':'custom_dns_lists','status':'COPY_FAILED','error':str(exc)[:250]})
    return {'ok':True,'custom_lists':status(store),'apply_status':result.get('status'),
            'active':bool((store.get('dns_policy',{}) or {}).get('enabled')) and result.get('status') in ('configured','unchanged')}
