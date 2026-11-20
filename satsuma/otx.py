"""AlienVault OTX threat-intelligence worker with strict TLS verification.

Anyone can publish an OTX pulse, so one pulse never blocks an address
(audit K3). Blocking needs at least two pulses, the operator's threshold
and a recent pulse; the retired ``any_pulse`` mode is read as
``threshold``. Selected DNS resolvers are never blocked. TeamViewer and
AnyDesk domains, and the addresses resolved from them, are never blocked
automatically because of OTX; they are recorded for review instead.

AlienVault OTX tehdit istihbaratı işçisi; TLS doğrulaması zorunlu.

OTX'e herkes kayıt (pulse) ekleyebildiği için tek kayıt hiçbir adresi
engellemez (denetim K3). Engelleme için en az iki kayıt, operatörün eşiği
ve güncel bir kayıt gerekir; kaldırılan ``any_pulse`` modu ``threshold``
olarak okunur. Seçili DNS sunucuları hiçbir zaman engellenmez. TeamViewer ve
AnyDesk alan adları ile bu adlardan çözülen adresler OTX yüzünden otomatik
engellenmez; kayıt tutulur ve incelemeye bırakılır.

Ayarlar iki kaynaktan gelir:
- ``policy.json`` (workers.otx): enabled, blocker_mode, pulse_threshold,
  recent_pulse_days, require_tls — operatör tarafından yönetilir.
- ``/etc/satsuma-core/otx.json``: yalnızca API anahtarı (secret) ve cache TTL.

blocker_mode açıkken OTX tek başına bloker olarak çalışır: TLS kanıtlı ve
son ``recent_pulse_days`` gün içinde güncellenmiş pulse'lar eşiği aşarsa
açıkça seçilmiş OTX eşik politikasıyla IP bloklanır; bu bir doğrulanmış saldırı hükmü değildir.
"""
import http.client
import ipaddress
import json
import math
import os
import signal
import ssl
import time
from pathlib import Path

from .config import load_with_policy
from .response import ResponseWorker
from .sentinel import peers
from .store import Store

def record_health(store, state):
    """Preserve historical success without turning the current failure green.

    Geçmiş başarıyı koru; güncel hatayı başarılı gösterme.
    """
    previous=store.get('otx_health', {}) or {}
    history={key:previous[key] for key in ('last_success','last_ip','last_score','last_reason') if key in previous}
    store.set('otx_health', {**history, **state})


CONFIG_PATH = Path('/etc/satsuma-core/otx.json')
HOST = 'otx.alienvault.com'
BASE = '/api/v1/indicators/IPv4/{ip}/general'
# otx.json yalnızca secret + cache ayarlarını tutar; policy ayarları policy.json'dan gelir.
DEFAULT = {'api_key': '', 'cache_ttl_seconds': 3600, 'max_queries_per_cycle': 12}
# Audit K3: the floor under any configured pulse threshold.
# Denetim K3: yapılandırılan her pulse eşiğinin alt sınırı.
MIN_BLOCK_PULSES = 2


# Remote-support vendors the user works through; outbound support must keep
# working. Uzaktan destek üreticileri; dışarıya destek bağlantısı kesilmemeli.
REMOTE_SUPPORT_DOMAINS = ('teamviewer.com', 'anydesk.com')


# 2.2.63 (field 2026-11-20): an OTX pulse put fedoraproject.org on the block list; at the next full
# reload Fedora updates (rpm-ostree, mirrors) would have stopped, and an unpatched system is the
# weaker one. Automatic (OTX) blocking never takes the update servers of what is installed here.
# Lists the owner adds can still block them. Exact registrable domains only (not fedorapeople.org,
# which hosts anyone's files). Güncelleme sunucularını OTX otomatik engellemez.
UPDATE_INFRA_DOMAINS = ('fedoraproject.org', 'getfedora.org', 'flathub.org', 'snapcraft.io', 'snapcraftcontent.com')


def update_infra_domain(name):
    name = (name or '').lower().rstrip('.')
    return any(name == root or name.endswith('.' + root) for root in UPDATE_INFRA_DOMAINS)


def remote_support_domain(name):
    name = (name or '').lower().rstrip('.')
    return any(name == root or name.endswith('.' + root) for root in REMOTE_SUPPORT_DOMAINS)


def remote_support_ips(store, limit=2000):
    """Addresses recently resolved from a remote-support domain."""
    ips = set()
    rows = store.db.execute("SELECT body FROM records WHERE kind='dns' ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    for (body,) in rows:
        try:
            item = json.loads(body)
        except (ValueError, TypeError):
            continue
        if isinstance(item, dict) and remote_support_domain(item.get('query')):
            ips.update(str(ip) for ip in item.get('ips') or [] if isinstance(ip, str))
    return ips


def match_mode(value):
    """Only ``threshold`` remains; ``any_pulse`` (one pulse blocks) is retired."""
    return 'threshold' if value in (None, 'any_pulse') else value


def load_config(path=CONFIG_PATH):
    """otx.json'dan secret + cache ayarlarını oku (policy ayarları hariç)."""
    cfg = dict(DEFAULT)
    try:
        import stat
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                    or st.st_mode & 0o077 or st.st_size > 16384):
                raise PermissionError('OTX config requires a private root-owned regular file')
            with os.fdopen(os.dup(fd), encoding='utf-8') as stream:
                raw = json.load(stream)
        finally:
            os.close(fd)
        if path == CONFIG_PATH:
            import hmac
            from installer.integrity import KEY, read_key, file_hmac
            signature = Path(str(path) + '.sig')
            if signature.is_symlink() or not hmac.compare_digest(file_hmac(read_key(KEY), path), signature.read_bytes()):
                raise PermissionError('OTX configuration signature mismatch; save the key again')
        if not isinstance(raw, dict):
            raise ValueError('invalid OTX configuration')
        for key in DEFAULT:
            if key in raw:
                cfg[key] = raw[key]
    except FileNotFoundError:
        if path.exists() or path.is_symlink():
            raise PermissionError('OTX configuration is unsigned; save the key again')
    if not isinstance(cfg['api_key'], str):
        raise ValueError('invalid OTX configuration')
    if type(cfg['cache_ttl_seconds']) is not int or not 300 <= cfg['cache_ttl_seconds'] <= 86400:
        raise ValueError('invalid OTX cache TTL')
    if type(cfg['max_queries_per_cycle']) is not int or not 1 <= cfg['max_queries_per_cycle'] <= 64:
        raise ValueError('invalid OTX query limit')
    return cfg


def save_key(api_key, enabled=True, path=CONFIG_PATH):
    """Save a secret privately; activation is explicit in configure_key."""
    api_key = api_key.strip()
    if enabled and len(api_key) < 16:
        raise ValueError('OTX API key is empty or too short')
    # Never adopt an old unverified secret file when replacing its key.
    cfg = dict(DEFAULT)
    cfg['api_key'] = api_key
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import tempfile
    fd, temporary = tempfile.mkstemp(prefix='.otx-', dir=path.parent)
    tmp = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(cfg, stream, ensure_ascii=False)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    if path == CONFIG_PATH:
        from installer.integrity import KEY, read_key, sign
        sign(path, read_key(KEY))
    return cfg


def configure_key(api_key, store=None, runner=None):
    import subprocess
    runner = runner or subprocess.run
    save_key(api_key)
    own = store is None
    store = store or Store()
    try:
        policy = dict(store.get('operator_otx_policy', {}) or {})
        policy.update(enabled=True, blocker_mode=True)
        # Audit K3: one pulse is not enough; block only under the threshold.
        policy['match_mode'] = match_mode(policy.get('match_mode'))
        store.set('operator_otx_policy', policy)
        record_health(store, {'status':'starting', 'updated_at':time.time(), 'tls_verified':False})
        for args in (['/usr/bin/systemctl','enable','satsuma-core-otx.service'],
                     ['/usr/bin/systemctl','restart','satsuma-core-otx.service']):
            result = runner(args, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError('OTX key saved, but service activation failed: ' + result.stderr[:300])
        store.add('actions', {'action':'otx.key_configured','status':'service_started',
                             'enabled':True,'blocker_mode':True,'timestamp':time.time()})
        return {'enabled':True,'blocker_mode':True,'service_started':True,'remote_key_verified':False}
    finally:
        if own: store.close()


def request_indicator(value, api_key, kind="IPv4", timeout=8):
    if kind == 'IPv4':
        value = str(ipaddress.IPv4Address(value))
    elif kind == 'domain':
        from .domain_lists import domain
        value = domain(value)
    else:
        raise ValueError('Unsupported OTX indicator type')
    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    conn = http.client.HTTPSConnection(HOST, 443, timeout=timeout, context=context)
    try:
        conn.connect()
        sock = conn.sock
        if sock is None or not isinstance(sock, ssl.SSLSocket):
            raise ssl.SSLError('TLS socket not established')
        cert = sock.getpeercert()
        if not cert:
            raise ssl.SSLError('peer certificate unavailable')
        tls = {'verified': True, 'host': HOST, 'version': sock.version() or '-',
               'cipher': (sock.cipher() or ('-',))[0]}
        conn.request('GET', '/api/v1/indicators/' + kind + '/' + value + '/general', headers={
            'X-OTX-API-KEY': api_key, 'Accept': 'application/json',
            'User-Agent': 'Satsuma-Security/0.3.4'})
        res = conn.getresponse(); body = res.read(2 * 1024 * 1024)
        if res.status != 200:
            raise RuntimeError('OTX HTTP %s' % res.status)
        return json.loads(body.decode('utf-8')), tls
    finally:
        conn.close()


def _parse_epoch(value):
    """OTX tarih alanını (ISO 8601 veya epoch) epoch saniyeye çevir."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            from datetime import datetime, timezone
            cleaned = text.replace('Z', '+00:00')
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (ValueError, TypeError):
            return None
    return None


def _latest_pulse_epoch(pulses):
    """Pulse listesindeki en güncel (modified/updated/created) epoch değeri."""
    latest = None
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        for key in ('modified', 'updated', 'created'):
            epoch = _parse_epoch(pulse.get(key))
            if epoch is not None and (latest is None or epoch > latest):
                latest = epoch
    return latest


def summarize(ip, data, tls):
    pulse_info = data.get('pulse_info') if isinstance(data, dict) else {}
    pulse_info = pulse_info if isinstance(pulse_info, dict) else {}
    pulses = pulse_info.get('pulses') if isinstance(pulse_info.get('pulses'), list) else []
    count = pulse_info.get('count')
    if type(count) is not int: count = len(pulses)
    reputation = data.get('reputation', 0) if isinstance(data, dict) else 0
    try: reputation = max(0, int(reputation or 0))
    except (TypeError, ValueError): reputation = 0
    # Product-owned score, never presented as an official OTX score.
    score = min(100, count * 8 + min(20, reputation * 2))
    names = [str(p.get('name')) for p in pulses[:3] if isinstance(p, dict) and p.get('name')]
    tags = []
    for p in pulses[:5]:
        if isinstance(p, dict) and isinstance(p.get('tags'), list): tags.extend(map(str, p['tags'][:5]))
    reason = '; '.join(names[:2]) or (', '.join(dict.fromkeys(tags)) if tags else 'OTX pulse eşleşmesi')
    # En güncel pulse'ın yaşı (gün). Pulse yoksa None.
    latest_epoch = _latest_pulse_epoch(pulses)
    latest_pulse_age_days = None
    if latest_epoch is not None and math.isfinite(latest_epoch) and latest_epoch <= time.time()+60:
        latest_pulse_age_days = max(0.0, (time.time() - latest_epoch) / 86400.0)
    return {'timestamp': time.time(), 'ip': ip, 'pulse_count': count, 'reputation': reputation,
            'satsuma_otx_risk_score': score, 'reason': reason[:500], 'tls': tls,
            'latest_pulse_age_days': latest_pulse_age_days}


def _should_block(item, otx_cfg):
    """Doğrudan bloklama koşulları (blocker_mode açıkken):
      1. require_tls ise TLS bağlantısı kanıtlanmış olmalı.
      2. Pulse sayısı eşiği aşmalı.
      3. En güncel pulse son recent_pulse_days gün içinde olmalı.
    """
    tls = item.get('tls') or {}
    if otx_cfg.get('require_tls', True):
        if not (isinstance(tls, dict) and tls.get('verified') is True):
            return False, 'tls_not_verified'
    if match_mode(otx_cfg.get('match_mode')) != 'threshold':
        return False, 'invalid_match_mode'
    count = item.get('pulse_count')
    if type(count) is not int or count < max(MIN_BLOCK_PULSES, otx_cfg['pulse_threshold']):
        return False, 'below_pulse_threshold'
    age = item.get('latest_pulse_age_days')
    if age is None:
        return False, 'pulse_age_unknown'
    if type(age) not in (int,float) or not math.isfinite(age) or age < 0:
        return False, 'pulse_age_invalid'
    if age > otx_cfg['recent_pulse_days']:
        return False, 'pulse_too_old'
    return True, 'ok'


def _run_once(store=None, response=None, candidates=None):
    own = store is None
    store = store or Store()
    cfg = load_config()
    core_cfg, _, _ = load_with_policy()
    override = store.get('operator_otx_policy', {}) or {}
    if type(override.get('enabled')) is bool:
        core_cfg = {**core_cfg, 'otx_enabled': override['enabled']}
    if type(override.get('blocker_mode')) is bool:
        core_cfg = {**core_cfg, 'otx_blocker_mode': override['blocker_mode']}
    # Policy'den OTX ayarları (servis bazlı yönetim).
    otx_cfg = {
        'enabled': bool(core_cfg.get('otx_enabled', False)),
        'blocker_mode': bool(core_cfg.get('otx_blocker_mode', False)),
        'pulse_threshold': int(core_cfg.get('otx_pulse_threshold', 11)),
        'recent_pulse_days': int(core_cfg.get('otx_recent_pulse_days', 14)),
        'require_tls': bool(core_cfg.get('otx_require_tls', True)),
        'match_mode': match_mode(override.get('match_mode', core_cfg.get('otx_match_mode'))),
    }
    if not otx_cfg['enabled'] or not cfg['api_key']:
        record_health(store, {'status':'disabled' if not otx_cfg['enabled'] else 'key_missing','updated_at':time.time(),'tls_verified':False})
        if own: store.close()
        return []
    # Enabling this exact policy grants only its IP-limit operation, like subnet protection.
    response = response or ResponseWorker(store, {**core_cfg, 'response_enabled': bool(otx_cfg['blocker_mode']),
                                                'otx_limit_authorized': bool(otx_cfg['blocker_mode'])})
    cache = store.get('otx_cache', {}) or {}; now = time.time(); results=[]
    record_health(store, {**(store.get('otx_health', {}) or {}), 'status': 'idle', 'updated_at': now})
    try:
        support = remote_support_ips(store)
        ips = sorted(candidates if candidates is not None else peers())
        todo=[]
        for ip in ips:
            try:
                addr=ipaddress.ip_address(ip)
                if not addr.is_global: continue
            except ValueError: continue
            old=cache.get(ip,{})
            if (now-float(old.get('checked',0)) >= cfg['cache_ttl_seconds']
                    or old.get('blocker_mode') != otx_cfg['blocker_mode']
                    or old.get('match_mode') != otx_cfg['match_mode']): todo.append(ip)
            if len(todo) >= cfg['max_queries_per_cycle']: break
        for ip in todo:
            try:
                if ipaddress.ip_address(ip).version == 4:
                    data,tls=request_ipv4(ip,cfg['api_key'])
                else:
                    data,tls=request_indicator(ip,cfg['api_key'],'IPv6')
                item=summarize(ip,data,tls)
                cache[ip]={'checked':now,'pulse_count':item['pulse_count'],'score':item['satsuma_otx_risk_score'],
                           'blocker_mode':otx_cfg['blocker_mode'], 'match_mode':otx_cfg['match_mode']}
                item['decision']='observe'
                item['classification']='indicator'
                item['confidence']='low'
                if item['pulse_count'] >= otx_cfg['pulse_threshold']:
                    item['decision']='review'
                    item['classification']='suspicious'
                    item['confidence']='medium'
                # blocker_mode: OTX tek başına bloker.
                if otx_cfg['blocker_mode']:
                    block_ok, block_reason = _should_block(item, otx_cfg)
                    resolvers=set(core_cfg.get('expected_dns_servers',[]))
                    upstream=(store.get('dns_policy',{}) or {}).get('upstream')
                    if upstream:resolvers.add(upstream)
                    # A reputation feed must not silently remove the resolver
                    # explicitly selected for this host. Keep its indicator for
                    # operator review; do not turn it into an automatic IP block.
                    if ip in resolvers:
                        block_ok=False;block_reason='protected_dns_resolver'
                        item['decision']='review'
                    elif block_ok and ip in support:
                        # The user's remote-support relay: record, never cut.
                        block_ok=False;block_reason='remote_support_peer'
                        item['decision']='review'
                    item['block_eligible'] = block_ok
                    item['block_reason'] = block_reason
                    if block_ok:
                        from .early_guard import read_verdict
                        if not read_verdict().get('response_unlocked'):
                            block_result = {'status': 'boot_integrity_locked'}
                        elif (item.get('tls') or {}).get('verified') is not True:
                            block_result = {'status': 'tls_not_verified'}
                        elif len([stamp for stamp in (store.get('otx_block_attempts', []) or []) if now-stamp < 60]) >= 20:
                            block_result = {'status':'rate_limited'}
                        else:
                            attempts = [stamp for stamp in (store.get('otx_block_attempts', []) or []) if now-stamp < 60]
                            store.set('otx_block_attempts', attempts+[now])
                            # A reputation threshold is an explicit operator policy, not
                            # independent confirmation that the peer is malicious.
                            block_result = response.block_ip(
                                ip, 'Operator OTX '+otx_cfg['match_mode']+' (TLS verified): '+item['reason'],
                                raw_id=None, manual=False)
                        item['block_result'] = block_result.get('status')
                        item['authorization'] = 'operator_otx_'+otx_cfg['match_mode']
                        item['decision'] = 'block' if block_result.get('status') == 'set_membership_confirmed' else 'review'
                        if item['decision'] != 'block':
                            # Do not suppress retries for a full cache TTL after a firewall failure.
                            cache.pop(ip, None)
                        store.add('actions', {'timestamp':time.time(),'source':'otx','action':'otx.indicator_block','ip':ip,
                            'classification':item['classification'], **block_result})
                store.add('otx',item); results.append(item)
                record_health(store, {'status':'active','updated_at':time.time(),'tls_verified':True,
                    'tls_version':tls['version'],'cipher':tls['cipher'],'host':tls['host'],
                    'last_success':time.time(),'last_ip':ip,'last_score':item['satsuma_otx_risk_score'],'last_reason':item['reason']})
            except Exception as exc:
                store.add('errors',{'timestamp':time.time(),'component':'otx','error':str(exc)[:500]})
                record_health(store, {'status':'error','updated_at':time.time(),'tls_verified':False,'error':str(exc)[:300]})
        store.set('otx_cache',cache)
        run_domains(store, cfg, {**core_cfg, 'otx_match_mode': otx_cfg['match_mode']})
        return results
    finally:
        if own: store.close()


def run():
    running=True
    def stop(*_):
        nonlocal running; running=False
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    while running:
        started=time.monotonic()
        try:
            run_once()
        except Exception as exc:
            with_store = Store()
            try:
                record_health(with_store, {'status': 'error', 'updated_at': time.time(), 'error': str(exc)[:300]})
            finally:
                with_store.close()
        while running and time.monotonic()-started < 60: time.sleep(.5)


def request_ipv4(ip, api_key, timeout=8):
    return request_indicator(ip, api_key, 'IPv4', timeout)


def dns_status(store, now=None):
    """What OTX adds to the DNS filter, for the dashboard.

    OTX'in DNS filtresine kattıkları: engellenen alan adı sayısı, son
    denetim ve son hata (ör. blocked.conf yazılamadı).
    """
    now = time.time() if now is None else now
    blocked = store.get('dns_blocked_domains', {}) or {}
    active = [name for name, item in blocked.items() if item.get('source') == 'otx' and item.get('expires_at', 0) > now]
    health = store.get('otx_health', {}) or {}
    return {'blocked': len(active), 'checked': len(store.get('otx_domain_cache', {}) or {}),
            'status': health.get('status'), 'error': health.get('error'),
            'dns_filter': (store.get('dns_filter_health', {}) or {}).get('status')}


def run_domains(store, cfg, core_cfg):
    from .domain_lists import domain
    rows = store.db.execute("SELECT body FROM records WHERE kind='dns' ORDER BY id DESC LIMIT 500").fetchall()
    candidates = set()
    for (body,) in rows:
        try:
            item = json.loads(body)
            name = domain(item.get('query', ''))
            if name and not name.endswith('.arpa') and not remote_support_domain(name) and not update_infra_domain(name):
                candidates.add(name)
        except (ValueError, TypeError):
            continue
    now = time.time()
    cache = store.get('otx_domain_cache', {}) or {}
    blocked = store.get('dns_blocked_domains', {}) or {}
    for name in sorted(candidates, key=lambda name: cache.get(name, {}).get('checked', 0))[:cfg['max_queries_per_cycle']]:
        if (now - cache.get(name, {}).get('checked', 0) < cfg['cache_ttl_seconds']
                and cache.get(name, {}).get('match_mode', 'threshold') == core_cfg.get('otx_match_mode', 'threshold')):
            continue
        try:
            data, tls = request_indicator(name, cfg['api_key'], 'domain')
            summary = summarize(name, data, tls)
            eligible, reason = _should_block(summary, {'require_tls': True,
                'pulse_threshold': core_cfg.get('otx_pulse_threshold', 11),
                'recent_pulse_days': core_cfg.get('otx_recent_pulse_days', 14),
                'match_mode': core_cfg.get('otx_match_mode', 'threshold')})
            cache[name] = {'checked': now, 'eligible': eligible, 'reason': reason,
                           'match_mode': core_cfg.get('otx_match_mode', 'threshold')}
            if eligible:
                blocked[name] = {'checked': now, 'expires_at': now + cfg['cache_ttl_seconds'], 'source': 'otx', 'pulse_count': summary['pulse_count']}
            else:
                blocked.pop(name, None)
            store.add('otx_domains', {'timestamp': now, 'domain': name, 'eligible': eligible, 'reason': reason})
        except Exception as exc:
            store.add('errors', {'component': 'otx_domain', 'domain': name, 'timestamp': now, 'error': str(exc)[:300]})
    store.set('otx_domain_cache', cache)
    before = {name for name, item in (store.get('dns_blocked_domains', {}) or {}).items() if item.get('expires_at', 0) > now}
    kept = {name: item for name, item in blocked.items()
            if item.get('expires_at', 0) > now and not remote_support_domain(name)
            and not (item.get('source') == 'otx' and update_infra_domain(name))}
    store.set('dns_blocked_domains', kept)
    if refresh_due(store, before, set(kept), now):
        from .dnsmasq_control import refresh
        store.set('otx_dns_refreshed_at', now)
        refresh(store)


REMOVAL_REFRESH_SECONDS = 1800


def refresh_due(store, before, after, now):
    """Restart dnsmasq for OTX only when it matters.

    Field 2026-11-04 (2.2.32): every OTX cycle that changed the list
    restarted dnsmasq with the whole Ultimate list; DNS answered nothing
    during the restart and the filter reported "readiness timed out". A
    newly blocked domain applies at once; expired ones are removed at most
    every 30 minutes.
    dnsmasq yalnızca gerekince yeniden başlatılır: yeni engellenen alan adı
    hemen uygulanır, süresi dolanlar en fazla 30 dakikada bir kaldırılır.
    """
    if after - before:
        return True
    if before - after:
        return now - float(store.get('otx_dns_refreshed_at', 0) or 0) >= REMOVAL_REFRESH_SECONDS
    return False


def run_once(store=None, response=None, candidates=None):
    own = store is None
    store = store or Store()
    try:
        return _run_once(store, response, candidates)
    finally:
        if own:
            store.close()
