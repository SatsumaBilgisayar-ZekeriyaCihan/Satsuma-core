"""One-way kernel module loading lock, applied after boot services settle.

Wired in 2.2.30 (it was never run before; user report 2026-11-04): the
satsuma-module-lock timer runs it three minutes after boot. Modules that
Satsuma's own features load later (WireGuard, nftables matches used by
App Control and OpenSnitch) are loaded first, because once locked nothing
can be loaded until the next reboot. A device plugged in afterwards whose
driver is not loaded yet will not work until reboot; that is the point.

Tek yönlü çekirdek modülü yükleme kilidi; açılış servisleri oturduktan sonra
uygulanır. 2.2.30'da bağlandı (daha önce hiç çalışmıyordu; kullanıcı bildirimi
2026-11-04): satsuma-module-lock zamanlayıcısı onu açılıştan üç dakika sonra
çalıştırır. Satsuma'nın kendi özelliklerinin sonradan yüklediği modüller
(WireGuard, App Control ve OpenSnitch'in kullandığı nftables eşleşmeleri)
önce yüklenir; kilitten sonra yeniden başlatmaya kadar hiçbir modül
yüklenemez. Sonradan takılan ve sürücüsü yüklü olmayan bir aygıt yeniden
başlatmaya kadar çalışmaz; amaç da budur.
"""
import os
import time
from pathlib import Path

from .host_store import HostStore

CONTROL=Path('/proc/sys/kernel/modules_disabled')
# Loaded before the lock: WireGuard, NFQUEUE and the nftables pieces Satsuma,
# App Control and OpenSnitch add rules with later.
PRELOAD=('wireguard','nfnetlink_queue','nft_queue','nft_ct','nft_socket','nft_reject_inet','nft_nat','nft_redir','xt_mark')


def preload(runner=None):
    import subprocess
    runner=runner or subprocess.run
    loaded=[]
    for name in PRELOAD:
        if runner(['/usr/sbin/modprobe','-q',name],capture_output=True,text=True,timeout=20).returncode==0:loaded.append(name)
    return loaded


def lock(path=CONTROL):
    path=Path(path);before=path.read_text(encoding='ascii').strip()
    if before not in ('0','1'):raise RuntimeError('Beklenmeyen kernel.modules_disabled değeri: '+before)
    if before=='0':
        fd=os.open(path,os.O_WRONLY|os.O_CLOEXEC)
        try:os.write(fd,b'1\n')
        finally:os.close(fd)
    after=path.read_text(encoding='ascii').strip()
    if after!='1':raise RuntimeError('Çekirdek modül kilidi doğrulanamadı')
    return {'timestamp':time.time(),'status':'LOCKED','before':before,'after':after,
            'reversible':'reboot_required','control':str(path)}


def run(store=None):
    from satsuma.runtime_user import require_service_user; require_service_user()
    own=store is None;store=store or HostStore()
    try:
        try:
            loaded=preload()
            result={**lock(),'preloaded':loaded}
        except Exception as exc:
            result={'timestamp':time.time(),'status':'ERROR','error':str(exc)[:500],'control':str(CONTROL)}
        store.add('module_lock',result);store.set('module_lock_health',result)
        if result['status']!='LOCKED':raise RuntimeError(result['error'])
        return result
    finally:
        if own:store.close()


if __name__=='__main__':
    run()
