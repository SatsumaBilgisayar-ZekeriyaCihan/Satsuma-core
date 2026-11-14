#!/usr/bin/env python3
"""satsuma-kur: after the package is installed, set everything up in one terminal session.

User decision 2026-11-10: nothing should have to be typed from memory after
installation. The RPM cannot ask questions, so ``sudo satsuma-kur`` does, in
order, and reports each step as TAMAM or SORUN:

1. tools (taken from the satsuma-omni V62 setup): the scanner signatures
   (freshclam), the Suricata rules and auditd;
2. the desktop user and the first admin password (satsuma-setup);
3. the modem: found automatically, or the MAC typed from its label;
4. the OTX key, optional: network protection works without it;
5. the strictest kernel profile on every installed kernel (grubby);
6. browser policies (from satsuma-omni V62);
7. the full check (tam-kontrol);
8. last, only after Satsuma has made every change: the AIDE snapshot. Taken
   earlier it would record a half-configured system as the reference, and a
   mistake there would be protected from then on (user, 2026-11-10).

A failed step does not stop the following ones; the summary lists it. Every
command is a fixed list, never a shell string.

satsuma-kur: paket kurulduktan sonra her şeyi tek terminal oturumunda kurar.

Kullanıcı kararı 2026-11-10: kurulumdan sonra ezberden komut yazmak
gerekmemeli. RPM soru soramaz; ``sudo satsuma-kur`` sırayla sorar ve her
adımı TAMAM ya da SORUN olarak bildirir: araçlar (satsuma-omni V62
kurulumundan: imzalar, Suricata kuralları, auditd), masaüstü kullanıcısı ve
ilk yönetici parolası, modem, isteğe bağlı OTX anahtarı, en sıkı çekirdek
profili, tarayıcı politikaları (V62), tam kontrol ve en son, Satsuma bütün değişiklikleri yaptıktan sonra
AIDE örneği. Daha önce alınsaydı yarım yapılandırılmış sistemi referans
kaydederdi ve oradaki bir hata bundan sonra korunurdu (kullanıcı, 2026-11-10). Başarısız adım sonrakileri
durdurmaz; özet onu listeler. Her komut sabit bir listedir, kabuk dizgisi
değildir.
"""
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path

PYTHON = ['/usr/bin/python3', '-X', 'pycache_prefix=/run/satsuma-python-cache', '-I', '-B']
AIDE_DB = Path('/var/lib/satsuma-core/aide/aide.db.gz')
MAC = re.compile(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$')


class Setup:
    def __init__(self, runner=subprocess.run, ask=input, say=print, exists=os.path.exists,
                 environ=os.environ, user_exists=None):
        self.runner, self.ask, self.say, self.exists, self.environ = runner, ask, say, exists, environ
        self.user_exists = user_exists or _user_exists
        self.results = []

    # -- helpers ---------------------------------------------------------
    def run(self, argv, interactive=False, timeout=1800, cwd=None):
        """Run a fixed command; interactive ones keep the terminal for their own questions."""
        extra = {'cwd': cwd} if cwd else {}
        try:
            if interactive:
                return self.runner(argv, timeout=timeout, **extra).returncode == 0
            result = self.runner(argv, capture_output=True, text=True, timeout=timeout, **extra)
            if result.returncode != 0:
                self.say('   ' + ((result.stderr or result.stdout or '').strip().splitlines() or ['hata'])[-1][:300])
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError) as exc:
            self.say('   ' + str(exc)[:300])
            return False

    def step(self, name, ok, detail=''):
        self.results.append((name, bool(ok), detail))
        self.say(('[TAMAM] ' if ok else '[SORUN] ') + name + (': ' + detail if detail else ''))

    def yes(self, question, default=False):
        answer = self.ask(question + (' [E/h] ' if default else ' [e/H] ')).strip().lower()
        return default if not answer else answer in ('e', 'evet', 'y', 'yes')

    # -- 1. tools ----------------------------------------------------------
    def tools(self):
        self.say('\n1/8 Araçlar kuruluyor ve yapılandırılıyor')
        self.step('ClamAV imzaları (freshclam)', self.run(['/usr/bin/freshclam', '--quiet']))
        self.step('Suricata kuralları', self.run(['/usr/bin/suricata-update', '--no-test']))
        self.step('auditd', self.run(['/usr/bin/systemctl', 'enable', '--now', 'auditd.service']))

    # -- 7. AIDE snapshot, last ----------------------------------------------------
    def snapshot(self):
        self.say('\n8/8 AIDE örneği (Satsuma bütün ayarları yaptıktan sonra)')
        failed = [name for name, ok, _ in self.results if not ok]
        if failed:
            # A reference taken over a failed step would protect the failure.
            self.step('AIDE örneği', False, 'alınmadı: önce şu adımlar düzelmeli: ' + ', '.join(failed))
            return
        if self.exists(str(AIDE_DB)) and not self.yes('Önceki AIDE örneği var. Bugünkü durumla değiştirilsin mi?'):
            self.step('AIDE örneği', True, 'önceki örnek korundu')
            return
        self.say('   AIDE örneği ve ayar kopyaları hazırlanıyor; bu birkaç dakika sürebilir.')
        ok = self.run(['/usr/bin/satsuma-admin', 'aide', 'ornek-al'], timeout=7200)
        ok = ok and self.run(['/usr/bin/systemctl', 'enable', '--now', 'satsuma-aide-check.timer'])
        self.step('AIDE örneği', ok, 'Satsuma ayarlarından sonraki durum; saatlik karşılaştırılır, değişiklik '
                  'sudo satsuma-admin aide geri-al <yol> ve Satsuma yönetici parolasıyla geri alınır. '
                  'Önceden temiz olduğunu kanıtlamaz')

    # -- 2. user and password ------------------------------------------------
    def account(self):
        self.say('\n2/8 Masaüstü kullanıcısı ve yönetici parolası')
        default = self.environ.get('SUDO_USER') or ''
        if default == 'root':
            default = ''
        while True:
            name = self.ask('Satsuma panelini kullanacak masaüstü kullanıcısı' + (f' [{default}]' if default else '') + ': ').strip() or default
            if name and name != 'root' and self.user_exists(name):
                break
            self.say('   Var olan, root olmayan bir kullanıcı adı yazın.')
        self.say('   Parola yoksa şimdi sorulur; yazdıklarınız ekranda görünmez.')
        self.step('Kullanıcı ve yönetici parolası', self.run(['/usr/bin/satsuma-setup', '--user', name], interactive=True), name)

    # -- 3. modem ----------------------------------------------------------------
    def modem(self):
        self.say('\n3/8 Modem')
        if self.run(['/usr/bin/satsuma-admin', 'modem']):
            self.step('Modem', True, 'otomatik tanındı ve kaydedildi')
            return
        self.say('   Modem otomatik tanınamadı. MAC adresi modemin altındaki etikette yazar (ör. a8:9a:93:12:34:56).')
        for _ in range(3):
            mac = self.ask('Modem MAC adresi (boş bırakırsanız sonra panelden onaylarsınız): ').strip()
            if not mac:
                break
            if MAC.match(mac):
                self.step('Modem', self.run(['/usr/bin/satsuma-admin', 'modem', '--mac', mac]), mac.lower())
                return
            self.say('   Biçim xx:xx:xx:xx:xx:xx olmalı.')
        self.step('Modem', False, 'onaylanmadı; Yönetim → Ağ koruması bölümünden onaylayın')

    # -- 4. OTX ------------------------------------------------------------------
    def otx(self):
        self.say('\n4/8 OTX anahtarı (isteğe bağlı; ağ koruması OTX olmadan da çalışır)')
        if not self.yes('OTX API anahtarını şimdi girmek ister misiniz?'):
            self.results.append(('OTX anahtarı', True, 'atlandı'))
            self.say('[ATLANDI] OTX anahtarı')
            return
        self.step('OTX anahtarı', self.run(['/usr/bin/satsuma-admin', 'set-otx-key'], interactive=True))

    # -- 5. kernel profile -----------------------------------------------------------
    def kernel(self):
        self.say('\n5/8 En sıkı çekirdek profili (kurulu bütün çekirdeklere)')
        ok = self.run(['/usr/bin/systemctl', 'start', 'satsuma-kernel-profile.service'])
        self.step('Çekirdek açılış ayarları', ok, 'yeniden başlatınca etkin olur; değişirse Satsuma geri koyar')
        self.run(['/usr/bin/journalctl', '-u', 'satsuma-kernel-profile.service', '-n', '3', '--no-pager', '-o', 'cat'], interactive=True, timeout=30)

    # -- 6. browser policies -----------------------------------------------------------
    def browser(self):
        self.say('\n6/8 Tarayıcı politikaları (Firefox, Chrome, Chromium)')
        ok = self.run(['/usr/bin/python3', '-X', 'pycache_prefix=/run/satsuma-python-cache', '-E', '-s', '-B',
                       '-m', 'satsuma.browser_policy'], cwd='/opt/satsuma-core')
        self.step('Tarayıcı politikaları', ok, 'açık tarayıcıları yeniden başlatın; yalnızca HTTPS, http:// adresleri engelli')

    # -- 7. full check --------------------------------------------------------------------
    def check(self):
        self.say('\n7/8 Tam kontrol')
        self.step('Tam kontrol', self.run(['/usr/bin/satsuma-admin', 'tam-kontrol'], interactive=True))

    def all(self):
        self.say('Satsuma kurulumu: her adım sırayla yapılır; ezberden komut yazmanız gerekmez.')
        for part in (self.tools, self.account, self.modem, self.otx, self.kernel, self.browser, self.check, self.snapshot):
            part()
        failed = [name for name, ok, _ in self.results if not ok]
        self.say('\nÖzet: ' + ('bütün adımlar tamam.' if not failed else 'sorunlu adımlar: ' + ', '.join(failed)
                 + '. Yeniden denemek için: sudo satsuma-kur'))
        self.say('Çekirdek ayarlarının tamamı için bilgisayarı yeniden başlatın.')
        return 0 if not failed else 1


def _user_exists(name):
    try:
        return pwd.getpwnam(name).pw_uid >= 1000
    except KeyError:
        return False


def main():
    if os.geteuid() != 0:
        print('Kullanım: sudo satsuma-kur', file=sys.stderr)
        return 2
    try:
        return Setup().all()
    except (KeyboardInterrupt, EOFError):
        print('\nKurulum yarıda kesildi. Yeniden başlatmak için: sudo satsuma-kur', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
