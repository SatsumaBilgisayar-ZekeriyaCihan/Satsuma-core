# Fedora 44 bellek koruması kurulumu

Bu rehber 2.1.6 bellek koruması ve imzalı Fedora RPM yayını içindir. Mevcut
GitHub main veya önceden indirilmiş 2.1.6 RPM bu değişiklikleri içermeyebilir.
Sürüm numarası değiştirilmedi: doğru kaynaktan derlenmiş RPM ve dosya özetleri
ile kurulum yapılmalıdır. Yayın dosyaları GitHub ana sayfasındaki indirme dizininde bulunur.

Teslim paketi SatsumaBilgisayar anahtarıyla detached GPG imzası taşır. Önce
tam parmak izini doğrulayın ve dış arşivin `.asc` imzasını kontrol edin;
adımlar SATSUMA-SIGNING.md belgesindedir. İmzalı dış arşiv ile imzalı bir RPM
aynı şey değildir: RPM ayrıca rpmsign ile imzalanıp rpmkeys ile doğrulanmalıdır.

Bu paketin yaptığı işler: erken boot bellek erişim kısıtları, /dev ve /dev/shm
çalıştırma kısıtları, ana executable RAM kodu karşılaştırması ve doğrulanmış
kod bütünlüğü ihlalinde otomatik süreç sonlandırma. Tüm fiziksel RAM'i
şifrelemez ve aktif eBPF LSM müdahale programı içermez. TPM anahtar mühürleme
mekanizması eklenmemiştir.

## 1. Kaynağı ve yerel araçları hazırlama

Değişiklikleri içeren kaynak arşivi ile SHA256SUMS aynı dizinde olmalıdır.
Önceden kurulu uygulamayı /opt altında elle değiştirmeyin: Satsuma paket
bütünlüğü denetimi elle değiştirilen dosyaları reddeder.

```bash
sha256sum -c SHA256SUMS
tar -xzf satsuma-core-2.1.6.tar.gz
cd satsuma-core-2.1.6
rpm -q rpm-build cpio tar gzip gcc python3 python3-pytest \
  python3-pydantic python3-psutil python3-pyyaml python3-jsonschema \
  python3-pyqt6-base squashfs-tools libnetfilter_queue systemd
```

Bağımlılıklar mevcutsa sonraki adıma geçin. Eksik paketler yerel DNF cache'inde
bulunuyorsa aşağıdaki komut internet kullanmadan kurar:

```bash
sudo dnf --cacheonly install rpm-build cpio tar gzip gcc python3 python3-pytest \
  python3-pydantic python3-psutil python3-pyyaml python3-jsonschema \
  python3-pyqt6-base squashfs-tools libnetfilter_queue systemd
```

Cache eksikse bu komut başarısız olur; cache dışı indirme yapılmaz. İnternet
üzerinden kurulum ayrı izin ve bağlantı gerektirir. Buluttaki ajan, kullanıcı
internet erişimini yasakladıktan sonra indirme yapmamıştır.

## 2. Davranışı kurulumdan önce test etme

Kaynak arşivinin kökünde:

```bash
PYTHONPATH=. QT_QPA_PLATFORM=offscreen python3 -m pytest -q \
  tests/test_memory_validation.py tests/test_memory_access.py \
  tests/test_memory_hardening.py tests/test_memory_mounts.py \
  tests/test_hardware_memory.py tests/test_auto_process.py tests/test_memory_status.py \
  tests/test_release_install.py
```

Bu testler host mount veya sysctl ayarlarını değiştirmez. Core dump kapatma
testi yalnızca kendi alt sürecini non-dumpable yapar. Bellek testleri geçici
bir C programı derler, programın kendi kodunu değiştirmesini sağlar ve yalnızca
kendi başlattığı süreçte gerçek SIGTERM/SIGKILL ile sonlandırmayı kontrol eder.
GCC yoksa canlı C testi skipped olur; skipped sonucu başarıyla eş tutulmaz.

Normal executable kodu eşleşmeli, değiştirilmiş kod CODE_MISMATCH olmalı,
kural/normalizasyon/Brain yolu üzerinden test süreci gerçekten çıkmalıdır.
Sahte mismatch etiketi normal süreci sonlandırmamalıdır.

Tüm regresyonlar için:

```bash
PYTHONPATH=. QT_QPA_PLATFORM=offscreen python3 -m pytest -q tests
```

Başlangıç main sürümünde üç eski gelen-trafik beklentisi ve bir eski candidate
RPM release beklentisi olmak üzere dört test zaten başarısızdı. Bunlar bu
değişiklikte kapatılmadı veya başarı gibi gösterilmedi. Yeni bir hata görülürse
kuruluma geçmeden inceleyin.

## 3. Fedora 44 RPM derleme

Fedora 44 x86_64 makinesinde, kaynak arşivi kökünde:

```bash
SATSUMA_RPM_BUILD_ROOT="$HOME/satsuma-build/rpmbuild" bash packaging/build.sh
rpm -K "$HOME/satsuma-build/rpmbuild/RPMS/x86_64/satsuma-core-2.1.6-1.fc44.x86_64.rpm"
rpm -qp --queryformat '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' \
  "$HOME/satsuma-build/rpmbuild/RPMS/x86_64/satsuma-core-2.1.6-1.fc44.x86_64.rpm"
rpm -qpl "$HOME/satsuma-build/rpmbuild/RPMS/x86_64/satsuma-core-2.1.6-1.fc44.x86_64.rpm" \
  | rg 'memory_(access|validation|hardening)|memory-hardening.service|memory_integrity.yaml'
```

`rg` yoksa son komutta `grep -E` kullanılabilir. `rpm -K` digest denetimi ile
GPG imza doğrulaması ayrı sonuçlardır. İmzasız yerel RPM için imzalı ürün
iddiasında bulunmayın; TLS/GPG kontrollerini devre dışı bırakan seçenekler
kullanmayın. Kurumsal dağıtımda RPM mevcut güvenilir paket anahtarıyla
imzalanmalıdır.

## 4. Yedek ve kurulum

Yerel konsol erişimiyle uygulayın. Bu politika normal kullanıcı debugger
erişimini, core dump üretimini ve /dev/shm üzerinden executable kullanımını
sınırlar. Önce geri dönebileceğiniz önceki RPM'i saklayın. İşletim sistemi
ayarlarının ilk hali ayrıca hardening uygulanmadan önce otomatik kaydedilir:
`/var/lib/satsuma-core/memory-hardening/initial.json`.

```bash
sudo install -d -m 0700 /root/satsuma-before-memory-update
sudo cp -a /etc/satsuma-core /root/satsuma-before-memory-update/
sudo rpm -q satsuma-core
```

Kurulu sürümle aynı NEVRA yeniden derlendiği için, mevcut kurulumda:

```bash
sudo dnf --cacheonly reinstall \
  "$HOME/satsuma-build/rpmbuild/RPMS/x86_64/satsuma-core-2.1.6-1.fc44.x86_64.rpm"
```

Satsuma henüz kurulu değilse `reinstall` yerine `install` kullanın. Eksik
runtime bağımlılıkları cache'de yoksa ağ üzerinden indirme yapılmadan işlem
durur. Paket scriptleri mevcut Satsuma ağ/IPS/masaüstü kurulumunu da yürütür;
bu yalnızca tek bir Python dosyasını kopyalama işlemi değildir.

RPM `%config(noreplace)` nedeniyle mevcut politika korunur. Etkin süreç
sonlandırma için `/etc/satsuma-core/config.json` içinde
`auto_action_process_enabled: true` bulunmalı; etkin response politikasında
`enabled: true`, destructive `enabled: true` ve `allowed_actions` içinde
`process_kill` olmalıdır. `policy.json` içindeki yapı
`workers.response.destructive` altındadır. Diğer ayarları silmeden mevcut
yapılandırmayı düzenleyin. Uygulama ayarlarıyla operatör duraklatmasını
kaldırmadan otomatik aksiyon çalışmaz.

```bash
sudo systemctl restart satsuma-memory-hardening.service satsuma-early-guard.service
sudo systemctl restart satsuma-core.service satsuma-teams.service
```

## 5. Korumanın uygulandığını doğrulama

```bash
sudo systemctl status satsuma-memory-hardening.service satsuma-early-guard.service --no-pager
sudo python3 -I -B /opt/satsuma-core/installer/boot_setup.py --check-memory
sudo sysctl kernel.yama.ptrace_scope kernel.kptr_restrict kernel.dmesg_restrict fs.suid_dumpable kernel.core_pattern
findmnt -no TARGET,FSTYPE,OPTIONS /dev
findmnt -no TARGET,FSTYPE,OPTIONS /dev/shm
sudo journalctl -b -u satsuma-memory-hardening.service -u satsuma-early-guard.service --no-pager
```

Beklenen: ptrace_scope=2 (önceden 3 ise korunur), kptr_restrict=2,
dmesg_restrict=1, suid_dumpable=0, core_pattern=`|/usr/bin/false`.
/dev için devtmpfs,nosuid,noexec; /dev/shm için tmpfs,nosuid,nodev,noexec.
/dev üzerine nodev EKLENMEZ. `--check-memory` yalnızca okur; ayar değiştirmez
ve kontrollerden biri başarısızsa sıfır olmayan çıkış kodu verir.

Sonrasında yeniden başlatıp aynı kontrolleri tekrarlayın. Bu adım, gerçek
Fedora boot entegrasyonunun kabul testidir; bulut kaynak testleri bu adımın
yerine geçmez. SELinux enforcing durumunu koruyun. Erişim hatasında
`sudo ausearch -m AVC -ts boot` ile ilgili engeli inceleyin; SELinux'u kapatmayın.

RAM panelinde Kod eşleşen, Kod farkı, Bellek erişimi reddedilen ve Eksik
doğrulama ayrı görünmelidir. Eski kayıtlarda “yalnızca üstveri” yazmalıdır.
CODE_MATCH tüm RAM temiz anlamına gelmez. Başarılı müdahale için aksiyon
kaydında `action: process.terminate`, `status: terminated`,
`exit_verified: true` aranmalıdır; yalnızca `authorized` veya sinyal gönderimi
süreç çıkışı kanıtı değildir.

## 6. Geri alma

Core/teams ve onları tekrar başlatabilecek guardian/self-health süreçlerini
bakım için durdurun; bu sırada Satsuma'nın aktif müdahalesi çalışmaz.

```bash
sudo systemctl stop satsuma-self-health.timer satsuma-self-health.service \
  satsuma-guardian.service satsuma-core.service satsuma-teams.service \
  satsuma-early-guard.service satsuma-memory-hardening.service
sudo systemctl mask --runtime satsuma-memory-hardening.service
sudo python3 -I -B /opt/satsuma-core/installer/boot_setup.py --restore-memory
```

Komut yalnızca saklanan ilk mount/sysctl politikasını geri yükler ve tekrar
okuyarak doğrular. Başarı sonucu ORIGINAL_MEMORY_POLICY_RESTORED'dur. İlk
yedek yoksa varsayılan ayarlar uydurulmaz. ptrace_scope=3 mevcutsa reboot
gerekmeksizin gevşetilemez; araç bunu hata olarak bildirir.

Ardından sakladığınız önceki RPM'i DNF'nin yerel `reinstall` veya `downgrade`
işlemiyle geri yükleyin; aynı sürüm numarasında `reinstall` gerekir. Runtime
mask reboot'a kadar sürer. Yeni paketle kalmaya devam edip yalnızca hardening
servisini maskelerseniz early guard doğrulamayı geçemez ve otomatik müdahale
kilitli kalır. Kalıcı geri dönüş için önceki güvenilir paketi geri yükleyin.

## Donanım şifreleme ve TPM

Donanım kontrolü salt okunurdur:

```bash
sudo python3 -I -B /opt/satsuma-core/installer/boot_setup.py --memory-encryption-status
systemd-creds has-tpm2
```

TPM bulunması anahtar mühürleme olanağıdır; tüm fiziksel RAM şifrelemesi
anlamına gelmez. Bildirilen Ryzen 5 5500 lscpu çıktısında SME/SEV bayrağı
bulunmadığı için bu yapılandırmada donanım RAM şifrelemesi doğrulanmamıştır.
Bu geliştirme BIOS'u, bootloader'ı, disk bölümlerini, swap'ı veya TPM PCR
politikasını değiştirmez.
