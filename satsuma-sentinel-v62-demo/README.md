# Satsuma Mini — deneme betiği

Bu dosya, ana SatsumaSecurity 2.2.35 ürününden ayrı bir deneme betiğidir. Ana ürünün yerine kurulmaz. Depodan inen dosyanın adı `satsuma-omni-sentinel-v62-fedora-hardened.sh`; kurulunca `/usr/local/bin/satsuma-mini` komutu olur.

## İndirme

[satsuma-omni-sentinel-v62-fedora-hardened.sh](https://github.com/SatsumaBilgisayar-ZekeriyaCihan/Satsuma-Mini/raw/main/satsuma-omni-sentinel-v62-fedora-hardened.sh) — bu depo özeldir; link, depoya erişimi olan GitHub hesabıyla açılır.

## Kurulum (tek komut)

İndirilen dosyanın bulunduğu dizinde. Firefox aynı adlı eski bir dosya varsa yenisini `(1)` ekiyle kaydeder; önce eskisini silin ve `sha256sum satsuma-omni-sentinel-v62-fedora-hardened.sh` ile özeti kontrol edin:

```sh
sudo env SATSUMA_CONFIRM_FULL=YES /bin/bash -p ./satsuma-omni-sentinel-v62-fedora-hardened.sh --install-service
```

Betik sözdizimini denetler, kendini root'a ait `/usr/local/bin/satsuma-mini` olarak kurar, kısa komutları yazar ve `satsuma-mini` servisini başlatır. Servis her açılışta `--full` kurulumunu doğrular, sonra ana döngüyü çalıştırır; başarısız olursa 60 saniyede bir, saatte en fazla 5 kez yeniden dener. İlerleme `journalctl -u satsuma-mini -f` ile izlenir. Yeni sürüme geçmek için aynı komut yeni dosyayla yeniden çalıştırılır.

Kurulum sırasında saatlik dosya taraması duraklatılır (ClamAV yapılandırma adımı tarama kilidini bekler) ve kurulumun sonunda yeniden başlar; kurulum başarısız olursa da yeniden başlatılır.

## Canlı oturum ve kurulu sistem

Aynı betik iki sürüm olarak çalışır ve hangisinde olduğunu kendisi ayırt eder (`/run/initramfs/live`, `/run/live/medium` ya da çekirdek satırında `rd.live.image` / `boot=live` varsa canlı oturum). Fark yalnızca AIDE'dedir:

- **Canlı oturum:** 2026-11-10 kuralı geçerlidir. Bu oturumun önceki AIDE örneğinden fark varsa kurulum durur ve farkı gösterir.
- **Kurulu sistem:** Fark alarm olarak journal'a ve panoya yazılır, tam rapor `/var/log/satsuma/aide-fark/` altına kaydedilir, korumalar çalışmaya devam eder. Önceki örnek kullanıcı onaylayana kadar değiştirilmez; ana döngünün 10 dakikalık AIDE denetimi de fark onaylanana kadar her seferinde bildirir. `satsuma-aide` farkı gösterir; `satsuma-aide onayla` EVET onayıyla yeni örnek alır ve eskisini `aide.db.gz.onceki-*` olarak saklar.

## Yerel ClamAV özet veritabanı

Dosya taramasının bir imzaya takılan her dosyası SHA-256 özeti ve boyutuyla `/var/lib/clamav/satsuma-yerel.hsb` dosyasına `Satsuma.Yerel.<özgün imza>` adıyla eklenir ve clamd yeniden yüklenir. Böylece aynı içerik, özgün imza değişse ya da kaldırılsa bile yakalanır. Kayıtlar `/var/log/satsuma/yerel-imzalar.json` içinde ilk görülme zamanı ve yoluyla tutulur.

Daha önce işaretlenmiş bir özet ya da yol, önceki tam taramada yokken yeniden görülürse alarm verilir: `[TEKRAR] Daha once tespit edilen dosya yeniden goruldu, incelenmeli`. Alarm panoda, `satsuma-log`'da ve `file-events.jsonl` içindedir. Özellik eklenmeden önce işaretlenen yollar tarama günlüğünden alınır; bu dosyaların özeti o zaman kaydedilmediği için yalnızca yol olarak hatırlanır, yeniden görüldüklerinde özetleri de eklenir.

## Sembolik bağlar

Tarayıcı sembolik bağın içinden yürümez. Hedefi tarama köklerinden (`/home /tmp /var /usr/bin /usr/sbin /usr/local/bin /etc /opt`) birinde olan bağ, hedef kendi yerinde tarandığı için ayrıca taranmaz. Hedefi bu köklerin dışında olan dosya bağı izlenir ve hedef taranır; hedefin bulunduğu klasördeki bütün normal dosyalar da taranır (tek seviye; alt klasörler ve oradaki bağlar daha ileri izlenmez). Kök dışını gösteren klasör bağında o klasörün dosyaları taranır. Eşleşme olursa kayıt hem hedefi hem bağı (`linked_from`) gösterir ve dosya otomatik karantinaya alınmaz, incelemeye düşer. Kırık bağ ve normal dosya olmayan hedef "incelenmeli" olarak kalır. Soket ve FIFO'nun içeriği olmadığı için sayılır, hata sayılmaz.

## Kısa komutlar

| Komut | Ne yapar |
|---|---|
| `satsuma-dashboard` | Canlı pano (salt okunur) |
| `satsuma-durum` | Satsuma servislerinin durumu ve tarama özeti |
| `satsuma-clamav` | Dosya taraması durumu; `satsuma-clamav tara` yeni döngü başlatır |
| `satsuma-suricata` | Suricata durumu, IPS yapı denetimi, son 20 alarm |
| `satsuma-ram` | RAM35 bellek izleyicisi durumu |
| `satsuma-log` | Satsuma servis günlüklerini canlı izler |
| `satsuma-aide` | Onay bekleyen AIDE farkını gösterir; `satsuma-aide onayla` yeni örnek alır |

Komutlar root gerektirdiğinde kendilerini `sudo` ile yeniden çalıştırır.

## Elle kurulum (servis olmadan, tek seferlik)

Her satır başarılı olduktan sonra sonrakini çalıştırın:

```sh
/bin/bash -p -n ./satsuma-omni-sentinel-v62-fedora-hardened.sh
sudo install -o root -g root -m 0750 ./satsuma-omni-sentinel-v62-fedora-hardened.sh /usr/local/bin/satsuma-mini
sudo env SATSUMA_CONFIRM_FULL=YES /bin/bash -p /usr/local/bin/satsuma-mini --full
```

Komutlar betiğin `--help` çıktısında da bulunur. `/usr/local/sbin` yerine tek kurulum yolu `/usr/local/bin/satsuma-mini` kullanılır. `SATSUMA_CONFIRM_FULL=YES` ortam değişkenidir; `--full` sonuna eklenen bir argüman değildir.

## Bu düzeltmedeki değişiklikler

- Audit, `/etc/resolv.conf` bağlantısının işaret ettiği iki bilinen systemd-resolved çalışma dosyasını servis kullanıcısına ait oldukları için reddetmez. Sahiplikleri değiştirilmez. Çalışan sistemde izlenirler; erken açılışta henüz bulunmayabilecek `/run/` yolları kalıcı audit kuralına yazılmaz. Diğer hedeflerde sahiplik denetimi sürer. Başka uygulamaların audit kuralları topluca silinmez.
- SELinux incelemesi, değiştirmeden önce durum, etiket ve yakın AVC kayıtlarını `/var/log/satsuma/selinux/check-*/` altında yalnız root tarafından okunabilen dosyalara kaydeder. İki sabit dosyanın (`/etc/ld.so.cache`, `/etc/selinux/config`) etiketleri dağıtım politikasına göre düzeltilir. Yönetilen servis ve yapılandırma dosyalarına da beklenen etiketler uygulanır. ISO'nun bu etiketlere nasıl geldiği bu işlemle kanıtlanmış olmaz.
- SELinux çalışma durumu ve `/etc/selinux/config` enforcing olur; sonuç okunarak doğrulanır. `domain_can_mmap_files` kalıcı olarak **off** tutulur. `audit2allow` modülü üretilmez, genel izin boolean'ları açılmaz. Yüklenmemiş/Disabled SELinux çalışan çekirdekte açılmış gibi gösterilmez: işlem açıklayıcı hatayla durur. Debian/Ubuntu desteği burada SELinux politikasının zaten yüklü ve etkin olmasını gerektirir; varsayılan AppArmor kurulumu bu koşulu sağlamaz.
- SatsumaSecurity **2.2.35**, kaynak commit `b6ee6d3d37355badc8dca6f16ff4433ac0cff64d`, Unlicense kaynaklarından `ram/proc.py`, `ram/clamd.py`, `ram/engine.py`, `memory_validation.py`, `memory_mounts.py`, `memory_access.py` uyarlanmıştır. Qt, ayrıcalık aracı ve otomatik süreç sonlandırma zinciri aktarılmamıştır.
- RAM35; uygun süreç eşlemelerinde tur başına en fazla 4 MiB okur, 1 MiB parçalar ve 64 KiB örtüşme kullanır. Süre bütçesi 2 saniyedir. Ayrı yerel Unix soketli clamd ile imza sorgular; soket sahipliği ve bağlanılan sürecin kimliği doğrulanır. Değişen süreç/eşleme veya tekrarlanamayan imza kesin bulgu sayılmaz. Kod sayfası farkı tek başına zararlı yazılım teşhisi değildir. Bulgu kaydı inceleme içindir; otomatik süreç öldürme yapılmaz.
- RAM35 için yeni capability, SELinux allow kuralı veya daha gevşek ptrace ayarı verilmez. Mevcut `ptrace_scope=3` korunur ve tarama **BLOCKED** raporlanır. Erişilemeyen alanlar temiz sayılmaz. `/dev` üzerine `nosuid,noexec`; `/dev/shm` üzerine `nosuid,nodev,noexec` uygulanır. `/dev` için `nodev` eklenmez. Çekirdek adres/sızıntı ve core dump sınırları uygulanır. Bu fiziksel RAM şifreleme veya tüm RAM'in taranması değildir.
- RAM35 özel clamd ve izleyici servisleri ayrı çalışır. Özel clamd bellek üst sınırı 2 GiB; izleyici üst sınırı 384 MiB'dır. Bunlar ayrılmış bellek miktarı değildir. Dosya tarama için mevcut clamd da çalıştığından toplam kaynak tüketimi cihaz üzerinde ölçülmelidir.
- AIDE ilk veritabanı hazırlanırken kurulum bekler ve ilerlemeyi ekrana yazar. Fedora'nın `/etc/aide.conf` yolu kullanılır. İlk veritabanı sistemin o andaki durumudur; önceden temiz olduğunu kanıtlamaz.

## Durum komutları

```sh
sudo /bin/bash -p /usr/local/bin/satsuma-mini --selinux-audit
sudo /bin/bash -p /usr/local/bin/satsuma-mini --memory35-status
sudo /bin/bash -p /usr/local/bin/satsuma-mini --verify-ips
sudo /bin/bash -p /usr/local/bin/satsuma-mini --dashboard
```

`--selinux-audit` politika değiştirmez; korumalı yerel inceleme kaydı yazar. `--selinux-enforce` etiket/boolean/enforcing ayarlarını uygular. `--memory35-scan` bir sınırlı tur yapar. Dashboard RAM35 durumunun yaşını ve Suricata'nın kendi `ips.blocked` sayacını gösterir; eksik veya eski veriyi başarı saymaz.

## Ağ davranışı

Suricata NFQUEUE, güvenlik duvarı kararından sonra çalışır; kuyrukta bypass yoktur. `--verify-ips` yapı ve kuyruk sahipliği denetimidir. Gerçek paket düşürme kanıtı değildir; `packet_drop_proven:false` bu nedenle korunur. ET/Open `alert` kurallarının hepsi `drop` kuralına çevrilmez.

Fast.log P1/P2/P3 TCP olaylarında kalıcı IP engeli için aynı SID/uçlar ile güncel EVE olayı, iki yönlü akış ve canlı TCP bağlantısı aranır. UDP olayları kalıcı IP engeli için inceleme kaydıdır; Suricata'nın paket üzerindeki IPS kararı sürer. Böylece sahte UDP alarmıyla kalıcı IP engeli oluşturulması önlenir.

Kullanıcının seçimi gereği 30 toplam etkin TCP/bağlı UDP bağlantısında tüm ağ bağlantıları kilitlenir. Aynı `/24` içinde 10 farklı bağlı IP, altyapı istisnaları dışında o alt ağı engeller. Normal tarayıcı trafiği de 30 eşiğine ulaşabilir. Ağ kilidi yerelden kaldırılır:

```sh
sudo /bin/bash -p /usr/local/bin/satsuma-mini --network-reset
```

RAM35 için son kontrolde özel clamd soketinin yanıtı ve çalışan izleyicinin gerçekten clamd’ye gönderdiği yakın tarihli süreç belleği baytları aranır. Bunlar doğrulanamazsa veya `ptrace_scope=3` ise kurulum modül kilidine ilerlemez; izinler gevşetilmez. Bu örnek işleme teyidi tüm RAM kapsamı anlamına gelmez. Kontrol ayrıca `--memory35-preflight` ile çalıştırılabilir.

Kurulumun son adımı çekirdek modülü yükleme/kaldırmayı yeniden başlatılana kadar kapatır. Sonradan gerekli olacak aygıt/VPN modülleri daha önce yüklenmiş olmalıdır. Live ISO üzerinde `/etc` ve servis değişikliklerinin yeniden başlatma sonrası korunması kalıcı depolamaya bağlıdır.

## Doğrulanan kapsam

Bu sürümde Bash sözdizimi ve 19 gömülü Python bloğu kontrol edildi. Yeni bellek/SELinux/audit testlerinde 34 test geçti; bunlardan biri yalnız testin başlattığı zararsız alt sürecin belleğini gerçekten okudu. Soket kimlik denetimi, imza teyidi, süreç/eşleme değişimi, erişim reddi ve daha sıkı ptrace ayarının korunması sınandı. Ağ entegrasyon ve Fedora/Debian paket seçimi testleri komut taklitleriyle geçti.

Bu geliştirme ortamında gerçek clamd/Suricata kurulumu, Fedora SELinux enforcing ve uçtan uca paket düşürme testi yapılmadı. Kullanıcının önceki cihaz çıktısı NFQUEUE tüketicisini ve firewall sırasını doğruluyordu; bu yeni sürümün cihaz testinin yerine geçmez. Başarısız kurulum, önceki adımlarda uygulanmış firewall veya servisleri otomatik geri almaz.
