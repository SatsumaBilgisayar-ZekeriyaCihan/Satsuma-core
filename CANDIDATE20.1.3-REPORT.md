# Satsuma Core 20.1.3 — inceleme ve doğrulama raporu

Tarih: 22 Ekim 2026 (Europe/Istanbul).
Temel: **2.0.0-candidate.20.1.2**, commit `f03a08eb6dbc0a5c50483d0c5e1a54b46d2781e4`.
Dal: `fix/candidate20.1-queue-recovery-dual-stack`.
Yeni aday: **2.0.0-candidate.20.1.3**. Önceki paketlerin üzerine yazılmaz.

Bu teslim tam RPM içerir. **RPM imzasızdır. GPG anahtarı oluşturulmadı veya
pakete eklenmedi.** SHA-256 dosya eşitliğini doğrular, yayıncı kimliğini doğrulamaz.
Paket Debian üzerinde RPM 4.20.1 ile Fedora 44 hedef metadata'sıyla oluşturuldu;
Fedora üzerinde derlenmiş veya kurulmuş olduğu iddia edilmez.
**Gerçek Fedora kabulü tamamlanmadı; kararlı veya üretime hazır değildir.**

## Talimat maddelerinin durumu

“Düzeltildi ve doğrulandı” yalnız burada belirtilen kaynak/yerel test kapsamını
ifade eder. Bir satırdaki açık alt gereksinim, o maddenin tamamlandığı anlamına
gelecek şekilde “uygulandı” olarak işaretlenmedi.

| Madde | Durum | Yapılan ve kalan |
|---|---|---|
| 1. Çalışma ve teslim kuralları | Düzeltildi ve doğrulandı | Aynı geliştirme dalı; ayrı sürüm; tam imzasız RPM, kaynak ve rapor. Ana dal ve eski paketler değiştirilmez. SELinux, hesap izinleri, yön/yetki kapıları gevşetilmedi. |
| 2. Yönetim paneli | Uygulandı, gerçek sistem testi bekliyor | Altı sayfa ve sabit yan menü. Her sayfanın ayrı kaydırması var. Yenileme metin/odak/seçimi korur; açık menü yeniden doldurulmaz. Kaybolan istek yerine başka uygulama seçilmez. Tekerlekle seçim engellenir. Durumu bilinen boolean seçenekler tek anahtar. Alan etiketleri ve servis adı görünür. Offscreen kontroller geçti; gerçek masaüstü kabulü bekliyor. |
| 3. App Control karar akışı | Uygulandı, gerçek sistem testi bekliyor | Ana pencereden bağımsız üst düzey karar penceresi; İzin ver/Engelle, bir kez/uygulama için hatırla. Gösterilen istek sabitlenir. Yönetici IPC doğrulaması korunur. Yalnız aynı komutun APPLIED kaydı sonrası uygulanma bildirilir; timeout/hata ayrı. Önceki hash/yol/UID temelli gruplayıcı ve güvenlik testleri korundu. Brave ve Wayland konum/odak/minimize kabulü yapılmadı. |
| 4. Sağlık tutarlılığı | Uygulandı, gerçek sistem testi bekliyor | Eski self_integrity_health yerine integrity_runtime öncelikli. Ortak özet: dosyalar/yapılandırma/işlev ayrı, zaman/güncellik ve çelişki mesajı. Ana sayfa, uyarı şeridi, yönetim, bütünlük ve sağlık aynı değerlendirmeyi kullanır. Genel sistem temizliği doğrulanmış sayılmaz. |
| 5. Sistem Sağlığı | Açık | Genel özet, beş durum kartı, etki/öneri, onarım kayıtları ve teknik ayrıntılar uygulandı. Geçmiş hata sayacı güncel arıza olarak yorumlanmıyor. Kuyruk uzunluğu tek başına hata sayılmıyor. İlerleme/gecikme eşik modeli ve hedefteki gerçek packet-drop/gelen trafik arızalarının nedenleri açık. |
| 6. Ortak durum dili | Açık | Ortak durum/tarih biçimi, eksik ölçümün 0 sayılmaması, ham nesnelerin teknik ayrıntıya taşınması ve birçok tekrar sütununun kaldırılması uygulandı. Eski TUI ve bütün eski ekran metinlerinin eksiksiz dönüşümü tamamlanmadı. |
| 7. Arka plan ve servisler | Açık | Gateway last_check uyuşmazlığı düzeltildi. Arka Plan Bileşenleri adı, görevler, iş üretimi/heartbeat ayrımı ve servis yaşam türleri eklendi. correlation_manager alt takım nedenlerini saklar. Journal geçici dosya hatası artık sağlık kaydı üretir; teams için PrivateTmp açıldı. Gateway/Sentinel yönetim listesine eklendi. dns_monitor/evidence/response bağımsız heartbeat üretmiyorsa bu açıklanır; yeni producer eklenmedi. Sentinel/boot arızalarının hedef journal ile kök neden kabulü bekliyor. |
| 8. Kural → karar → uygulama | Açık | Kuralın istenen davranışı anlaşılır gösterilir. REQUESTED/completed engel kanıtı sayılmaz; nft readback ile gerçek paket düşürme ayrıdır. Yön güvenlik kapıları korundu ve regresyonları geçti. Kontrollü gerçek Fedora trafiğiyle uçtan uca engelleme doğrulanmadı. |
| 9. Otomatik Aksiyonlar | Uygulandı, gerçek sistem testi bekliyor | Zaman için kayıt oluşturma zamanı fallback'i, hedef/neden aktarımı, iç kayıt filtresi, sonuç etiketleri ve arama. Aynı detection_id/aksiyon/hedef/sonuç tekrarları gruplanır; kayıt geçmişi teknik ayrıntıda korunur. Yenilemede seçili kayıt ve kaydırma korunur. |
| 10. OTX | Uygulandı, gerçek sistem testi bekliyor | Gösterge sorgu ve OTX onay kayıtları saklanır; eşleşmeler ve OTX aksiyonları zaman sırasıyla, arama/filtreyle gösterilir. Cache, kanıtlı eşleşme ve traffic_drop_verified sayıları ayrı ve sınırlı kayıt penceresiyle sunulur. Cache bulk gösterge indirme sayısı değildir. Kaynakta uygulama/domain ilişkisi yoksa üretilmez. Geçmiş hata güncel bağlantı hatası sayılmaz. Gerçek API/engelleme kabulü bekliyor. |
| 11. Ağ Koruması ve Engellenen IP’ler | Uygulandı, gerçek sistem testi bekliyor | Yeni ad/açıklama, neden/kaynak/başlangıç/bitiş alanları, boş görünüm nedeni. READY yalnız ön koşullardır; koruma kanıtı sayılmaz. Engel geçmişi canlı kernel ölçümü değildir. |
| 12. Audit | Uygulandı, gerçek sistem testi bekliyor | USER_START/END ve CRED olaylarındaki iç içe msg alanları ayrıştırılır. PID/UID/exe/sonuç taşınır; olay türüne özgü Türkçe özet, oturum/güvenlik ayrımı, ham kayıt erişimi. Mevcut node+timestamp+serial gruplayıcı korunur. Gerçek kullanıcı audit.log kayıtları sağlanmadığından hedef kayıt kabulü yapılmadı. |
| 13. Bellek savunması | Açık | Ölçüm yokken 0/temiz sonucu kaldırıldı; 0 süreçte collector DEGRADED. İncelenen/erişilemeyen/kaybolan süreç, zaman ve üstveri kapsamı gösterilir. Güvenli procfs fixture testi ve gerçek Debian procfs okuması yapıldı. Hedef Fedora kapsamı, JIT yanlış pozitifleri ve tespit kabiliyetinin kabulü açık. |
| 14. Ağ savunması | Açık | Ağ menüsüne taşındı; ayarlara bağlantı, son trafik, son batch sayısı ve kayıttaki arayüzler aktarılır. Bu bilgisayardaki kaynak kapsamı belirtilir; yerel ağ bütünü iddia edilmez. Yerel IP kaynakta yoksa belirtilmemiş gösterilir. Eksiksiz arayüz/IP/kapsam ölçümü ve gerçek sensör veri akışı kabulü açık. |
| 15. Fedora yaşam döngüsü | Açık | 20.1.2 systemd-sysusers akışı korunur; disposable root kimlik koruma testleri geçti. Gerçek Fedora 44 SELinux enforcing ilk kurulum/yükseltme/reboot/kaldırma yapılmadı. Posttrans sonrası kısmi kurulum toparlama açığı sürüyor. |
| 16. Doğrulama ve teslim | Açık | Tam RPM, kurulum/kaldırma açıklaması, kaynak, SHA-256, değişiklik ve test kanıtları hazır. Aşağıdaki gerçek sistem kabul kapıları kapanmadı. |

## Doğrulanan nedenler ve kod karşılıkları

- `dashboard_api.m_integrity`: güncel runtime kaydı mevcutken kullanılmayan eski
  anahtar özetin NO_DATA görünmesine yol açabiliyordu. Aynı veritabanıyla regresyon eklendi.
- `m_workers`: gateway yazıcısının `last_check` zamanı dikkate alınmıyordu.
  Taze gerçek biçimli kayıt artık RUNNING; son olay zamanı heartbeat'ten uydurulmaz.
- `worker_journal`: TemporaryFile hata yakalama bloğunun dışındaydı. Hata artık
  DEGRADED olarak yayımlanır. PrivateTmp, strict dosya sistemi altında gereken dar
  yazılabilir geçici alanı sağlar; hedef journal hatasının bununla eşleştiği henüz kanıtlanmadı.
- `audit_host.event`: oturum kayıtlarının alanları SYSCALL olmadığı için dışarı
  taşınmıyordu; ayrıca iç içe quoted msg içindeki res/exe ayrıştırılmıyordu.
  Kaynakta success yoksa başarılı varsayılmaz.
- Bellek ekranı `health.get('inspected', 0)` ile ölçüm yokken sıfır gösteriyordu.
  Artık eksik/sıfır/eski ölçüm farklıdır; boş tablo “bellek temiz” sayılmaz.

## Test kanıtı

Python 3.12, Qt 6 offscreen, Debian kullanıcı ortamı: **552 test ve 5 alt test geçti**;
0 başarısız, 0 hata, 0 atlama. Yeni onarım regresyonları: 15 test.
Tüm kaynak testleri yerel loopback ve Unix soketleriyle çalıştırıldı. Yetkilendirme,
aynı uygulamada 100 bağlantı gruplaması, farklı hash/UID ayrımı, once/persistent
kararlar, yön doğrulaması ve NFQUEUE hata davranışı mevcut testler kapsamındadır.
Bu testler gerçek Brave, canlı nft DROP veya gerçek Fedora servis testi değildir.

Gerçek Debian procfs okumasında 3 süreç incelendi, 11 süreç okunamadı; durum
**DEGRADED** raporlandı. Bu erişim kısıtları gizlenmedi, yetkiler gevşetilmedi.
Bu ölçüm Fedora bellek savunması veya tehdit tespitinin kabulü değildir.

RPM içerik kontrolü derlenen Python modüllerini, entrypoint hedeflerini, kaynak
byte eşitliğini, sysusers dosyasını, launcher'ları ve digest/imzasızlık durumunu
kontrol eder. Fedora systemd başlangıcını doğrulamaz.

## Açık gerçek sistem kabul kapıları

- Fedora 44 x86_64/Wayland: karar penceresi sağ konum, odak, ana pencere küçültme.
  Wayland compositor'ü uygulamanın konum isteğini reddedebilir; gerçek sağ konum garantisi yok.
- **Uygulama tamamen kapalıyken karar penceresi çalışmaz.** Bu teslim ayrı oturum
  notifier servisi eklemez. Firewall servisi bekleyen bağlantıyı onay gelene kadar
  engellemeye devam eder; panel açılınca bekleyen güncel istemler gösterilir.
- Brave çoklu süreçleri, gerçek izin/engel, bir kez/hatırlanan karar ve gerçek
  oturum süresi dolması; frontend timeout testi canlı kernel uygulaması kanıtı değildir.
- SELinux enforcing ilk kurulum, yükseltme, reboot, kaldırma ve UID/GID koruma.
- Gerçek EVE → conntrack ORIGINAL yönü → politika → nft → paket düşürme zinciri;
  IPv4/IPv6, DNS/HTTPS ve NFQUEUE100/201 throughput/drop/gecikme ölçümleri.
- Tespit sensörlerinin gerçek veri üretimi, gerçek audit.log alanları, normal JIT,
  uzun süreli servis/restart sayısı, CPU/RAM ve ilk kurulumdaki Suricata kuralları.
- Önceden belgelenen socket sahipliği snapshot yarışı ve posttrans toparlama.

Genel korumayı etkin göstermek için kural aksiyonları kendiliğinden Engelle'ye
çevrilmedi. Güvenlik kapılarının başarısızlığını gizleyen bypass eklenmedi.
