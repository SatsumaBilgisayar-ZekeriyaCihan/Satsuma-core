# Ağ keşfi, tarama ve müdahale planı

## Hedef akış

Yeni cihaz gözlemi → kimlik ve kapsam kaydı → yetkili ajan erişimi → desteklenen motorlarla tarama → mevcut kurallarla kanıt eşleştirme → Qt bulguları/uyarıları → kullanıcı kararı → uygulama ve sonuç doğrulaması.

IP veya MAC gözlemi saldırı kanıtı ya da kimlik doğrulaması değildir. ClamAV dosya tarar; Linux üzerinde rkhunter/chkrootkit yerel sistem belirtilerini inceler. Windows için bu iki motor UNAVAILABLE değil NOT_APPLICABLE olarak sunulmalı; Windows incelemesi için desteklenen platform bileşenleri ayrıca gerekir. Ajan olmadan uzak dosya/sistem taraması yapılmış sayılmaz. Bu sürümde uzak taramalar AGENT_REQUIRED, kural eşleştirmeleri AWAITING_SCAN_EVIDENCE durumundadır.

## Bu değişiklikte uygulanmış kaynak akışları

- 30 saniyelik pasif arayüz/rota/ARP/NDP envanteri ve hata durumları.
- Yeni cihazları IP/MAC/arayüz kimliğiyle kaydetme, yinelenmeyen keşif bildirimi ve tarama gereksinimi.
- Qt ağ cihazları ve üç yerel tarama motoru ekranı. Yerel taramayı root operatör kanalı üzerinden sabit systemd servisiyle başlatma.
- Güncel gözlemle eşleşen cihaz için oturum doğrulamalı engelle/izin ver. Engel yalnız Satsuma bilgisayarıyla IP trafiğini kapsar; diğer ağ cihazlarının aralarındaki trafiği veya modem/AP üyeliğini yönetmez. İzin ver kaydı tek başına bir firewall istisnası veya güvenilir cihaz kaydı değildir; bu ekran üzerinden uygulanmış engel varsa kaldırma sonucu doğrulanır.
- ClamAV sonuçlarında dosya yolu, imza ve tarama sonrasında ölçülen dosya kimliği. Başka motorların genel uyarılarından dosya silme yetkisi çıkarılmaz.
- Açık onayla, değişmemiş ve tek hardlink'i olan düzenli dosyayı root korumalı alana atomik taşıma. Sürekli silme ve otomatik karantina yoktur. Desteklenen konumlar /home ve /opt; Satsuma uygulaması ve sistem yolları hariç. 64 MiB üstü dosyalar, symlink'ler ve dosya sistemleri arası taşıma bu uygulamada desteklenmez. Sonradan alınan hash, ClamAV'ın okuduğu baytları kriptografik olarak tasdik etmez; motor çıktısı ve manuel karar birlikte değerlendirilir.
- OTX için TLS korunarak seçilebilir pozitif pulse eşleşmesi; mevcut eşik/yaş modu korunur. IP/alan adı önbelleği mod değişiminde yenilenir. IPv6 IP sorguları eklenmiştir.
- Açık OTX/subnet/otomatik ağ politikalarının iki yönlü engel setlerine ulaşması. Genel otomatik çağrının gelen bağlantı doğrulaması korunur.
- Ardışık farklı subnet IP'leri için beş dakikalık pencere. Aynı IP'nin bağlantı sayısı farklı IP sayısı yerine kullanılmaz.
- Sağlık değerlendirmesinde onarım öncesi servis hatası güncel başarılı servis sonucunu gölgelemez; diğer başarısız kontroller korunur.
- Teyitli, çok kaynaklı ağ bulgularında hedef, güncel yerel IP envanterinden tek anlamlı uzak uç olarak çözümlenir. Belirsiz/eski hedef ve zayıf göstergeler otomatik engellenmez.

- NFQUEUE ve journal dayanıklılık düzeltmeleri 20.1.4.3 dalından geri taşındı; geçici hata, eski paket, transaction rollback ve journal taşkın testleri eklendi.

Bu liste kaynak/test kapsamıdır; kurulu RPM üzerinde veya gerçek Fedora/Windows üzerinde başarı iddiası değildir.

## Sonraki zorunlu geliştirmeler

1. **Ajan taşıma ve kayıt protokolü:** Linux ve Windows platform bilgisi, yönetici tarafından cihaz kaydı, karşılıklı kimlik doğrulama, hedef bağlama, süre sonu, tekrar oynatma önleme ve sınırlı komut listesi. Parola veya anahtarlar sohbetten toplanmaz. Komşu IP'ye göre otomatik SSH parolası denemesi yapılmaz.
2. **Uzak iş akışı:** keşif olayı cihaz başına tek tarama işine dönüşür; ajan yetkisi yoksa bekler. Ajan erişimi kurulduğunda tarama başlar; offline/zaman aşımı/eksik motor durumları ayrı raporlanır. Cihazın işletim sistemine uygun motorlar çalışır. Linux'un üç motoru Windows'ta çalışmış sayılmaz.
3. **Kanıt eşleştirme:** ajan raporları tek şemada normalize edilir; motor sürümü, imza tarihi, iş kimliği, hedef kimliği ve zaman bilgisi tutulur. Mevcut kuralların gerektirdiği telemetri taşınır. Eksik telemetri eşleşme/temiz sonucu sayılmaz. Uzak karantina ajan üzerinde dosya kimliği yeniden doğrulanarak ve kullanıcı onayıyla yapılır.
4. **Karantina yaşam döngüsü:** geri yükleme, özel dosya sistemi destekleri, Linux sistem dosyalarında paket onarımı ve Windows ACL/karantina desteği ayrı kabul testleri ister. Bu değişiklik henüz bunları içermez.
5. **En az 200 gerçek önleme kuralı:** 227 kuralı çoğaltmak veya hepsine block eklemek yeterli değildir. Lisansı ve kaynağı belirli ağ saldırısı imzaları seçilecek; her kural için tespit koşulu, hedef/yön kapsamı, engelleme yöntemi, yanlış pozitif koşulları ve saldırı/normal trafik fixture'ları tutulacak. Suricata IPS imzaları ile Python davranış kuralları ayrı sayılacak.

## 200 kural için kabul kapısı

Her kural ayrı kimlik ve sürüme, zararsız bir saldırı temsilinde gerçek eşleşmeye, en az bir normal trafik karşı testine ve doğru hedef/yön üzerinde uygulanmış DROP/karar kanıtına sahip olmalı. Kuralın yüklenmesi veya alert üretmesi önleme kanıtı değildir. Varsayılan rota, DNS, uygulama izinleri, IPv4/IPv6, izin listeleri ve fail-closed davranışı regresyonlarla sınanmalı. Kanıtlanmış kural sayacı yalnız bu kapıyı geçenleri saymalı.

Mevcut sayım: 227 SmartRule; doğrudan durdurma aksiyonu olan 0, olmayan 227. Bu çalışma sırasında canlı trafikle doğrulanmış 200 önleme kuralı eklenmedi. Tam liste: RULE-PREVENTION-AUDIT-20.1.4.md.

## Kullanıcının fiziksel makinesinde VM laboratuvarı

- Fedora 44 x86_64 Satsuma VM: 4 vCPU, 8 GiB RAM, 40 GiB disk, yerel konsol erişimi.
- İkinci Linux VM: keşif, üç motor, izin/engel, tarama raporu ve karantina hedefi.
- Windows 11 VM: keşif, Windows ajanı/ClamAV ve platforma uygulanmayan motor durumları.
- Ayrı test ağı; ilk testlerde üretim cihazları bulunmasın. Test öncesi snapshot alınsın. Aynı fiziksel makinede üç VM yeterlidir.
- Önce yeni cihaz ve IP/MAC değişimi, ardından resmi zararsız EICAR örneğiyle ClamAV bulgusu ve manuel karantina, sonra normal trafik ile kontrollü saldırı fixture'ları. Gerçek zararlı çalıştırılmaz.
- İzin ver/engelle sonrası kuralların okunması, sayaçlar ve iki uçtan bağlantı denemesi birlikte kaydedilsin. Başlangıç, reboot, SELinux enforcing, kaldırma ve performans testleri de gerekli.
- Bulut ortamından VM erişimi henüz kurulmuş/doğrulanmış değildir. Gerekirse desteklenen VPN ve güvenli ajan kayıt akışı yapılandırılmalıdır.
