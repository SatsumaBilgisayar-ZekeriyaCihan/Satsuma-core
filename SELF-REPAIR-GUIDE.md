# Satsuma 20.1.1 — otomatik kurtarma ve onarım kılavuzu

## Son koruma, kullanıcı onayı beklemez

`satsuma-rescue.service`, Core veritabanını veya paneli kullanmadan şu dört
koruma servisinin systemd durumunu beş saniyede bir sorgular:
`satsuma-network`, `satsuma-suricata-ips`, `satsuma-suricata-otx-guard`, `satsuma-core`.
En az ikisi inactive/failed/deactivating ise otomatik devralır. Açılışta servislerin
başlaması için sistem uptime'ının ilk 90 saniyesi beklenir. Panelin kapalı olması
bir koşul değildir. “disabled” bir enablement ayarıdır: çalışır durumdaki servis,
yalnız disabled olduğu için arızalı sayılmaz. Bilinmeyen systemd durumu sağlıklı
veya doğrulanmış iki arıza olarak gösterilmez.

Üç bağımsız iş aynı anda yürür: fast.log öncelik 1–3 TCP/UDP uyarıları, OTX
(pulse sayısı >35, saatte en çok 120 sorgu), aynı /24 içindeki en az 10 farklı
gelen IP. /24 grubunun kendisi engellenmez; yalnız tekil IP'ler engellenir.
Yerel IP'ye gelen ORIGINAL conntrack yönü doğrulanır. fast.log için tam protokol,
kaynak/hedef IP ve port eşleşmesi aranır. Bu, aktarma bağlantısının içindeki
uzaktan kontrol oturumunu kanıtlamaz. Kabuk adı tek başına kötü amaç kanıtı
sayılmadığından otomatik blok üretmez. Operatörün değişmez kuralı gereği PTR kaydı
olmayan bir uç, bağlı kaldığı sürece 5 bağlantı yapabilir; 6.sında Suricata veya
OTX beklenmeden engellenir (bekçi, `satsuma/peer_watch.py`). Sentinel yalnızca
inceleme önerir.

Yedek tablo `inet satsuma_rescue` olur; diğer tablolar silinmez. OUTPUT zinciri
kurulmaz ve conntrack bağlantıları topluca silinmez. Yeni tablo gelen ORIGINAL
paketleri engeller; kullanıcının dışarı başlattığı akışın yanıtlarına uygulanmaz.
Eski tablolardaki mevcut engeller bundan bağımsızdır. Her eklemede kernel set
üyeliği okunarak doğrulanır. Bu okuma gerçek saldırı önleme testi değildir.

Suricata ve ana ağ servisi en çok dakikada bir yeniden başlatılmak üzere
systemd'ye istenir. Başarılı başlangıç garanti edilmez. Suricata yoksa yeni
fast.log üretilemez; OTX anahtarı yoksa OTX devre dışı/DEGRADED görünür.
OTX anahtarını root-owned 0600 `/etc/satsuma-core/otx-api.key` dosyasında tutun.
API anahtarı paketlenmez. Conntrack/nft veya kernel bozulmuşsa betik bunların
yerine geçemez; arızayı kaydeder. Kernel/root bütünüyle ele geçirildiyse aynı
makinedeki watchdog güvenlik garantisi sağlayamaz.

Dört servisin tamamı iki ardışık kontrolde active olduğunda watchdog beklemeye
döner. Eklenmiş engeller bilerek korunur. İnceledikten sonra tekil engeli kaldırmak
için `sudo nft delete element inet satsuma_rescue blocked_v4 '{ IP_ADRESI }'`
(IPv6 için blocked_v6). Tüm yedek tabloyu silmek korumayı kaldırır; otomatik
onarım bu işlemi yapmaz. Watchdog hizmeti diğer Satsuma servislerine Requires
ile bağlı değildir ve onların çökmesi onu durdurmaz.

## Her on dakikada canlı sağlık kontrolü

`satsuma-self-health.timer`: ilk kontrol açılıştan iki dakika sonra, ardından
10 dakikada bir. Panel açıkken “Sağlık kontrol ediliyor” bandı gösterilir.
Rapor: `/var/lib/satsuma-core/self-health/status.json`; geçmiş: aynı dizinde
events.jsonl; panelde Sistem Sağlığı. Sonuç 15 dakikadan eskiyse STALE olur.

Servis durumu, worker heartbeat güncelliği, imzalı uygulama envanteri, müdahale
bütünlük kilidi/pause, gerçek nft kural bağlantısı denetlenir. Ayrı network
namespace içinde IPv4/IPv6 UDP için önce teslim, sonra DROP + sayaç artışı,
sonra kural kaldırıldığında tekrar teslim sınanır. Host namespace'ine veya gerçek
kullanıcı trafiğine deneme kuralı eklenmez. Namespace yetkisi yoksa test başarısızdır;
atlanmış test geçer sayılmaz. Bu test tüm uygulama izinlerini, Suricata imzalarını
veya gerçek AnyDesk/TeamViewer oturumlarını doğrulamış sayılmaz.

İmzalı uygulama dosyaları sağlamsa allowlist'teki inactive/failed servisler için
reset-failed + start istenir. Worker heartbeat arızasında çalışan teams servisi için sınırlı restart istenir. Her servis için 30 dakikada en çok üç deneme;
deneme bütçesi eylemden önce kalıcı yazılır. Maskelenmiş servis açılmaz. Kod
indirilmez, manifest/AIDE baseline yenilenerek değişiklik onaylanmaz, paket
yeniden kurulmaz ve firewall flush yapılmaz. Yeniden başlatma isteği onarımın
başardığı anlamına gelmez: son durum ayrıca okunur; başlangıçta bulunan hata
aynı kontrolde silinmez. Gerekirse bir sonraki kontrol doğrular.

## Çözülemeyen arızayı inceleme

1. Yerel konsolda `sudo systemctl status satsuma-rescue satsuma-self-health.timer`
   ve `sudo cat /var/lib/satsuma-core/self-health/status.json` çıktısını inceleyin.
2. Arızalı servis için `sudo journalctl -u SERVIS_ADI --since '-30 min'` kullanın.
   Tekrar denemeden önce rapordaki neden ve deneme limitini kontrol edin.
3. Suricata için `sudo suricata -T -c /etc/suricata/suricata.yaml`,
   `sudo journalctl -u satsuma-suricata-ips -b`, NFQUEUE 100 ve kuralları inceleyin.
   Geçersiz imzayı veya eksik NFQUEUE desteğini körlemesine yeniden başlatma çözmez.
4. nft için `sudo nft list ruleset`; ana politika, satsuma_otx_guard,
   satsuma_rescue ve OpenSnitch tablolarını ayrı inceleyin. Ruleset flush etmeyin.
5. Bütünlük uyarısında dosya farkını güvenilir paketle karşılaştırın; yedek alın.
   Güvenilir RPM ile kontrollü yeniden kurulum kullanın. Mevcut şüpheli içeriği
   “yeni güvenli baseline” diye imzalamayın.
6. `sudo systemctl start satsuma-self-health.service` tek seferlik denetimdir.
   Başarıyı status.json ve servis günlüğüyle doğrulayın.

## Uygulama internet onayı — OpenSnitch

Paket OpenSnitch daemon ve UI sağlayıcılarını bağımlılık olarak ister. Fedora 44 standart depolarında olmadıkları doğrulandığından resmî upstream v1.8.0 RPM’leri, GitHub SHA256 digest doğrulaması ve aynı tag/commit kaynak arşiviyle kurulum paketine eklenir. `satsuma-candidate19.4-fedora44-x86_64.tar.gz` arşivini çıkarıp `bash INSTALL.sh` çalıştırın; üç yerel RPM tek dnf işleminde kurulur. Tek başına Core RPM bu iki bağımlılık kurulu değilse yeterli değildir. Kurulum
standart OpenSnitch ayarlarını koruyarak DefaultAction=deny, InterceptUnknown=true,
QueueBypass=false, QueueNum=200 ayarlar. Suricata queue 100 ile karışmaz.
FlushConnsOnStart=false mevcut bağlantıların topluca kesilmesini önler. İlk
ayarın kopyası default-config.pre-satsuma.json olarak saklanır.

Masaüstünde `satsuma-internet-permissions` veya karşılama ekranındaki düğmeyi
kullanın. Oturum açılışında da başlatılır. Yeni izinsiz bağlantı onay bekler;
30 saniyede yanıt yoksa reddedilir, otomatik allow olmaz. Kalıcı açık kullanıcı
izinleri tekrar sorulmadan uygulanır. OpenSnitch'te eski genel allow kuralları
veya açık bir UI oturumu varsa bunları inceleyin; güncellemeden sonra oturumu
kapatıp açın. Kullanıcı izinlerini paket sessizce silmez.

OpenSnitch onayı Satsuma'nın temel TCP53/443, UDP53/NFQUEUE politikasını veya
isteğe bağlı ek sistem-servisi cgroup filtresini kaldırmaz. İzin verilmesi tüm
portların açıldığı anlamına gelmez. OTX/sistem servisleri de ilk bağlantılarında
onay isteyebilir. Bu sürümün gerçek Fedora masaüstünde ilk kurulum/reboot ve
iki cihazlı izin/uzak kontrol kabul testleri ayrıca yapılmalıdır.

Kaynak doğrulaması: upstream OpenSnitch daemon/data/default-config.json,
daemon/ui/config/config.go, ui/opensnitch/config.py ve daemon/ui/client.go,
commit a1353848ba1b660320e90cefea782c3fba272c00. Upstream lisansı GPLv3; kodu
ürüne kopyalanmaz, ayrı dağıtım bağımlılığı olarak kullanılır.

## Candidate19 ilk kurulum hatası

`rpm -q satsuma-core` kurulu değil derken `%pre` içinde `No module named
installer` görülüyorsa eski AIDE dizini kalmış olabilir. 19.2, RPM veritabanından
paketin kayıtlı olmadığını doğrulayıp eski dizini
`/var/lib/satsuma-core/orphaned-integrity-ZAMAN` altında, eski aide.conf ve
imzalarıyla korur. Yeni RPM doğrulanmadan yeni baseline kurulmaz. Mevcut kayıtlı
RPM yükseltmeleri bu yolla atlatılmaz; imza ve değişiklik denetimleri devam eder.
Manuel AIDE silme veya `--noscripts` ile Satsuma kurma gerekli değildir.

## Ağ kimliği güvenlik sınırı (19.2)

İlk gözlem yalnız değişiklik karşılaştırması içindir, güvenilir ağ geçidi
kanıtı değildir. Ağ kimliği servisi root çalışsa da bounding capability seti
boştur ve yalnız AF_UNIX/AF_NETLINK kullanır. `ip neigh replace`, otomatik ARP/ND
sondalaması ve bu modülden nft kilitlemesi yapılmaz. Hatalar bağlantıları
değiştirmez; bulgu üretir. Önceki permanent komşu kayıtlarını `ip neigh show` ile
inceleyin; doğrulanmamış kayıtları meşru statik kayıtlardan ayırmadan topluca
silmeyin. 19.2 önceki sürümün bilinmeyen statik kayıtlarını otomatik değiştirmez.

## 19.3: maskeli Satsuma servisleri

RPM posttrans etkinleştirmeden önce current-package mask recovery çalıştırır.
Vendor unit digest'i RPM envanteriyle eşleşmeden maske kaldırılmaz. Her kaldırma
/var/lib/satsuma-core/service-recovery/masks.jsonl içine kaydedilir. Paket dışı
servisler, paylaşım maskeleri ve gerçek override dosyaları korunur.
NAT sadeleştirmesi yalnız OpenSnitch'in boş accept NAT şablonlarıyla sınırlıdır;
yedek /etc/opensnitchd/system-fw.pre-satsuma-compact.json dosyasındadır.

## HaGeZi dışındaki listeler

Yönetim → Ek malware listesi alanına doğrudan HTTPS domain/hosts/adblock adresi
girin; Listeyi ekle/güncelle ile doğrulatın. DNS filtresi kapalıysa liste kaydedilir
ama aktif engel diye gösterilmez. En çok 8 kaynak, kaynak başına 4 MiB ve toplam
200000 ek alan adı desteklenir. IP listelerini veya tam kötü URL listelerini
bu alana girmeyin. Liste kaldırma işlemi DNS yapılandırmasına da uygulanır.
