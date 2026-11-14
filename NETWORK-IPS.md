# DNS/HTTPS + NFQUEUE 100 — candidate.14

Giriş, çıkış ve yönlendirilen trafik için varsayılan politika DROP'tur.
Dışarı başlatılan yalnız TCP/53, UDP/53 ve TCP/443 bağlantıları geçebilir.
Girişte yalnız bunların established, conntrack reply yanıtları geçer; yeni dış girişler
ve bütün yönlendirilen trafik DROP olur. Loopback ayrıca koruma tablosuyla denetlenir.
Tüm bu izinli paketler Suricata'nın NFQUEUE 100 kuyruğuna gider. Bypass bayrağı,
UDP/443 (QUIC), 853 (DoT), SSH, DHCP veya genel established/related ACCEPT yoktur.
DHCP ile adres alan cihazlarda bu politika DHCP'yi de engeller; uygun statik ağ
ayarları gerekir. ICMP/IPv6 otomatik komşu keşfi bu dar izin listesinde değildir.

IP engelleri kuyruktan önce uygulanır: engelli IP DNS/HTTPS üzerinden de geçmez.
Satsuma'nın yeni temel tablosunun önceliği conntrack sonrasında, filter/0'dır.
Başka uygulamaların tabloları değiştirilmez. Eski bilinen Satsuma zincirleri tek
atomik işlemle değiştirilir; IPv4/IPv6 blok setleri ve elemanları korunur.
Beklenmeyen kurallar veya kurulum hatasında ayrıca satsuma_lockdown tablosunda
üç yön DROP uygulanır. Bu acil tablo ancak sıkı temel politika doğrulanınca
kaldırılır; hata, izinli eski politika üzerinden sessizce sürdürülmez.
Çekirdek/netlink işlemi de başarısızsa uygulama korumayı doğrulanmış göstermez.

/etc/satsuma-core/nftables.nft yönetilen politika dosyasıdır. Paket, dosyayı
noreplace olarak korur; değiştirilmiş/eski bir dosya otomatik güvenilir kabul
edilmez. Dağıtım sırasında .rpmnew ve mevcut dosya incelenmelidir.

satsuma-network.service önce DROP/queue kurallarını yükler. Ardından
satsuma-suricata-ips.service Suricata'yı -q 100, stream.inline=yes,
stream.bypass=no, nfq.mode=accept, nfq.fail-open=no ile çalıştırır. Dağıtımın
ayrı suricata.service birimiyle çakışması önlenir. Kural hatası veya boş tespit
kural seti açılış ön kontrolünde reddedilir. Etkin, güvenilir bir imza setinin
sağlanması dağıtımın sorumluluğundadır; boş paket kuralları yeterli sayılmaz.

Kuyruk hazır kontrolü MainPID, gerçek executable, root dosya izinleri ve
NETLINK_NETFILTER socket inode/peer eşleşmesini denetler. Sonuç boot kimliği,
PID ve süreç başlangıç zamanı ile root-only /run kaydına yazılır. Core bu kaydı
ve güncel kuyruk eşini denetler; sırf herhangi bir dinleyici var diye IPS hazır
sayılmaz. Okunamayan kimlik bilgisi hazır sonucuna dönüşmez.

OTX anahtarı kaydetme sorgulamayı ve operatör onaylı blocker_mode'u açar.
OTX'e herkes kayıt (pulse) ekleyebildiği için tek kayıt engelleme sebebi
değildir (denetim K3). Tek eşleşme modu `threshold`'dur: TLS ile doğrulanmış
yanıtta en az iki ve operatör eşiği kadar kayıt, ayrıca son
`recent_pulse_days` gün içinde güncellenmiş bir kayıt gerekir. Suricata
bekçisinde OTX desteği en az iki kayıt ve pozitif itibar ister. Eski
`any_pulse` ayarı `threshold` olarak okunur; arayüz ve operatör kanalı bu
modu artık kabul etmez. Boot/integrity, pause,
izin verilen IP ve kritik DNS hedefi korumaları korunur. nft başarısızlığı
bloklandı diye gösterilmez; başarısız girişim cache nedeniyle ertelenmez.

Suricata guard'da yapılandırılmış `max_priority` kapsamındaki tek bir imza
eşleşmesi, `fast_block` açıkken OTX onayı beklemeden müdahaleyi başlatır.
Gözlenen uzak IP, kendi adresimizden dışarı çıkan bağlantıda hedef, bize gelen
alarmda kaynak olarak seçilir. Yönlendirilmiş LAN trafiği için conntrack yön
doğrulaması korunur. Guard'a gelen ve giden yönleri kapsayan `nftables` output
zinciri eklenmiştir. Önceki yönetilen input/forward düzeni ancak bire bir
doğrulanırsa, blok setleri korunarak yeni zincire taşınır; bilinmeyen kural
dizilimi kabul edilmez.

Ardışık IP tespiti, aynı subnet'te beş dakika içinde gözlenen farklı IP'leri,
aynı anda bağlı kalmasalar bile sayar. Varsayılan eşik 10'dur. Eşik oluşunca
yalnızca yeni gelen IP hedef alınır; tüm CIDR bloke edilmiş sayılmaz.
Başarılı `nftables` set okuması engel kuralını doğrular, gerçek paket DROP
testi yapılmadıysa yapılmış gibi gösterilmez. Bu değişikliklerin otomatik
test başarısı, Fedora 44 fiziksel sistem kurulum/reboot, SELinux enforcing,
canlı trafik kesme ya da performans kabulü yerine geçmez.

## Güven sınırı

Yerel AIDE temeli, HMAC anahtarı, RPM veritabanı, dosya izinleri ve süreç
kayıtları ele geçirilmiş root/çekirdeğe karşı harici güven kökü değildir.
İlk host taraması mevcut zararlı içeriği de görebilir; temelin oluşturulması
hostun temizliğini kanıtlamaz. Verdict bu nedenle host_cleanliness_verified=false
ve reference_scope=local_installation_and_aide_baseline bilgilerini taşır.
Güvenilir kurtarma/kurulum medyası ve dışarıdan doğrulanmış işletim sistemi,
uygulama paketleri ve Suricata imzaları olmadan temiz host iddiası yapılmaz.

## Doğrulama kapsamı

Yayın iş akışı Fedora 44 konteynerinde gerçek systemd servisleri, RPM kurulumu,
servis yeniden başlatma, Qt/reader soketi, gerçek Suricata DROP kuralı ve EVE
iletimi, DNS liste/istisna ve subnet IP eşiği kontrollerini çalıştırır. Kontroller
başarılı olmadan yayın yapılmaz. Fiziksel makine açılışı ve SELinux enforcing
bu test kapsamına dahil değildir. OTX uzak API anahtarı ve gerçek TeamViewer /
AnyDesk oturumları sağlanmadı. Uzak erişim sınırları REMOTE-ACCESS.md içindedir.

## EVE yazıcı kimliği — candidate.8

Yeni varsayılan `managed_suricata`dır. EVE dosyasının sahibine bakıp güvenilir
UID seçilmez: IPS başlangıç kaydı, doğrulanan Suricata sürecinin `/proc/PID/status`
alanındaki filesystem UID'sini taşır. Core aynı boot, PID, süreç başlangıç zamanı,
güncel UID ve NFQUEUE eşini doğrular, ardından EVE okuyucusuna bu UID'yi verir.
Eski `writer_uid: 0` varsayılanı yönetilen servis için bellekte bu otomatik moda
çözümlenir; mevcut politika dosyasının sessizce yeniden yazılması gerekmez.
Açıkça verilmiş sıfır dışı UID, doğrulanan yazıcıyla eşleşmesi gereken sabit bir
pindir. Root olmayan Suricata UID'si dosya adından veya mevcut dosya sahibinden
öğrenilmez. Doğrulanamayan süreç/readiness kaydı varsa EVE tüketimi başlamaz.
Root sahipliğinde, ayrıcalık bırakılmadan önce açılmış güvenli EVE dosyaları da
kabul edilir. Farklı kullanıcı sahipliği, symlink, birden fazla hard link ve
grup/diğer yazma izinleri reddedilir. Yerel UID doğrulaması, ele geçirilmiş
root/çekirdeğe karşı harici temiz sistem kanıtı değildir.

Yerel DNS yönlendirmesi için yalnız conntrack original hedef portu 53, güncel
hedefi 127.0.0.1 veya ::1 ve güncel hedef portu 53053 olan çıkış paketleri
queue100 ile geçer. Bu, dışarıya 53053 izni vermez; DNAT sırasında hook arayüz
bilgisinin henüz değişmemesi nedeniyle gereken yerel yönlendirme kuralıdır.
