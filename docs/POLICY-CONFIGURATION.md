# Policy/config yönetimi — Candidate20.1.5

Ana ayar dosyası `/etc/satsuma-core/policy.json` dosyasıdır. Bu dosya varsa policy çalışma ayarlarını belirler; `config.json` eski kurulum uyumluluğu için, policy yoksa kullanılır. Aynı işlevi iki dosyada farklı değerle tanımlamak yerine policy düzenlenmelidir. Qt ayarları ayrıca kayıtlı operatör kararlarıdır; policy yeniden uygulandığında policy'nin kapsadığı anahtarlar esas alınır.

`workers`: Suricata, DNS toplama, ağ müdahalesi, OTX, audit, bulgu ve kanıt servisleri. `response.destructive` açık ağ politikasını belirler; tek göstergeden dosya/süreç silme yetkisi üretmez. `scheduled_scans`: enabled, interval_seconds (60–604800), order (clamav/rkhunter/chkrootkit). overlap ve automatic_quarantine desteklenmediği için false kalır; manuel karantina ayrıca kullanıcı onayı ister.

`features` altında ağ keşfi, subnet koruması, App Control, DNS filtresi, HaGeZi, LAN erişimi, OTX eşleşme modu, yerel/web araştırması, kural adaptörü, DeepSeek araç ayarları bulunur. API anahtarları policy içinde tutulmaz. Anahtarı veya kurulmuş motoru olmayan işlev çalışıyor diye gösterilmez. Tüm desteklenen anahtarlar örnek policy dosyasında yazılıdır.

`satsuma-configuration.path` iki dosyanın değişmesini izler. `satsuma-configuration.service` uygulama dosyalarını ve yeni ayarı doğrular, başarılı politika görüntüsünü root korumalı `/var/lib/satsuma-core/configuration/last-valid-policy.json` konumunda saklar. Hatalı düzenleme aynı ayar dosyasının üzerine düzeltilmiş gibi yazılmaz; önceki geçerli politika yeniden doğrulanıp koruma onunla sürer. İlk kurulumda hiç geçerli politika veya uygulama bütünlüğü yoksa çalışıyor sonucu uydurulmaz.

Yalnız geçerli ayar değiştiğinde ilgili servisler yeniden başlatılır; sonrasında işlevsel sağlık kontrolü istenir. Servis başlatma isteği, paketin gerçekten düştüğünün kanıtı sayılmaz. Disabled/masked servisler bu yardımcı tarafından açılmaz. Durum `configuration_reload` ve `integrity_runtime` kayıtlarından, ayar reddi ise bulgulardan izlenir.

Başlangıçta koruma ve motor taramaları etkin istenir. Yeni kurulumda OTX, web araştırması ve DeepSeek için gerekli anahtarlar güvenli yerel kurulumla ayrıca girilmelidir. Uzak cihaz ajanı ve Windows taşıma protokolü henüz yoktur; ağ komşuluğu taranmış/temiz cihaz sonucu sayılmaz. chkrootkit isteğe bağlıdır; kurulu değilse yalnız bu motor UNAVAILABLE olur. ClamAV ve rkhunter zorunlu RPM bağımlılıklarıdır; RPM'nin kurulum sonrası sağlık kontrolü bunu gizlemez.

Bu bir test adayıdır. Ağ filtresi kurulumu bağlantıyı kesebilir; ilk deneme snapshot alınmış Fedora 44 sanal makinesinin yerel konsolunda yapılmalıdır. Üretim sisteminde denenmiş kararlı sürüm iddiası yoktur.
