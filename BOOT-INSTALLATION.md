# Otomatik AIDE ve erken açılış kurulumu

RPM kurulumu AIDE gerektirir. `%pre`, dosyalar açılmadan önce uygulama,
yapılandırma, güven ve veri dizinlerini root sahipliğinde hazırlar. Üst dizinler
ve mevcut alt ağaçlar bağlantı, başka kullanıcı sahipliği ve grup/diğer yazma
izinlerine karşı denetlenir. Güvensiz yolların üzerinden kurulum sürdürülmez.
Uygulama kodu 0755 dizinlerde/0644 dosyalarda, özel veri 0700 dizinlerde tutulur.
Bunlar root yetkisine karşı değiştirilemezlik sağlamaz.

Yeni paketin sağlamadığı eski `satsuma*.service` ve `satsuma*.timer` birimleri
kurulum öncesi durdurulur, devre dışı bırakılır ve maskelenir. Birim dosyaları
silinmez. Yerel birim dosyası maskelemeyi engelliyorsa kurulum hata verir;
operatör dosyayı incelemelidir. Proje dışındaki zamanlayıcılar veya root
süreçleri bu işlemle engellenmez.

`%posttrans`, /opt altındaki dosya/dizin listesini, dosya türlerini, sahipliği,
izinleri ve SHA256 değerlerini RPM veritabanıyla karşılaştırır. Fazladan veya
bozulmuş içerik güvenilir envantere alınmaz, otomatik silinmez. Ardından uygulama
envanteri ve HMAC anahtarı hazırlanır, systemd etkinleştirme bağlantıları kurulur,
AIDE ilk veritabanı oluşturulur ve imzalanır. İlk tam kontrol başarılı olmadan
kurulum başarı mesajı verilmez veya önceki hizmetler yeniden başlatılmaz.
Paket işlem betiği hatası RPM tarafından payload kurulumu tamamlandıktan sonra
bildirilebilir; başarılı payload kopyalaması başarılı güvenlik kurulumu değildir.

Mevcut AIDE veritabanı yeniden oluşturulmaz veya yeniden imzalanmaz. Değişiklik,
imza hatası veya yarım kalmış veritabanı operatör incelemesi gerektirir. Özellikle
mevcut host AIDE temeliyle kapsanan paket/dosya güncellemeleri sonrasında bu
kontrol durabilir; geniş bir host değişikliği otomatik güvenilir ilan edilmez.

`satsuma-setup --user KULLANICI` yalnız masaüstü üyeliği/yönetici kurulumu ve
servis başlatma içindir. Üyelik işleminden önce mevcut temel doğrulanır. `usermod`
sonrası AIDE `--update --limit` yalnız /etc dizininin kendi metadatasını ve
group/gshadow dosyalarını (yedekleriyle) günceller; diğer envanter kayıtları
korunur. Ardından tam kontrol tekrarlanır. Yönetici parola dosyası ve güven
metadatası AIDE içeriği dışındadır; yapılandırma ve AIDE temeli HMAC ile doğrulanır.

Erken açılış servisi sysinit.target için otomatik etkinleştirilir; ağ ve Core
başlangıcından önce doğrulama yapar. AIDE eksik/bozuk/hazır değilse verdict FAILED
olur ve yanıt kilidi açılmaz. Host açılışı bloke edilmez. Tarama süresi sınırı
600 saniyedir; servis sınırı 660 saniyedir. Kurulumdaki ilk üretim sınırı 1800
saniyedir. Büyük hostlarda bu sınırların ayrıca ölçülmesi gerekir.

/opt yalnız çalışma zamanı kodu, kurallar, şemalar ve kurulum yardımcılarını
barındırır. README ve teslim belgeleri /usr/share/doc, depodaki mevcut LICENSE
metni /usr/share/licenses, örnek olaylar /usr/share/doc/satsuma-core/examples
altındadır. Testler, derleme araçları, Python bağımlılık listeleri, C/PAM kaynakları
ve isteğe bağlı web geliştirme ağacı RPM çalışma zamanı yüküne alınmaz.

Debian bulut ortamında kaynak testleri, gerçek AIDE ile izole dosya testleri ve
RPM paket içeriği kontrol edilebilir. Fedora/systemd/SELinux ile gerçek açılış ve
yükseltme testi ayrı bir test makinesinde gereklidir.

Fedora işlem sonu kapsamı: /usr/lib/sysimage/rpm ve libdnf5 değişken durum
veritabanları AIDE temelinden hariçtir; paket güven kaynağı olarak kullanılmazlar.
Bağımsız Satsuma imza geçidi onaylı anahtarlardan oluşturduğu ayrı RPM veritabanını
kullanır. /etc üst dizini yalnız izin/sahiplik ile izlenir; alt dosyalar içerik
kapsamında kalır. /etc/ld.so.cache için atomik yeniden yazımdan etkilenen inode ve
zamanlar yerine izin/sahiplik, boyut ve SHA256 korunur.
