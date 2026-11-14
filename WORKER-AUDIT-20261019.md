# Worker ve eski yapı denetimi — 19 Ekim 2026

Bu rapor kaynak incelemesi ve regresyon kanıtını açıklar. Kurulu Fedora 44'te
bütün servislerin çalıştığı veya gerçek saldırıların engellendiği anlamına gelmez.
`bin/structure_audit.py` bütün kaynak dosyalarını SHA256 ile envanterler; Python,
JSON, YAML ve kabuk sözdizimini denetler, exception bloklarını satırlarıyla çıkarır.
Görseller yalnızca hashlenir; TypeScript JSONC dosyaları derleyici denetimi bekler.
Bu tarama bütün satırlar için güvenlik onayı vermez. CI artifaktında tam JSON bulunur.

## Gerçek çalışma yolları

| Bileşen | Kaynağa göre bağlantı | Kapsam / koşul |
|---|---|---|
| sys_proc | Core ana döngüsü | /proc ve /sys; iki saniyede bir. İlk görüntüdeki süreçler de incelenir. |
| memory | Core ana döngüsü | Procfs metadata; 30 saniyede 128 süreç. Bellek içeriği taraması değildir. |
| Suricata EVE | Core Reader → Pipeline → normalized → Brain | Doğrulanmış Suricata yazıcı kimliği gerekir. |
| Suricata fast.log guard | Ayrı systemd servisi | Öncelik 1–3, doğrulanmış incoming ORIGINAL TCP/UDP tuple, ayrı nft tablosu. |
| audit | Dedicated servis → AuditReader → host.db | Var olan audit kuralları neyi üretiyorsa onu görür. |
| audit_bridge | Identity team → Core Pipeline | host.db'deki audit kayıtlarını cursor ile aktarır. |
| journal | Identity team | Kayıt başına kalıcı journal cursor. |
| systemd_dbus | Host team | Unit karşılaştırması + sürekli D-Bus başlık kuyruğu; mesaj argümanları toplanmaz. |
| kernel | Host team | dmesg ring buffer; CAP_SYSLOG gerekir; erişim reddi DEGRADED'dır. |
| clamav | File team | Zamanlanmış taramanın host.db kayıtları; DB yoksa eski log okuyucu. |
| security_scan | Saatlik timer | Kurulu ClamAV/rkhunter/chkrootkit; araç yokluğu UNAVAILABLE. Karantina yok. |
| finding/evidence | Dedicated finding servisi | İnceleme/arşiv işleri, policy koşullu. |
| response | Pipeline/broker | Policy, kimlik, bütünlük ve duraklatma kapıları; bağımsız sınırsız aksiyon döngüsü değildir. |
| udev | Yeni ayrı servis | Gerçek aygıt olayı + kısa süre sonra gözlenen açık aygıt FD ilişkisi. Örnekleme; nedensellik veya saldırı kanıtı değildir. |
| integrity | Yeni otomatik timer | İmzalı AIDE kontrolü + ayrı güncel snapshot. Güvenilir temel otomatik değiştirilmez. |
| OTX | Ayrı servis, anahtar/policy koşullu | Anahtar olmadan çalışıyor/engelliyor sayılamaz. |
| subnet | Ayrı servis, policy koşullu | Var olan eşik koruması; genel /24 engeli yok. |
| gateway/sentinel | Kaynak ve birimler korunur | Eski alternatif yollar; varsayılan ana çalışma zincirinin parçası oldukları iddia edilmez. |
| WorkerAudit / WorkerSuricata | Uyumluluk sınıfları korunur | Ana audit ve Suricata okuyucularının yanında ikinci kez başlatılmaz. |
| SysProcMonitor / SystemdDbusMonitor | Eski API'ler korunur | Ortak sağlamlaştırılmış toplayıcılara yönlendirilir; aktif yeni worker yerine iki kez çalıştırılmaz. |
| onay/ticket katmanı, eski web arayüzü ve eski motor API'leri | Kaynak korunur | Aktif yeni iş akışı olarak yeniden açılmaz; kullanılabilir koruma sayısına eklenmez. |

## Düzeltilen açıklar

- Teslim başarısızken baseline/cursor ilerlemesi durduruldu; yeniden denemede en az bir kez teslim semantiği vardır. Tam bir kez teslim garantisi verilmez.
- Kernel/systemd hataları sağlıklı boş sonuç gibi gösterilmez. Worker istisnası takım sağlığına ve hata kaydına ulaşır.
- Suricata/Audit uyumluluk okuyucularında sınırsız readlines ve son N satırdan önceki olayların kaybı kaldırıldı. Kısmi satır beklenir, aşırı uzun satır hata verir.
- Journal kayıt boyutu sınırlı; stderr tüketilmeyen PIPE üzerinden kilitlenmez.
- D-Bus kısa örnekleme yerine sürekli okunur. Kuyruk taşması ve süreç ölümü açık kapsama kaybıdır; teslim edilmemiş başlıklar korunur.
- ClamAV zamanlanmış tarama çıktısı gerçekten worker'a bağlandı. Tarayıcı bulguları ayrıca Findings'e yazılır; tek başına kesin saldırı veya karantina kararı üretilmez.
- BPF aracı eksikken uydurma program kaydı veya kesin sıfır program sayısı üretilmez.
- SQL okuma hataları sıfır alarm/boş başarılı veri gibi dönmez. Eski heartbeat çalışıyor sayılmaz; STARTING/WAITING başarıya çevrilmez.
- Aktif kural değerlendirme hatası eşleşme yok gibi yutulmaz; başarısız normalized kayıt yeniden denenir. Korelasyon/araştırma hatası Brain sağlığını düşürür.
- Manifest oluştururken okunamayan dosya sessiz atlanmaz; eski scope API'sinde dashboard dışlanması kaldırıldı.
- Watch-list hash işlemi özel aygıtları açıp okumaz; dosya türü/boyutu sınırlıdır. Sadece metinde geçen yol yürütme gibi eşleştirilmez.
- Reader bağlantı/eşzamanlılık/boyut/zaman sınırları eklendi.
- Core için eksik CAP_SYS_PTRACE (çapraz UID procfs metadata) ve CAP_KILL (yetkili sonlandırma) tamamlandı. Ptrace/process_vm/kcmp/pidfd_getfd sistem çağrıları kapalı; /proc bellek dump işlemi yapılmaz. Udev yetkileri daraltıldı; PID yeniden kullanımına karşı okuma öncesi/sonrası kimlik kontrolü ve sınırlı scandir eklendi.
- Yeni udev ve integrity birimleri kurulum, başlatma, yükseltmede durdurma ve kaldırma zincirine bağlandı.
- Tarama policy'sindeki yürütülmeyen eski tarayıcı adı gerçek yürütülen sırayla hizalandı; eski sabit policy bellekte uyarlanır.

## Korunanlar ve sınırlar

Önceki 223 kuralın tüm kimlikleri ve YAML dosyalarının hashleri regresyonla
korunur; dört yeni /dev kuralıyla 227 olur. Yeni aygıt kuralları göstergedir;
audit yolu/operation telemetrisi olmadan erişim tespit edilemez. Otomatik
karantina veya eski ticket akışı açılmadı.

Bütün worker'ların kurulu makinada aktif olduğu bu bulut ortamından
ispatlanamaz. Native Fedora ilk kurulum, ilk yeniden başlatma, yükseltme,
Suricata paket akışı, rootkit/aygıt kötüye kullanım önlemesi ve gerçek
AnyDesk/TeamViewer oturumları henüz canlı doğrulanmadı. Relay üzerinden
önceden dışarı kurulmuş TLS oturumundaki uzaktan kontrolü yalnızca IP/fast.log
ile ayırmak mümkün değildir. Application control mevcut systemd-cgroup
filtrelemesidir; tam masaüstü OpenSnitch eşdeğeri değildir.
