# Candidate 19 — worker ve eski yapı onarımları

19 Ekim 2026. Temel: Candidate18.3
`456e0bd615f80d9d992375c95f803f7c7004718c`. Çalışma: taslak PR #5.
Bu geliştirme adayıdır; canlı ürün kabulü henüz tamamlanmamıştır.

## Son davranış

- AIDE, genel işletim sistemi ağaçları yerine Satsuma uygulaması, başlatıcıları,
  systemd birimleri ve desktop dosyasını doğrular. İlk temel kurulumda otomatik
  hazırlanır. İmzalar ve eski temel korunur; değişiklik sessizce onaylanmaz.
- Otomatik timer kontrol ve ayrı güncel snapshot üretir. Bütünlük değişikliğinde
  Core, salt okunur toplayıcılar ve korelasyon uyarı vererek sürer; müdahale
  yetkisi kilitlenir. Fiziksel olarak silinmiş/çalıştırılamayan kodun çalışacağı
  garanti edilemez. Snapshot bütçesi dolarsa görünür hata/uyarı gerekir.
- __pycache__, pyc ve pyo yenilenmesi AIDE'yi bozmaz. Kaynak hashleri,
  sahiplik, izin ve symlink hedefi izlenir. Python başlatıcıları yerel
  bytecode'u okumamak için özel /run cache prefix'i ve -B kullanır.
- Karşılama ekranı geri gelir. Mevcut cgroup uygulama kontrolü yönetici ekranına
  bağlanır. Bu tam masaüstü OpenSnitch değildir; eksik bileşen kurulmuş sayılmaz.
- Desteklenen response/audit/finding/evidence yolları taze kurulumda açık gelir.
  Kimlik, imzalı bütünlük, açık policy, izinli liste ve pause kapıları korunur.
  Otomatik karantina, eski ticket akışı ve anahtarsız dış API çağrıları açılmaz.
- Suricata fast.log öncelik 1–3 TCP/UDP uyarısı, conntrack ORIGINAL tuple ile
  dışarıdan başlatıldığı doğrulanırsa gelen yönde nft engeline dönüşür.
  Yanıt trafiği/dışarı başlatılan bağlantı bu yeni sette engellenmez.
  Genel otomatik IP aksiyonları da gelen yön için doğrulanan ayrı sete gider;
  kimliği/yönü belirsiz bağlantı kapatılmış gibi gösterilmez. Elle çift yönlü
  izolasyon ayrı yönetici işlemidir. Eski kurulumdan kalan çift yönlü bloklar
  ayrıca incelenmelidir; yeni davranış geçmiş bütün operatör kararlarını silmez.
- Paylaşım/uzak sunucu kapatma listesi genişletilir; AnyDesk/TeamViewer'ın dış
  bağlantı istemcileri maskelenmez. Relay üzerinden önceden dışarı açılmış TLS
  oturumundaki uzaktan kontrolü IP yönü/fast.log tek başına ayıramaz. Bu native
  vendor politikası ve iki cihazla canlı test olmadan çözülmüş sayılmaz.
- Udev yaşam döngüsü ve gerçekten gözlenen süreç/aygıt FD ilişkisi yeni Findings
  kodlarıyla kaydedilir. systemd-analyze güvenlik başlatıcısı ve metadata /dev
  envanteri yönetim kanalına bağlanır. Olay sonrası gözlem önleme kanıtı değildir.
- Worker teslim/cursor/baseline, hata görünürlüğü, sürekli D-Bus, ClamAV tarama
  köprüsü, eski uyumluluk toplayıcıları, BPF bilinmeyen durumu, Reader sınırları
  ve SQL hata yolları onarılır. Ayrıntı: WORKER-AUDIT-20261019.md.

## Kural ve dosya koruması

Orijinal 223 kuralın bütün kimlikleri ve YAML hashleri korunur. Dört /dev
kuralıyla 227 olur. SATSUMA-UDEV-001/002, SATSUMA-WATCH-001,
SATSUMA-INTEGRITY-001 ve SATSUMA-SCAN-001 ayrı gözlem/bulgu kodlarıdır;
227 YAML kural sayısına dahil değildir. Koruma bileşenleri silinerek test
geçirilmez; uyumluluk API'leri korunur, ortak sağlamlaştırılmış toplayıcıya bağlanır.

Bütün dosya yapısal envanteri ve exception satırları CI structure-audit.json'dadır.
Yapısal tarama, her satır için manuel güvenlik onayı veya temiz sistem kanıtı
vermez. Devre dışı eski/alternatif bileşenler aktif koruma sayısına eklenmez.

## Doğrulama

Son yerel kaynak turu: **429 PASS, 1 FAIL, 1 SKIP; 5 alt test PASS**.
FAIL: Unix socket bind ortam tarafından EPERM ile engelleniyor.
SKIP: gerçek AIDE binary'si bu çalışma ortamında bulunmuyor.
Bu test beklentileri gevşetilmedi. Yerelde Docker soketi de kapalıdır.

Fedora44 CI, bu commit için tüm kaynak testlerini gerçek AIDE fixture ve Qt ile
çalıştırır; ayrı, NET_ADMIN yetkili izole konteynerde nft JSON düzeni, IPv4/IPv6
üyelik ve kaldırma readback kontrolü yapar, RPM derler ve metadata/digestleri
kontrol eder. Sonucun kanıtı ilgili Actions işi ve source-tests.xml'dir.
Nft readback gerçek paket düşürme veya vendor kontrol oturumu testi değildir.
Başka bir job yalnız native VM için KVM imkânını sorgular; VM testi sayılmaz.

Kurulu Fedora44 ilk kurulum, yükseltme, ilk reboot, gerçek masaüstü oturumu,
223/227-kural canlı müdahale matrisi, tüm worker'ların canlı sağlığı ve native
AnyDesk/TeamViewer incoming-deny henüz kabul kanıtına sahip değildir.
Geliştirme RPM'si bu sınırlar kaldırılmadan üretime hazır diye teslim edilmez.
PR #4'teki ayrı genişletilmiş 1749/23/519 koleksiyonu bu kaynak testleriyle
birleştirilmez. Araştırma kaynakları: DEVICE-AND-SYSTEMD-RESEARCH.md.
