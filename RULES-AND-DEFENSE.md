# Kural düzeltmeleri ve ağ/RAM savunması — candidate.4

## Değişen davranış

- Komut eşleşmesi artık harf duyarlı argv sınırlarına dayanır: sudo -s/-S, -r/-R ve curl -t/-T ayrılır. Araç adının echo/grep argümanında geçmesi doğrudan çalıştırma sayılmaz. Desteklenen seçenekler araya girebilir; kısa seçenek kümeleri ve belirli uzun seçenekler normalleştirilir.
- Mutlak dosya yolları artık /tmp/etc/... ile eşleşmez. Ortam değişkenleri isim sınırıyla eşleşir.
- Ters shell desenlerinin YAML çift kaçışları düzeltildi. Cron listelemesi kalıcılık olarak işaretlenmez. Servis durdurma sözdizimi ve yaygın kalıcılık yolları genişletildi.
- Sudoers yazması NOPASSWD eklenmesini kanıtlıyor diye adlandırılmaz. Yanlış MITRE taktikleri/alt teknikleri düzeltildi. history -w temizleme sayılmaz; panic-off firewall'ın kapanması olarak anlatılmaz. İşlenmeyen UID bağlamı ve işlem saati üzerinden puanlama kaldırıldı.
- Komut adı tek başına saldırı sonucu olmadığı için genel aktarım/yönetim faaliyetleri indicator/low olarak sunulur. Bunlar adli kanıt veya kesin saldırı olarak gösterilmez.
- Yerleşik Core kurallarında doğrudan kill_process/block_ip talebi kalmadı. Kanıt, kayıt ve korelasyon akışı kullanılır. Yönetici tarafından açılan ayrı ağ koruma politikaları bundan bağımsızdır; bu değişiklik sistem firewall'ını değiştirmez.
- Süreç argv sınırları shlex.join ile korunur. Süreç ortamından yalnız LD_PRELOAD/LD_LIBRARY_PATH isimlerinin varlığı kaydedilir; değerleri ve diğer ortam anahtarları kaydedilmez.

## Yeni bölümler

Masaüstünde **AĞ SAVUNMASI / BULGULAR**: ağ/C2/sızdırma/yanal hareket bulguları ve Suricata/DNS kaynakları. Üç yeni gözlem kuralı: yeni dinleme portu, kalıcı firewall ayarı ve DNS resolver yapılandırmasına yazma. Mevcut DNS/LAN/subnet yönetimi Yönetim bölümündedir.

**RAM / BELLEK SAVUNMASI**: dört yeni gösterge — memfd yürütülebilir dosya, çalıştırılabilir memfd eşlemesi, anonim RWX bölgesi ve silinmiş yürütülebilir dosya. Salt okunur procfs metadata toplayıcısı Core döngüsüne bağlandı. En fazla 128 süreç/30 saniye, süreç başına en fazla 256 KiB maps okunur; tekrarlar PID/başlangıç/gösterge birleşimiyle bastırılır. PID yeniden kullanımı yeni olay oluşturabilir. Bellek içeriği okunmaz, dump alınmaz, ptrace uygulanmaz. JIT veya güncelleme bu göstergeleri meşru olarak üretebilir.

RAM paneli incelenen/okunamayan süreç sayılarını ve toplayıcı durumunu gösterir. Normal kullanıcı paneli veriyi mevcut salt okunur reader üzerinden alır; procfs erişimi GUI'ye verilmez.

## Doğrulama ve sınırlar

Ürün testleri source dizininden çalıştırılır:

```sh
QT_QPA_PLATFORM=offscreen /workspace/setup/satsuma/venv/bin/python -m pytest -q tests
```

Son doğrulama: **138 test başarılı**, **223 Core kuralı**, sıfır yükleme hatası.

Yeni regresyon testleri komut/opsiyon/yol sınırlarını, ortam değişkeni sözleşmesini, yeni ağ kurallarını, sahte procfs üstünden RAM toplayıcısını, tekrar bastırmayı ve normalize olayın kural motoruna ulaşmasını sınar. İki yeni Qt paneli offscreen olarak veriyle açılıp yenilendi.

Önceki validation raporları tarihsel denetimdir; o sayılar yeni sürümün sonucu değildir. Eski audit betikleri değişen kural şekillerini ve artık kullanılmayan tehlike sınıflandırmalarını varsayabildiği için hepsinin geçtiği iddia edilmez. Eski sabit örnekler bellek dökümü/gerçek saldırı testi değildir. Yeni ürün regresyonları ayrıca tutulur; önceki başarısız testler gizlice başarılıya çevrilmedi.

Bu çalışma RAM'deki bütün saldırıları yakalayan bir tarayıcı oluşturmaz: process_vm_writev/ptrace enjeksiyonunu veya shellcode içeriğini doğrudan izlemez. İzin verilmeyen, taramalar arasında biten veya 256 KiB maps sınırı dışındaki süreç/bölgeler kapsanmayabilir. /proc kısıtları health'te okunamayan süreç olarak görünür. Yeni ağ dosya kuralları audit toplayıcısının gerçekten o yolları izlemesine bağlıdır; yeni port kuralı sys_proc snapshot'ına bağlıdır. Panel en son 2000 bulgudan görünüm oluşturur.

Canlı Fedora/SELinux, nftables/dnsmasq ve RPM kurulumu bu bulut ortamında doğrulanmadı. Candidate4 RPM üretildi; paket digestleri, dosya izinleri ve 223 kuralın paket içinden yüklenmesi doğrulandı. Kurulu cihazlara dağıtım yapılmadı. YARA veya pass7 kullanılmadı.

## Candidate5: daha dar RPM bağımlılıkları

Masaüstü yalnız QtCore/QtGui/QtWidgets kullandığı için python3-pyqt6 yerine python3-pyqt6-base istenir. AIDE, bpftool, chkrootkit, ClamAV/data/freshclam ve rkhunter Requires yerine Suggests olarak sunulur; varsayılan DNF kurulumu bunları zorunlu çekmez. dnf paketi zorunlu olmaktan çıkarıldı. Audit/Suricata/nftables/dnsmasq ağ işlevleri için korunur. Eksik isteğe bağlı tarayıcılar mevcut UNAVAILABLE/DEGRADED durumuyla raporlanır; tarama yapılmış sayılmaz. Gerçek Fedora işlem boyutu yeniden ölçülmedi.
