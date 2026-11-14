# Satsuma-core 2.2.37 — Aşama 33, interaktif süreç müdahalesi

## Uygulanan (kaynak kod)
- Test modu varsayılan kapalıdır. Yetkili operator IPC üzerinden yönetici parolasıyla `interactive_process_test_mode` açılır/kapatılır.
- Önceden politika ve zaman kontrolünden geçmiş **otomatik süreç sonlandırma** kararları, test modu açıksa sinyal yerine onay kuyruğuna alınır.
- Panel: `Test Modu — Süreç Müdahale Onayları`. Üç işlem: `İşlemi uygula`, `İşlemi reddet`, `Log çıktısını paylaş (kopyala)`.
- Uygula ve Reddet: var olan kimliği doğrulanmış operator IPC ve HER karar için yeniden yönetici parolası. Parola bu modülce saklanmaz, kayda yazılmaz.
- Kaynak kanıtı değiştirmeden saklanır; onay üzerine `auto_process.respond` yeniden çağrılır ve mevcut `authorize_destructive`, canlı süreç kimliği ve ResponseWorker kontrollerinden tekrar geçirilir. Yeni veya farklı PID kabul edilmez.
- `process_approvals` SQLite tablosunda request-id, süre sonu ve `pending -> processing` atomik geçişiyle çift kullanım reddedilir; onayden sonra potansiyel hassas bulgu payload'ı tablodan çıkarılır. Kuyruk üst sınırı 64, süre 120 saniye.
- Kullanıcı log paylaşma seçeneğinde yalnız seçili isteğin sınırlı görünür özetini panoya kopyalar; dışarı veri gönderilmez.
- Test modu kapatıldığında bekleyen onaylar yürütülemez. Eski kayıtlar denetim amaçlı kalır; süre dolunca yeniden tespit gerekir.

## Çok önemli kapsam ve sınırlamalar
- **Yalnız otomatik PROCESS TERMINATION** bu kapıdan geçer. `satsuma_engine` 32. aşamada yalnız kanıt üretir, direkt sinyal göndermez. Smart Rules / RAM temelli süreç sonlandırma aynı `auto_process.respond` yolunu kullandığı ölçüde kapsam dahilindedir.
- Pasif RAM okuması (sensor), çekirdek fanotify önleme, Suricata IPS/NFQUEUE, nftables engelleme, doğrudan manuel admin operasyonları veya farklı servislerdeki olası alternatif `kill` yolları bu aşamada karara bağlanmaz. Tüm yıkıcı işlemlerde ortak merkezî müdahale kapısı **henüz tamamlanmamıştır**.
- Panel kendiliğinden masaüstü pop-up bildirim açmaz; kendi kendine kimlik doğrulama istemek için de periyodik yenilenmez. Kullanıcı paneli açar ve yenilemek için yönetici parolası girer. PyQt görsel testi bu ortamda çalıştırılmadı.
- Test modunu kapatmak eski otomatik sürece son verme politikalarını geri getirir; bunu kullanıcı açıkça başlatmalıdır.
- Python/sistem zamanlaması ve process kilidi güvenlik garantisi değildir; bu aşama 20 mikrosaniyelik müdahale iddiası değildir.
- Gerçek cihazda ölçülmüş müdahale süresi, başarıyla sonlandırılan süreç oranı veya yanlış pozitif oranı yoktur.

## Test ve doğrulama
- `python -m pytest -q tests/test_process_approval.py tests/test_auto_process.py tests/test_process_followup.py tests/test_response.py tests/test_guard_process_stop.py tests/test_deep_live_lane.py`: **82 geçti, 1 atlandı**.
- Daha geniş deneme (`tests/test_smart_rules.py` dahil): **92 geçti, 1 atlandı, 1 başarısız**. Başarısızlık eski sabit katalog beklentisidir: 233 bekleniyor, katalog 231 aktif kural içeriyor. Katalog yapay biçimde değiştirilmedi.
- SQLite iki bağımsız bağlantıyla sıra kaybı ve çift karar senaryosu test edildi; aynı süreçte iki farklı istek için ayrık karar test edildi.
- Gerçek Fedora cihazında, UI'de, RPM yükseltmesinde, sistemd/SELinux altında doğrulanmadı.

## Etkilenen dosyalar
- `satsuma/process_approval.py` (yeni)
- `satsuma/auto_process.py`
- `satsuma/operator_service.py`
- `satsuma/store.py` (SQLite tablo kurulumunda yeni CREATE TABLE)
- `satsuma/dashboard_qt/panels/process_approvals.py` (yeni, otomatik panel keşfi)
- `tests/test_process_approval.py` (yeni)

## Etki ve geri dönüş
- Bu paketin hazırlanmasında canlı Fedora sistemine müdahale edilmedi; root, SELinux, DNS, nftables, Suricata, OTX, clamonacc, RAM sensörü, `ptrace_scope` ve systemd yetkileri değiştirilmedi.
- Üretim ortamında test modu **varsayılan kapalıdır** ve mevcut otomatik koruma davranışı sürer. Açılırsa otomatik süreç durdurma taleplerinin bir kısmı insan onayına kadar uygulanmaz; bu bir güvenlik ödünleşimidir.
- Geri dönüş: önce test modunu açıkça kapatıp önceki kaynak sürümünü geri yükleyin; yeni SQLite tabloyu hemen silmek gerekmez, ancak onay kayıtlarının saklama/temizleme politikasını ayrıca belirleyin. Gerçek kurulumda geri alma prosedürü doğrulanmadı.
- `interactive_process_test_mode` yalnız süreç sonlandırma için bağlanmıştır: bütün sistem korumasını kapatmaz.
