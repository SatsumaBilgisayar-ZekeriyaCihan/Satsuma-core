# Satsuma-core 2.2.37 — Aşama 40: Kural inceleme kanıt kayıtları

## Amaç
Aşama 39 test kurallarının operatör incelemesinde yanlış pozitif/yanlış negatif analizine yarayacak bağlamı korumak. Bu aşama kural eşleşme veya müdahale davranışını değiştirmez.

## Uygulanan değişiklikler
- `satsuma_engine/review_evidence.py` eklendi. Derin motor bulgusundan sınırlı inceleme özeti üretir.
- İnceleme kaydı; bulgu/kural kimliği ve başlığı, önem, sınıflandırma, güven seviyesi, skor, kategori, zaman, olay kaynağı/türü/eylemi, süreç PID/starttime/boot_id/UID/PPID/exe/komut, dosya işlemi/yolu/hash, ağ uç bilgisi, eşleşen koşullar, MITRE teknikleri ve korelasyon penceresi sayısını içerir (kaynak olayda varsa).
- Komut satırı ve eşleşen komut alanlarında parola/token/secret/API anahtarı, Bearer token ve URL kimlik bilgileri için maskeleme eklendi.
- Ham `raw_event`, ortam değişkenleri, parola alanları ve yürütülebilir aksiyonlar inceleme kaydına alınmaz.
- `satsuma/deep_rule_review.py` inceleme kuyruğu için alan izin listesini genişletti; JSON kayıt boyutu 6 KiB ile sınırlandı.
- Operatör kararı sonrasında da sanitize edilmiş kanıt `deep_rule_review_events` denetim kaydında tutulur. `apply` etiketi `true_positive`, `reject` etiketi `false_positive` olarak kaydedilir.
- `satsuma_engine/process_ipc.py` yeni kanıt alanlarını IPC sonucuna taşır; `authorization=none` koşulu korunur.
- `process_approvals.py` seçilen kaydın türüne göre düğme metinlerini değiştirir. Derin kural için “Tespiti doğru işaretle / Tespiti yanlış işaretle”; gerçek süreç onayı metinleri ayrı kalır.

## Yetki ve güvenlik sınırı
- Yeni kural kataloğu halen yalnız `interactive_process_test_mode=True` olduğunda test hattında değerlendirilir.
- Yeni test bulguları `authorization=none` taşır.
- Operatörün `apply` veya `reject` kararı yalnız sınıflandırma etiketi oluşturur. Süreç sonlandırma, IP engelleme, karantina, RAM müdahalesi veya başka bir OS eylemi tetiklemez.
- Gerçek süreç müdahalesi onay kuyruğuyla karıştırılmaz; bu aşamada yeni kurallara müdahale yetkisi eklenmedi.
- Kayıtlar operatör panelinden açık kullanıcı eylemiyle kopyalanır; otomatik harici paylaşım yoktur.

## Değişen dosyalar
- `satsuma_engine/review_evidence.py` (yeni)
- `satsuma_engine/live_lane.py`
- `satsuma/deep_rule_review.py`
- `satsuma_engine/process_ipc.py`
- `satsuma/dashboard_qt/panels/process_approvals.py`
- `tests/test_stage40_review_evidence.py` (yeni)

## Test sonuçları
Seçili motor, kural test modu, IPC, kullanıcı onayı ve süreç onayı regresyonları:

`python -m pytest -q tests/test_stage40_review_evidence.py tests/test_stage39_user_review_rules.py tests/test_stage39_deep_review.py tests/test_deep_live_lane.py tests/test_deep_process_boundary.py tests/test_process_approval.py tests/test_process_approval_notice.py tests/test_engine.py`

**69 geçti, 0 başarısız.** Test ortamında doğrulandı.

Tam `pytest -q` çalıştırması test toplamına ulaşamadan 13 koleksiyon hatasıyla durdu: kaldırılmış `satsuma.ram` modüllerine bağlı eski testler, ortamda PyQt6/PyQt5 bulunmayan masaüstü testleri ve pakette bulunmayan `release/kaldir.sh` dosyasını bekleyen test. Bu sorunlar Aşama 40 değişikliklerinden kaynaklanan test başarısızlığı olarak sınıflandırılmadı; tam regresyon henüz doğrulanmadı.

## Sınırlamalar
- Maskeleme yaygın kimlik bilgisi desenlerini kapsar; keyfi uygulama içi gizli verilerin tümünü tespit edemez. Paylaşmadan önce operatör özeti gözden geçirmelidir.
- `cmd` ve dosya yolları tanılama için operatör kaydında tutulur; bunlar kullanıcı/ortam bilgisi içerebilir.
- Kuralın doğruluğu, skorun kalibrasyonu, yanlış pozitif/negatif oranı ve gerçek cihaz performansı bu aşamada ölçülmedi.
- Fedora hedef cihazı, RPM kurulum/upgrade, PyQt paneli ve gerçek fanotify/worker entegrasyonu üzerinde doğrulama yapılmadı.

## Etkilenen sistem ayarları
Bu aşama kaynak kod ve test dosyalarıyla sınırlıdır. Servisler, SELinux, nftables, DNS, Suricata, OTX, ClamAV, RAM ayarları, TPM veya firmware değiştirilmedi. Canlı cihaza kurulum yapılmadı.

## Geri alma
Bu aşamanın değişiklikleri yalnız yukarıdaki altı dosyadadır. Kaynak seviyesinde geri alma için bu dosyalar Aşama 39 arşivindeki karşılıklarıyla değiştirilebilir; yeni `review_evidence.py` ve `test_stage40_review_evidence.py` kaldırılır. Canlı sistemde ayar/servis geri alımı gerekmez; çünkü kurulum veya servis işlemi yapılmadı.
