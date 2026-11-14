# Otomatik süreç sonlandırma

Her kuralın bulgusu merkezi AutoActionEngine değerlendirmesine girer; YAML
dosyalarına koşulsuz kill aksiyonu eklenmez. `log_only` de dahil bütün bulgular
değerlendirilir. Bir faaliyet göstergesi tek başına sonlandırma yetkisi vermez.

Politika: `response_enabled`, `destructive_response_enabled` ve
`auto_action_process_enabled` açık olmalı; `destructive_allowed_actions`
listesinde `process_kill` bulunmalıdır. Paket örnek yapılandırması bunları
etkinleştirir. Genel response kapalıysa sonlandırma yapılmaz. Mevcut kurulumda
operatörün kapattığı response veya açıkça kapattığı süreç politikası korunur.

Brain aynı turda sys_proc, audit veya memory sensörlerinden gelen bulguları
karşılaştırır. Aynı PID, başlangıç zamanı ve executable için iki farklı gerçek
sensör ve iki farklı kural gerekir. Bulgular high/critical öneminde,
suspicious/likely sınıfında ve son 60 saniyeye ait olmalıdır. Indicator sınıfı,
aynı sensörden çok sayıda eşleşme veya yalnızca ekip etiketleri doğrulama
oluşturmaz. Bu korelasyon bir politika kararıdır; saldırı başarısını kanıtlayan
adli inceleme değildir. Gerçek sensörlerden üretilmiş bağımsız kanıt taşıyan
confirmed bulgular da değerlendirilir.

Bellek kod bütünlüğü için ayrı doğrulama yolu vardır: SATSUMA-RAM-005
bulgusundaki kod farkı canlı süreçte tekrar karşılaştırılır. Fark ve süreç
kimliği doğrulanırsa etkin process_kill politikası altında ikinci sensör
beklenmeden sonlandırma uygulanır. Bu, debugger/hotpatch ile değiştirilmiş
kodda da uygulanabilen açık bir kod bütünlüğü politikasıdır.

Hedef kimliği algılama olayından gelir. PID tek başına yeterli değildir;
başlangıç zamanı ve executable canlı süreçle karşılaştırılır. Eksik kimlik
sonradan canlı süreçten alınarak uydurulmaz. Bellek sensörü artık başlangıç
zamanını da taşır. Dosya veya ağ olayından sorumlu yerel süreç güvenilir biçimde
belirlenemiyorsa rastgele süreç sonlandırılmaz.

Sonlandırma Linux pidfd ile yalnızca doğrulanmış süreç örneğine SIGTERM gönderir;
bir saniyede çıkmazsa korumaları tekrar kontrol edip SIGKILL gönderir. Çıkış
pidfd üzerinden doğrulanır; doğrulanamazsa `termination_pending` kaydedilir.
Süreç ağacına veya ada göre toplu kill yapmaz. pidfd desteklenmiyorsa hata
kaydedilir; kimliği belirsiz PID sinyaline geri dönülmez.
Replay, operatör duraklatması, bütünlük sorunu, kritik sistem/Satsuma süreçleri
ve değişmiş süreç kimliği mevcut korumalarla engellenir. Karar ve sonucu
actions kayıtlarına yazılır; `signal_sent` gerçek sinyal gönderimini,
`exit_verified` süreç çıkışının doğrulanmasını belirtir.

Doğrulama: `PYTHONPATH=source QT_QPA_PLATFORM=offscreen python -m pytest -q
source/tests/test_auto_process.py`. Testler yalnızca kendilerinin başlattığı
geçici sleep süreçlerini sonlandırır. Gerçek Fedora host, saldırı trafiği veya
üretim kurulum kabul testi yerine geçmez.
