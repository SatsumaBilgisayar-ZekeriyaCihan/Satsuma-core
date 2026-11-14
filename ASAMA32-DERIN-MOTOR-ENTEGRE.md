# Aşama 32 — Satsuma Engine sınırlı asenkron canlı kanıt hattı

## Uygulanan
- `satsuma_engine/live_lane.py`: ayrı iş parçacığında çalışan, sınırlandırılmış olay kuyruğu (256), kanıt kuyruğu (128), 48 olaylık pencere ve 8 olaylık mikro-batch. 30 saniyeden eski olaylar pencereden çıkarılır. Ekleme bloklamaz; taşmalar sayaçla raporlanır.
- `run_satsuma_teams.py`: her canlı akış olayı Smart Rules sonrası `deep_lane.submit(event)` ile motor kuyruğuna gönderilir. Motorun analizini beklemez. Motor sonuçları mevcut otomatik aksiyon/sonlandırma çağrılarından **ayrı**, yavaş periyodik döngüde `deep_engine_evidence` türünde yalnız kanıt olarak yazılır.
- Başlangıçta Satsuma Engine'in paket içi 20 kuralı yüklenir. Hata olursa motorun başlamadığı `errors` ve `flow.health.deep_engine` alanlarında görünür; Smart Rules çalışmaya devam eder.
- Derin kanıt kaydı yalnız bulgu kimliği, kural kimliği, seviye, kanıt türü, `authorization=none` ve pencere olay sayısını içerir. Komut, özel ortam değişkeni, dosya yolu veya motorun kendi eylem komutları kayda taşınmaz.
- `tests/test_deep_live_lane.py`: olay/kuyruk, hata, kanıt sınırı ve bağlantı testleri.

## Doğrulama
- 74 seçili test geçti: `tests/test_deep_live_lane.py`, `tests/test_short_event_evidence.py`, `tests/test_engine.py`, `tests/test_flow_stream.py`, `tests/test_flow_owner.py`, `tests/test_flow_evidence.py`, `tests/test_multiengine_gate.py`, `tests/test_brain_latency.py`, `tests/test_brain_phase_timing.py`.
- Sözdizimi/compileall geçti.
- Hedef Fedora donanımı, panel, RPM kurulumu ve gerçek zamanlı gecikme testi **yapılmadı**.

## Bilinçli sınırlar ve kalan iş
- Bu aşama derin motoru **kanıt toplama** hattına bağlar. Derin bulgular sonlandırma yetkisi vermez; bağımsız yetki/kimlik doğrulaması olmadan bunu değiştirmek yasaktır.
- `run_satsuma_teams._run_once` içindeki senkron takım taraması ve `CorrelationEngine`, Findings persistans araştırması ve `sys_proc`/D-Bus köken güvenilirliği ayrıştırması henüz tamamlanmadı. Bu yüzden tam mimari göç tamamlanmış değildir.
- Mikrobatch başına pencere yeniden taranır; iş yükü CPU maliyetini artırabilir. Kuyruk dolarsa olay kaybı raporlanır. Görevler process isolation yerine thread içinde; CPython GIL nedeniyle ciddi CPU yükü hızlı akışa etkide bulunabilir. Sonraki aşamada ayrı, rootless worker ve IPC tasarlanmalıdır.
- 20 mikrosaniye karar süresi ve uçtan uca müdahale gecikmesi ölçülmemiştir. Ürünün gerçek koruma kapasitesi için hedef cihaz testi şarttır.
- Hiçbir root, TPM, RAM, DNS, nftables, Suricata, OTX, SELinux veya systemd servis ayarı değiştirilmedi.

## Geri alma
- `run_satsuma_teams.py` dosyasını 31. aşama ZIP sürümüne döndürün; `satsuma_engine/live_lane.py` ve `tests/test_deep_live_lane.py` dosyalarını kaldırın. Canlı servis, paket ya da cihaz değişikliği yapılmadığı için host rollback gerekmiyor.
