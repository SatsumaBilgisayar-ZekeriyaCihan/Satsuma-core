# Satsuma Core 2.2.59

## DeepSeek kural güvenliği (sahip, 2026-11-19)

"DeepSeek çok iyi bir özellik ama istismara açık bir alan; kötü niyetli saldırgan buradan kural
yükleyerek ürünü sonsuz döngüye sokabilir." Bir DeepSeek kuralı sahibin onayından geçer, ama içeriğini
saldırganın yazmış olabileceği metni okuyan bir model üretir. `satsuma.ai_guard`, kural ne derse desin:

* **Yükleme:** her regex doğrusal olmalı. Kendi sözcüklerinden ve genel girdilerden (`aaaa…!`) kurulan
  64 KiB metinde, ayrı bir alt süreçte 2 saniyelik kesin sınırla denenir; üstel bir arama bu süreçte
  kesilemeyeceği için motoru kilitleyemez. Eşleştirici başına en çok 16 desen, desen başına 512 karakter.
  Geçemeyen kural yüklenmez; doğrulamada da reddedilir.
* **Genişlik:** 77 gündelik komutun %2'sinden fazlasıyla ya da Satsuma, systemd, polkit, D-Bus veya masaüstü
  komutlarıyla eşleşen kural reddedilir.
* **Çalışma:** DeepSeek kuralları paketli kurallardan sonra ve her biri kendi 20 ms işlemci bütçesiyle
  çalışır; paketli kuralların bütçesini tüketip tespiti kör edemez. 10 dakikada 3 kez bütçeyi aşan kural
  askıya alınır, kritik alarm verilir (SATSUMA-AI-GUARD-001).
* **Durdurma:** DeepSeek kuralı PID 1'i, Satsuma'yı, systemd'yi, polkit'i, D-Bus'ı, oturum yöneticisini ve
  masaüstünü asla durdurmaz. Sahibin etkileşimli yönetim araçlarını (sudo, su, pkexec, gdb, strace...)
  yalnız bildirir: sahip ile parolayı bilen saldırgan orada ayırt edilemez, Satsuma'nın kendi sudo kuralları
  karar verir. Bellek kuralları RAM-001'in güvenilir program istisnasını izler (Firefox'un JIT belleği
  bildirilir, memfd'den ya da /tmp'den çalışan kod durdurulur). Bir kural 10 dakikada en çok 5 süreç
  durdurur; sonra bir saat yalnız bildirir.
* **Sahip:** `sudo satsuma-admin deepseek-kural liste | yalniz-bildir <kimlik> | devre-disi <kimlik> | normal <kimlik>`
  (gevşetmek yönetici parolası ister). En çok 100 etkin DeepSeek kuralı.

## DeepSeek süreç kuralları hiç durduramıyordu

2.2.32'den beri olaylar canlı akıştan gelir ve yalnız kural motorunun belleğinde durur. privd ayrı bir
süreç olduğu için "Satsuma veritabanında aynı sürecin taze kaydı" şartı orada hiç sağlanamıyordu (saha:
`sudo su`, `insufficient_independent_fresh_same_target_evidence`). Akış olaylarında teyidi artık çekirdek
verir: süreç /proc'tan yeniden okunur (PID, başlangıç zamanı, program) ve etkin kural canlı komut satırıyla
yeniden eşleşmelidir; sahte bir olay bunu değiştiremez. Bellek kuralları bellek tarayıcısı kaydı ister.

## Derin motor

* Cron kuralı (derin motordaki SATSUMA-PERSIST-001) yalnız yazmayı sayar; Fedora'nın saatlik cron işi
  (`/etc/cron.hourly`, her saatin 01. dakikası) yazma sanılıyordu.
* On derin motor kimliği kural motorunda başka anlamla da kullanılıyor; kayıtlarda "derin motor kuralı"
  diye belirtilir.
