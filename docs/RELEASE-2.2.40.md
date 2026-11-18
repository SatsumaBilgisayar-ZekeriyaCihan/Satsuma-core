# Satsuma Core 2.2.40 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## Fedora Atomic saha raporu (2.2.39, 2026-11-18)

2.2.39 Atomic'te kuruldu: bütünlük doğrulandı (536 dosya), derin motor,
reader, olay akışı ve çekirdek bekçisi çalışıyor. Kalanlar:

- İlk açılış betiği dört kez denendi ("start of the service was attempted too
  often", satsuma-deep-engine ve satsuma-clamonacc). Neden: güncellemeden sonra
  etkin birimler açılışta önceki imaja karşı başlayıp doğrulanamıyor ve başlatma
  sınırına takılıyordu. Betik artık %posttrans'tan önce
  `systemctl reset-failed 'satsuma-*'` çalıştırır.
- Bakım kiti satsuma-quarantine-rollback için "başlatılamadı: inactive" diyordu:
  birim yalnızca bekleyen karantina varsa çalışır (ConditionDirectoryNotEmpty).
  Koşulu sağlanmayan birim artık sorun sayılmaz.
- Paketin kurulumda etkinleştirmediği ama başarısız durumdaki birimler
  (satsuma-core-dns gibi) bakım kitinde hiç görünmüyordu; artık bildirilir ve
  sınırlı olarak yeniden başlatılır.

## Cihazda bakılacaklar (kodla çözülmedi)

- self-health: `competing_ips`: dağıtımın suricata.service'i etkin/çalışıyor ve
  Satsuma IPS ile kuyruk 100 için çakışıyor. Ürün kuralı gereği yalnızca
  bildirilir: `sudo systemctl disable --now suricata.service`.
- self-health: satsuma-core-dns ve DNS filtresi başarısız; nedeni cihaz günlüğünde
  (`journalctl -u satsuma-core-dns -b`). `sudo satsuma-kur` henüz çalıştırılmadı.
