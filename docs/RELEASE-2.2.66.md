# Satsuma Core 2.2.66

Saha denetimi 2026-11-20 (2.2.64):
- boot-lockdown /etc/cron.daily yazamıyordu ve birimin tamamı düşüyordu; yazma izni eklendi, adım hata verirse yalnız rapora yazılır. rkhunter posta cron işi kapanır.
- Yasaklı paket alarmı rpm-ostree RemovedBasePackages listesinden okunur (s-nail temel imajda; saatlik yanlış kritik alarm biter). s-nail çalışırsa yine durdurulur (GAP-076).
- Satsuma tarafından yazılmış tarayıcı politikası her güncellemede yenilenir (Firefox dil eklentisi engeli).
- 2.2.65 dahil: bootc geçici kopyası içerik doğrulamasıyla FILELESS-002 sayılmaz.

Açık: core-audit, maintenance, mitm-watch, module-lock, temporary-scan birimlerinin düşme nedeni (günlük bekleniyor).
