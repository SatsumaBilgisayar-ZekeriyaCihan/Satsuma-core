# SatsumaSecurity 2.2.33

2.2.32'nin sahada görülen sorunlarının düzeltmesi.

- **Durdurma teyidi yeniden çalışıyor.** 2.2.32'de kanıt isteyen her durdurma "satsuma_database_confirmation_missing" ile reddediliyordu: teyit, artık yazılmayan ham kayıtları veritabanında arıyordu. Teyit artık kural motorunun bellekteki akışından yapılıyor.
- **Durdurulan program masaüstünde bildiriliyor.** Servisler root olarak oturum dışında çalıştığı için bildirimleri ekrana hiç ulaşmıyordu; AnyDesk durdurulduğunda uyarı görünmemesinin sebebi buydu. Oturum açılınca "Satsuma bildirimleri" kendiliğinden başlıyor ve her durdurulan program için program adı, PID ve kuralı gösteriyor.
- **Güncellenen program "silinmiş dosya" sayılmıyor.** Paketi güncellenen çalışan programlar (ör. /usr/bin/anydesk) silinmiş dosyadan çalışıyor görünüyordu. Aynı yolda yine root sahipli dosya varsa uyarı verilmiyor. /tmp ya da ev klasöründen çalıştırılıp silinen program yine şüpheli.
- **DNS filtresi OTX yüzünden düşmüyor.** OTX listesi her değiştiğinde dnsmasq bütün Ultimate listesiyle yeniden başlıyor ve "readiness timed out" hatası veriyordu. Yeni engellenen alan adı hemen uygulanıyor, süresi dolanlar en fazla 30 dakikada bir kaldırılıyor.

Not: AnyDesk ve TeamViewer yalnızca paket olarak kurulduklarında (/usr/bin, root sahipli) korunur. Ev klasöründen çalıştırılan bir kopya korunmaz; zararlı bir program da kendine "anydesk" adını verebilir.
