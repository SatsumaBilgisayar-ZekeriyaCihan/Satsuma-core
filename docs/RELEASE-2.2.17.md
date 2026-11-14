# SatsumaSecurity 2.2.17

2.2.16'nın Fedora 44 sahasında görülen açılış hatasının düzeltmesi.

- **Açılışta güvenlik duvarı iki kez yazılmıyor.** `nftables.service` ve `satsuma-network.service` aynı tabloyu aynı anda yüklüyordu; kurallar çift yazılıyor, doğrulama başarısız oluyor ve acil durum kilidi bütün ağı kesiyordu. `satsuma-network` artık `nftables.service`'ten sonra başlar.
- **Acil durum kilidinde uzaktan destek açık.** Kilit sırasında da DHCP, NTP, TeamViewer ve AnyDesk dışarıya açık kalır; DNS ve HTTPS kapalı kalır.

Saha kaydı (2026-11-04, Fedora 44, nftables 1.1.3): Satsuma kuralları tek başına yüklendiğinde doğrulamadan geçiyor.
