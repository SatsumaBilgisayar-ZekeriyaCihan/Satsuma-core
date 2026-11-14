# SatsumaSecurity 2.2.31

- **dbus-tools ve unhide artık zorunlu bağımlılık.** D-Bus işçisinin kullandığı `dbus-monitor` kurulu değildi ve paket onu istemiyordu; işçi sistem veri yolunu izleyemiyordu. Araç eksikse işçi artık bunu nedeniyle söylüyor.
- **Gizli süreç ve port taraması (unhide).** Güvenlik taramasından sonra `unhide-linux` ve `unhide-tcp` çalışıyor. Bulunan her gizli süreç, sahte süreç ya da gizli port yeniden denetleniyor; ancak ikinci denetimde de sürerse yüksek önemli bulgu oluyor (SATSUMA-SCAN-002). Tarama sırasında başlayıp biten süreçler atılıyor.
- **Tam kontrol eksik araçları listeliyor.** dbus-monitor, unhide, rkhunter ve suricata-update eksikse kurulum komutuyla gösteriliyor.
- **EdDSA imzalı paketler imzalı sayılıyor.** OpenSnitch paketleri EdDSA ile imzalı; paket imza denetimi onları yanlışlıkla imzasız gösteriyordu.
- **Planlanmış modül kilidi sorun sayılmıyor.** Zamanlayıcı açıksa kilit bir sonraki açılışta başlayacağı için TAMAM gösteriliyor.
