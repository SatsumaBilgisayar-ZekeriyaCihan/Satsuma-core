# SatsumaSecurity 2.2.30

- **Yeni görünüm: siyah zemin, turuncu vurgu.** Bütün panel yeni renklerle geliyor. Durum renkleri vurgudan ayrı: yeşil sağlıklı, kehribar uyarı, kırmızı-turuncu kritik.
- **Kayıtlar ekranı.** Sol menüde yeni "Kayıtlar" bölümü var. Veritabanındaki her kayıt türü sade adı ve son 1 saat, 24 saat ya da 7 günlük sayısıyla listeleniyor. Bir tür seçilince ne olduğu, neden önemli olduğu ve en yeni kayıtları düz cümleyle görünüyor; ham kayıt istenince açılıyor. Tanımsız türler gizlenmiyor.
- **İnceleme bulguları süreci gösteriyor.** "Etkileşimli root shell isteği" gibi bulgularda süreç ve PID artık "Bilinmiyor" yazmıyor; kaynak olayın programı, kullanıcısı ve komutu geliyor.
- **OpenSnitch.** OpenSnitch kurulu ve çalışıyorsa uygulama izinlerini o veriyor; Satsuma App Control kenara çekiliyor ve OpenSnitch durursa kendiliğinden geri geliyor. Satsuma yalnızca kendi kurallarını yazıyor (etkin WireGuard portu, DNS filtresi). Kurulum artık OpenSnitch'i kapatmıyor.
- **App Control hızlandı.** Yalnızca her bağlantının ilk paketi inceleniyor. Eskiden her paket kuyruktan geçiyordu ve interneti yavaşlatıyordu.
- **WireGuard.** VPN'in şifreli paketleri App Control'den geçiyor. İçe aktarılan profil listede hemen görünüyor; NetworkManager profili içe aktarırken bağlarsa bağlantı kesiliyor, bağlanmak önce portu açan ayrı adım olarak kalıyor. İçe aktarma başarısız olursa nedeni WireGuard satırında kalıyor.
- **Suricata yapılandırması otomatik.** Her başlangıçta sistemdeki suricata.yaml'dan Satsuma'nın kendi yapılandırması üretiliyor: bilgisayarın kendi ağı (HOME_NET), kurallar, EVE günlüğü ve satır içi ayarlar. Paketin dosyasına dokunulmuyor. Eksik kurallar tam-kontrol'de indiriliyor; kurulum artık kural istemiyor.
- **Çekirdek modül kilidi çalışıyor.** Açılıştan 3 dakika sonra yeni çekirdek modülü yüklenmesi kilitleniyor; WireGuard ve güvenlik duvarı modülleri önceden yükleniyor. Bir sonraki açılıştan itibaren geçerli.
- **Paket imza denetimi.** dnf'te ve etkin depolarda imza denetimi açık olmalı; tam-kontrol kapalı olanı açıyor (eski dosyanın tarihli kopyası saklanıyor). İmzasız kurulu paketler listeleniyor.
