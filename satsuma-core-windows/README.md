# Satsuma Core — Windows 11

Satsuma Core 2.2.36'nın Windows 11 karşılığı. Ağırlıklı Python; Windows'un kendi araçlarını (Windows Güvenlik Duvarı, DNS istemcisi, bağlantı tablosu) kullanır. Sürüm **0.1.0**: geliştirme aşaması. `satsuma-core-windows.exe` GitHub Actions'ın Windows sunucusunda derlenir; 853 kapatma ve DNS kilidi sahibinin Windows 11 makinesinde 2026-11-11'de çalıştı.

## Bu sürümde (aşama 1: ağ ve MITM koruması)

| Koruma | Nasıl | Linux ürünüyle |
|---|---|---|
| Gelen bağlantı yok | Güvenlik duvarı üç profilde açık, gelen bağlantılar ve izinli uygulamalar listesi engelli; Uzak Masaüstü, Uzak Yardım, WinRM, dosya/yazıcı paylaşımı (SMB, SMB1) ve Uzak Kayıt Defteri kapalı; dakikada bir denetlenir, değişirse geri yazılır | Sahibinin kuralı: uzak destek yalnızca dışarıya |
| 853 portu kapalı (TCP ve UDP, dışa) | Windows Güvenlik Duvarı engel kuralı | Aynı sabit kural |
| DNS kilidi | Bağlı her bağdaştırıcıda OpenDNS 208.67.222.222 / 208.67.220.220; modemin DHCP DNS'i kullanılmaz; çözümleme sınanır | Aynı sunucular |
| PTR'siz uç 6. bağlantıda engellenir | Bağlantı tablosu + PTR sorgusu; CDN'ler dahil gevşetilmez | **Ortak kod** (`satsuma.peer_watch`) |
| Alt ağ sınırı | Aynı /24 içinde 300 sn'de 10 farklı uç | Aynı kural |
| Asla engellenmeyenler | Modem, DNS sunucuları, TeamViewer/AnyDesk uçları | Aynı |

## Bellek imza taraması (RAM v2, ClamAV)

Hizmet ayrı bir iş parçacığında süreç belleğini Satsuma'nın kendi ClamAV'ına (clamd) taratır. Tarama Linux'la ortak motordur (süreç başına en çok 4 MiB / 2 sn'lik turlar, yeni süreç önce); bir imza ancak aynı baytlar yeniden okunup yeniden aynı imzayı verirse sayılır. Ortak kural SATSUMA-RAM-106 süreci durdurur (durdurmadan önce aynı tutamaçla bir kez daha doğrulanır); sezgisel/PUA bulgusu SATSUMA-RAM-107'dir ve yalnızca kaydedilir. Windows'un kritik süreçleri, Satsuma, kendi clamd/freshclam'ı, uzak destek ve masaüstü durdurulmaz.

ClamAV 1.5.4 kurulumda GitHub'daki resmi sürümden indirilir; Windows programları imzasız olduğu için arşivin ve her dosyanın SHA-256'sı sabittir, tutmazsa kurulmaz. Dosyalar `C:\Program Files\Satsuma\ClamAV`, veritabanı `C:\ProgramData\Satsuma\clamav` altındadır; freshclam veritabanını kurulumda ve dört saatte bir indirip imzasını doğrular. clamd hizmetin alt sürecidir: yalnızca 127.0.0.1, en çok 2 GiB bellek, hizmetle birlikte kapanır. Bilinen sınır: yerel bir program 127.0.0.1'deki clamd'yi meşgul edebilir; tarama o zaman "DEGRADED" bildirir, asla temiz demez. Kapsam tüm RAM değildir; durum `state.json` içinde `ram_signatures` altındadır.

## Hizmet olarak kurulum

Bekçi gerçek bir Windows hizmetidir: **Satsuma Core** (`SatsumaCore`). Otomatik başlar, LocalSystem olarak çalışır, durursa bir dakika içinde yeniden başlatılır. Exe `C:\Program Files\Satsuma` klasörüne kopyalanır; o klasöre yönetici ve SYSTEM dışında biri yazabiliyorsa kurulum reddedilir. Kurulum sihirbazı (Inno Setup) bunu kendisi yapar; elle: `satsuma-core-windows.exe --install`, durum `--status`, kaldırma `--uninstall`. GitHub'daki her derlemede hizmet Windows sunucusunda kurulup doğrulanır ve kaldırılır.

Her engel, Windows Güvenlik Duvarı kuralı geri okunup "etkin" görülünce başarılı sayılır. Her karar `%ProgramData%\Satsuma\events.jsonl` dosyasına yazılır; durum `state.json` dosyasındadır.

## Sonraki aşamalar

2. Süreç izleme ve durdurma (Sysmon olay günlüğü + Satsuma kural motoru; derleme aracı engeli dahil)
3. Dosya taraması ve bütünlük (Windows Defender / ClamAV; ayar dosyaları için örnek ve karşılaştırma)
4. Qt paneli
5. Kurulum paketi: GitHub Actions'ın Windows sunucusunda üretilir; kullanıcının makinesinde derleme yapılmaz

## Geliştirme

Testler sahte PowerShell ve sahte bağlantı tablosuyla Linux'ta da çalışır:

```sh
cd satsuma-core-windows && python3 -m pytest -q tests
```

Windows'ta deneme: GitHub Actions'ın ürettiği `satsuma-core-windows.exe` dosyasını yönetici PowerShell'de `satsuma-core-windows.exe --once` ile çalıştırın. Kaynaktan çalıştırmak için `satsuma-core-windows` klasöründe `$env:PYTHONPATH` depo kökünü gösterecek şekilde: `python -m satsuma_win.guard --once`.

---

Windows 11 counterpart of Satsuma Core 2.2.36, mostly Python, using Windows Firewall, the Windows DNS client and the Windows connection table. Stage 1 (network and interception protection) is implemented and unit-tested; it has not run on a real Windows 11 machine yet.
