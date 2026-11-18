# Satsuma Core 2.2.41 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.
Fedora Atomic cihazında denenmedi.

## Suricata'dan geçmeyen kanal kalmadı (sahibinin isteği)

- 2.2.16'dan 2.2.40'a kadar DHCP (UDP 67), NTP (UDP 123), TeamViewer
  (TCP/UDP 5938) ve AnyDesk (TCP 6568) Suricata kuyruğuna girmeden kabul
  ediliyordu. Artık her profilde 100 numaralı kuyruktan geçerler; dönüş
  paketleri de. Acil durum kilidi tablosu da aynı kanalları kuyruğa yollar.
- Sonuç: Suricata durursa (kuyruk bağlantısı yoksa paket düşer, `bypass` yok,
  Suricata `fail-open: no`) DHCP yenileme, saat eşitleme ve uzaktan destek de
  durur.
- Loopback (lo) makineden çıkmaz, kuyruğa alınmaz: yalnızca yanıtlar, yerel
  DNS (53) ve TeamViewer'ın yerel servisi (5939) geçer.
- nftables kurallarının dışında kalan: ham paket soketleri (AF_PACKET; root ya
  da CAP_NET_RAW gerekir; DHCP'nin ilk keşfi ve ARP bu yolla gider). Bunlar
  inet filtre kancalarına hiç uğramaz.

## RAM-001: Snap ve Flatpak uygulamaları kapatılıyordu

- Snap (snap-confine) ve Flatpak (bubblewrap) uygulamaları kendi bağlama ad
  alanlarında çalışır; ana sistemden yolları `/snap/<ad>/<sürüm>/...` ya da
  `/app/...` görünür ve ana sistemde yoktur. Güvenilir program denetimi yolu
  bulamadığı için bu uygulamalar durduruluyordu (benzetimle yeniden üretildi).
- Yol bulunamazsa çekirdeğin çalıştırdığı dosyanın kendisine (/proc/PID/exe)
  bakılır: root'a ait ve kimsenin yazamadığı dosya kaydedilir, durdurulmaz.
  Kullanıcının kendi dosyası, kullanıcıya kurulu Flatpak, rootless kapsayıcı
  imajı ve memfd yine durdurulur.

## Panel açılmıyordu (Fedora Atomic)

- rpm-ostree paket gruplarını /usr/lib/group'ta tutar; masaüstü kaydındaki
  `usermod -a -G satsuma-reader` yalnızca /etc/group'u düzenler ve "grup yok"
  diye düşüyordu; başlatıcı parola sorduktan sonra sessizce kapanıyordu.
- Kayıt artık grubu usermod'dan önce /etc/group'a (ve /etc/gshadow'a) kopyalar
  (shadow-utils kilidi altında, dosya yerinde düzenlenir).
- Başlatıcı başarısız kaydı bir pencerede nedeniyle gösterir (iptal, yanlış
  parola ya da kayıt hatası).
