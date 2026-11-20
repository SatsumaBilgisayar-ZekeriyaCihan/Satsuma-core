# Satsuma Core 2.2.63

## DNS filtresi (saha 2026-11-20)

- **Şifreli DNS (DoH) atlatması kapatıldı.** `dns.google` ve `doh.opendns.com` çözülüyordu. Sistem çözümleyicisi
  OpenDNS olduğu için Chromium tabanlı tarayıcılar (Brave, Opera) kendiliğinden OpenDNS'in DoH sunucusuna geçip
  sorguları filtrenin yanından gönderir. Bilinen DoH sunucu adları ürünün içinde engellidir (indirilen liste
  değil); Firefox'un `use-application-dns.net` denetim adı NXDOMAIN döner, Firefox kendi DoH'unu kapatır.
- **OTX güncelleme sunucularını engellemez.** Bir OTX pulse'ı `fedoraproject.org`'u engel listesine koymuştu;
  bir sonraki tam yüklemede Fedora güncellemeleri duracaktı. OTX otomatik engeli fedoraproject.org,
  getfedora.org, flathub.org, snapcraft.io ve snapcraftcontent.com'u (ve alt adlarını) almaz; sahibin kendi
  listeleri yine engelleyebilir. fedorapeople.org kapsam dışı (herkesin dosyası).
- **Yeni engellenen adlar hemen geçerli.** core-otx dnsmasq'a sinyal gönderemiyordu ("dnsmasq could not re-read
  the added names"); yeni adlar 30 dakikalık tam yüklemeyi bekliyordu. Şimdi `systemctl reload` ile systemd
  gönderir (`ExecReload`).

## Satsuma kendi işini durdurmaz

- dns-netns'in kapanış adımındaki `nft delete table inet satsuma_dns_ns` GAP-023 ile durduruluyordu: komut ana
  süreçten değil ExecStop sürecinden geliyordu. Satsuma'nın kendi süreci olarak tanınan bir sürecin doğrudan
  çocukları (kabuk hariç) 2 dakika boyunca aynı birimden sayılır.

## Yeniden başlatma sınırı kaldırıldı (sahip: "ürün zayıflıyor")

- 30 dakikada 3 sınırı, bir koruma servisini dört kez öldüreni yarım saat kazandırıyordu. Tek defter
  (`satsuma.repair_budget`): yeniden başlatma hiç durmaz; 3'ten sonra aralık 2, 4, 8, en fazla 10 dakika.
  Tekrar tekrar düşen birim kritik SATSUMA-HEALTH-RESTART-001. self-health, maintenance, flow-guard ve
  firewall-watch aynı defterden izin alır; birbirini 60 saniye içinde yeniden başlatamaz.

## hidepid kalıcı: `sudo satsuma-admin hidepid ac|kapat|durum`

- fstab'a `hidepid=invisible,gid=satsuma-proc`; polkit, logind, rtkit, NetworkManager, COSMIC giriş ekranı ve
  Satsuma taraması muaf grupta. Bir sonraki açılışta geçerli. `kapat` parola ister. Elle açılan hidepid
  açılışta kayboluyor, tarama servisi süreçleri göremeyince unhide 1456 sahte "gizli süreç" bildiriyordu.

## Güncelleme

En sıkı mod açıkken (2.2.62'den beri) Satsuma güncellemesi durdurulur:
`sudo satsuma-admin en-siki-mod kapat` → güncelle → yeniden başlat → `sudo satsuma-admin en-siki-mod ac`.
