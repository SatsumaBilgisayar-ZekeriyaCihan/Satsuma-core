# Satsuma Core 2.2.44 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## DNS filtresi kendi ağ ad alanında (DEVAM-TALIMATI adım 1)

- dnsmasq geri döndü, ama loopback'te değil: `satsuma-dns` ağ ad alanında,
  yalnızca `169.254.53.2:53` üzerinde dinler. Ana makineyle bağlantısı bir veth
  çiftidir (`satsuma-dns0` 169.254.53.1/30 ↔ `satsuma-dns1` 169.254.53.2/30).
  127.0.0.0/8 ve 53053 hiç kullanılmaz; loopback kapalı kalır.
- Altyapıyı `satsuma-dns-netns.service` (root, oneshot) kurar ve dnsmasq'tan
  önce çalışır; `satsuma-core-dns.service` `NetworkNamespacePath=/run/netns/satsuma-dns`
  ile o ad alanında, yetkisiz kullanıcıyla çalışır ve ad alanı durursa durur.
- DNS kilidi (`satsuma_dns`): loopback dışındaki her DNS sorgusu, program hangi
  sunucuyu sorarsa sorsun, 169.254.53.2'ye yönlendirilir. Yerel çözücünün
  (systemd-resolved 127.0.0.53) dış sorguları da aynı kuralla yakalanır.
- dnsmasq yalnızca OpenDNS'e (208.67.222.222 / 208.67.220.220) sorar. Bu
  sorgular ana makinenin forward zincirinden geçer ve **Suricata kuyruğuna (100)
  girer**; yanıtlar da öyle. Forward zincirinde başka hiçbir şey yoktur
  (varsayılan düşür). 853 hiçbir yerde açılmaz.
- İkinci duvar: `satsuma_dns_ns` tablosundaki forward zinciri de varsayılan
  düşürdür; satsuma_core olmasa bile ana makine dnsmasq'ın DNS'i dışında hiçbir
  şeyi iletmez. Bu yüzden açılan `ip_forward`, ad alanı kaldırılınca eski
  değerine döner.
- Uygulama denetimi açıkken (forward tamamen kapalı) yalnızca ad alanının
  OpenDNS DNS trafiğine izin verir; bu izin satsuma_core'daki Suricata
  kuyruğunu atlatmaz.
- Önce filtre: ağ kipleri, tam kontrol ve operatör aynı sırayı izler —
  filtre başlatılır ve 169.254.53.2'de sınanır, ancak çalışıyorsa kilit
  uygulanır, sonra sistem DNS'i kilit üzerinden sınanır. Çalışmayan filtreye
  yeni yönlendirme yapılmaz; var olan kilit kaldırılmaz.
- Önceden başka bir üst sunucu kaydedilmişse OpenDNS'e çevrilir; eski değer
  `previous_upstream` alanında saklanır. Operatör OpenDNS dışı sunucu giremez.

## Listeler

- Ürün kendiliğinden hiçbir liste indirmez ve hiçbir liste adresi taşımaz:
  HaGeZi ve BlockListProject adresleri, paketlenmiş anlık görüntüleri
  (`/usr/share/satsuma-core/dns-feeds`) ve sağlık denetimindeki liste kontrolü
  kaldırıldı.
- Engellenen adlar Satsuma'nın kendi bulgularından (OTX vb.) ve kullanıcının
  eklediği listelerden gelir. Kullanıcı listesi yalnızca kullanıcı
  eklediğinde/güncellediğinde bir kez indirilir, otomatik yenilenmez; doğrulanan
  adlar `/var/lib/satsuma-core/dns/custom/` altında root'a ait, 0444, HMAC
  imzalı olarak saklanır.

## Kurulum

- Dağıtımın kendi `dnsmasq.service`'i etkin ya da çalışıyorsa durdurulur,
  devre dışı bırakılır ve maskelenir; `/etc/dnsmasq.conf`, `/etc/dnsmasq.d/*`
  ve `dns=dnsmasq` içeren NetworkManager dosyaları silinmez,
  `/var/lib/satsuma-core/evidence/dnsmasq-TARİH/` klasörüne taşınır.
- NetworkManager `satsuma-dns0`'ı yönetmez
  (`/usr/lib/NetworkManager/conf.d/90-satsuma-dns.conf`). firewalld çalışıyorsa
  veth yalnızca çalışma zamanında güvenilen bölgeye alınır.

## Cihazda doğrulama

```
systemctl status satsuma-dns-netns satsuma-core-dns
sudo ip netns exec satsuma-dns ss -lunt        # yalnız 169.254.53.2:53
sudo nft list chain inet satsuma_core forward  # yalnız satsuma-dns0, queue num 100
dig example.com                                 # yanıt gelmeli
sudo satsuma-admin bakim
```

## Açık konu

- SATSUMA-FILELESS-002'nin 3 saniyede bir tekrarı: çalıştırılan dosyanın yolu
  (panelde "Teknik ayrıntılar") bekleniyor.
- Dashboard baştan tasarımı sıradaki iş.
