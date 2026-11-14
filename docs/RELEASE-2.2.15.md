# SatsumaSecurity 2.2.15

2.2.14'ün yerini alır ve onun her şeyini içerir. Kurulumdan sonra yeniden
başlatın; ardından `sudo satsuma-admin tam-kontrol` her maddeyi TAMAM ya da
SORUN olarak gösterir.

## Sistem programları (/bin, /sbin): karantina önerisi, açılmazsa geri alma

- Denetim, paketlere ait olmayan, paketindekinden farklı, yerel ya da saldırı
  aracı olan programları doğru ayırır. Sistemin açılması için gerekli
  programlar hiçbir zaman karantinaya önerilmez.
- Önerilen bir programı panelden ya da
  `sudo satsuma-admin karantina al` ile karantinaya alabilirsiniz.
  Sonraki açılış tamamlanmazsa (bilgisayar açılıp 5 dakika çalışır duruma
  gelmeden yeniden başlarsa) program bir sonraki açılışta **kendiliğinden
  geri konur**. `sudo satsuma-admin karantina geri-al <kimlik>`
  ile her zaman geri alınabilir.

## SSH anahtarları: "bilginiz dahilinde mi?"

- Her yetkili anahtar ve özel anahtar size sorulur; kendiliğinden hiçbir şey
  yapılmaz. **Tanıyorum** derseniz bir daha sorulmaz. **Tanımıyorum** derseniz
  karantinaya alınır: authorized_keys içinden yalnızca o satır çıkarılır ya
  da özel anahtar dosyası taşınır; ikisi de geri alınabilir.
- SSH sunucusu açıksa uyarılır; isterseniz kapatılır.
- Panel: Antivirüs ve Rootkit Taramaları ekranı. Terminal:
  `sudo satsuma-admin ssh liste | tanidik | karantina | sunucu-kapat`.

## Yeni denetimler

- **Python betikleri:** gizlenmiş kod çalıştırma, ters kabuk, indir-çalıştır,
  kalıcılık ve parola toplama izleri.
- **Man, SVG, PNG ve font dosyaları:** içine gizlenmiş betik ya da veri.
- **systemd:** açılış süreleri (systemd-analyze), paketindekinden farklı
  systemd dosyaları, sonradan eklenen ya da /tmp, gizli klasör, `-c`,
  LD_PRELOAD kullanan birimler, generator'lar.
- **Açılış sorun eşleyici:** açılıştaki hataları bulgularla birleştirip tek
  cümleyle anlatır.

## DNS: OpenDNS ile başlar

- Satsuma'nın DNS filtresi artık **OpenDNS**'e sorar (208.67.222.222; yanında
  208.67.220.220). Bilgisayardaki bütün DNS sorguları bu filtreden geçer.
- Önceden modemden otomatik alınmış üst sunucu yükseltmede bir kez
  OpenDNS'e geçer. Panelde kendiniz seçtiğiniz sunucu korunur.

## Ortadaki adam izleyicisi (her dakika)

- **DNS:** resolv.conf değiştirilmiş mi, NetworkManager'ın bilmediği bir DNS
  sunucusu yazılmış mı, DNS filtresinin üst sunucusu değişmiş mi.
- **Rotalar:** başka bir sunucunun adresini bu makineye ya da DNS sorgularını
  başka bir ağ geçidine yönlendiren rotalar, fazladan yönlendirme kuralları,
  varsayılan rotanın değişmesi.
- **Ağ profilleri:** VPN, proxy, sabit rota ya da kendi DNS'i olan
  NetworkManager profilleri; yeni eklenen profil.
- **Çekirdek ağ ayarları:** route_localnet, rp_filter (sıkı), kaynak
  yönlendirme ve ICMP yönlendirmeleri. Değiştirilirse **hemen geri yazılır**
  ve bildirilir.
- **Uzak erişim:** dışarıdan bağlantı kabul eden SSH, VNC, RDP, TeamViewer,
  AnyDesk; AnyDesk'in gelen oturum ayarları.
- **DNS filtresinin üst sunucusu bu sunucularla sabitlenir:**
  `/etc/satsuma-core/dns-pinned.json` (OpenDNS). Dışına çıkılırsa yüksek
  önemde bildirilir.

## Tek root görevlisi (satsuma-privd), 1. aşama

- IP engelleme ve süreç durdurma işlerini tek bir root servisi yapar; her
  istek kaydedilir. privd'ye ulaşılamazsa koruma durmaz, servisler işi
  kendileri yapar.
