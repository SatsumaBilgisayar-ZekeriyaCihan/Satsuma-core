# SatsumaSecurity 2.2.13 — tam sürüm

2.2.11 ve 2.2.12'nin yerini alır ve ikisinin her şeyini içerir. Kurulu
sürümün üstüne `kur.sh` ya da `yama.sh` ile kurulur.

## Yeni: loopback (lo) kapalı

- `satsuma_core` güvenlik duvarında `lo` üzerindeki her trafik düşürülür.
- Yalnızca şunlar geçer: kurulmuş bağlantıların cevapları, DNS çözücüsü
  (53), Satsuma DNS filtresi (53053) ve TeamViewer'ın yerel servisi (5939).
- Eski "lo'ya her şey serbest" kuralı kaldırıldı.
- Yükseltmede eski tablo güvenle yeni düzene geçirilir; engellenen
  adresler korunur. Önceden bu durumda bütün trafik kesilebiliyordu.
- Bilinen etki: `localhost` üzerinden çalışan başka programlar (ör.
  yazıcı servisi CUPS 631) çalışmaz. Gerekirse portu eklemek için söyleyin.

## Yeni: parolasız sudo engeli

- `sudo -n` ya da `sudo -S` ile parola sorulmadan root olmaya çalışan
  program durdurulur.
- `/etc/sudoers` ve `/etc/sudoers.d` içindeki her `NOPASSWD` satırı
  dosyası ve satırıyla kritik bulgu olarak bildirilir. Dosyalar
  kendiliğinden düzenlenmez (yanlış düzenleme sizi root'tan keser);
  kaldırmak için `sudo visudo -f <dosya>`.

## Yeni: /bin ve /sbin denetimi

- `/usr/bin`, `/usr/sbin` (Fedora'da `/bin` ve `/sbin` buraya bağlı),
  `/usr/local/bin` ve `/usr/local/sbin` günde bir kez ve her elle taramada
  paket veritabanıyla karşılaştırılır:
  - **paketsiz program** (hiçbir pakete ait değil) → yüksek,
  - **değiştirilmiş program** (paketindeki özetten farklı) → kritik,
  - **saldırı aracı** (nmap, ncat, socat, hydra, metasploit, ettercap,
    bettercap, tcpdump…) → hangi paketten geldiğiyle bildirilir.
- Paketsiz ve değiştirilmiş programlar VirusTotal'a **yalnızca SHA-256
  özetiyle** sorulur, dosya gönderilmez. Bunun için anahtar gerekir
  (aşağıda).
- VirusTotal'da en az 3 motor zararlı diyorsa ya da ClamAV bulduysa
  program karantinaya alınır. Yalnızca şüpheli olan sistem programı
  taşınmaz; gerçek bir sistem programını taşımak makineyi açılmaz
  yapabilir.

## Virüs taraması (2.2.11'den)

- ClamAV servisi cevap vermezse `clamscan` ile taranır; ClamAV'ın hata
  mesajı sayfada görünür.
- `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/bin`, `/usr/sbin` de
  taranır.
- Bulunan dosyalar kendiliğinden karantinaya alınır
  (`/var/lib/satsuma-core/scan-quarantine`; silinmez).
- Tarama servisi artık her birkaç dakikada "Başarısız" görünmez.

## Güvenlik duvarı ve diğerleri (2.2.11, 2.2.12'den)

- `nftables.service` açılışta Satsuma güvenlik duvarını da yükler; durdurma
  ya da yeniden yükleme Satsuma tablolarını silmez.
- Elle değiştirilmiş `/etc/satsuma-core/nftables.nft` artık ağı kesmez:
  `nftables.nft.elle-degistirilmis-<tarih>` olarak saklanır ve doğru dosya
  yeniden yazılır.
- Güvenlik aksiyonlarında "Neden" sütunu dolu; sıradan etkinlikler
  (sudo, systemctl, git…) "Yalnızca bildirildi" diye görünür.
- "Cross-team" kritik bulguları programın adını ve komut satırını yazar.
- Otomatik ağ engelinde kalan son kota kaldırıldı.
- `dns_monitor`, `evidence`, `response` "Etkin" görünür.

## Anahtarlar

- **VirusTotal** (ücretsiz hesap yeterli): anahtarı aldıktan sonra
  ```
  read -rs -p "VirusTotal anahtarı: " k; echo
  printf '%s' "$k" | sudo install -m 0640 -o root -g root /dev/stdin /etc/satsuma-core/virustotal.key
  unset k
  ```
- **DeepSeek**: aynı şekilde `/etc/satsuma-core/deepseek.key`
  (`-g satsuma-reader`).

Kurulumdan sonra: `sudo satsuma-admin tam-kontrol`.
