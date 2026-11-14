# SatsumaSecurity 2.2.9 — tam koruma

2.2.8'in yerini alır ve onun her şeyini içerir.

## Değişen: bütün işlevler kutudan çıktığı gibi açık

Ürün artık işlevlerini kendisi açıyor; kurulum betiğine, eski bir ayar
dosyasına ya da panelde "aç" demenize bağlı değil. Eski bir `policy.json`
"kapalı" yazsa bile 2.2.9 açık çalışır.

Açık gelenler:

- Yanıt (engelleme) ana anahtarı. 2.2.8'e kadar kurulum betiği bunu her
  kurulumda zorla **kapatıyordu**; bu yüzden ağ engeli, OTX engeli ve
  benzerleri hiç çalışmıyordu.
- Bütün yıkıcı eylemler: ağdan yalıtma (IP engeli), program durdurma, dosya
  karantinası, kullanıcı devre dışı bırakma.
- Otomatik ağ engeli ve otomatik program durdurma.
- OTX sorgusu ve OTX eşik engeli (anahtar gerekir, aşağıya bakın).
- Web araştırması, kural adaptörü ve DeepSeek (anahtar gerekir).

## Yeni: IPv6 bütün makinede kapalı

Satsuma bilgisayardaki bütün IPv6 bağlantılarını kendiliğinden kapatır:

- Çekirdekte her arayüzde (`lo` dahil) IPv6 kapatılır; açılışta yeniden
  uygulanır.
- Güvenlik duvarında her zincirin **ilk kuralı** bütün IPv6 paketlerini
  düşürür; çekirdek ayarı geri alınsa bile IPv6 trafiği geçmez.
- Satsuma'nın DNS filtresi yalnızca IPv4'ten (127.0.0.1) dinler.

## Kaldırılan engelleme koşulları

Bir engelleme için önceden bunların **hepsi birden** gerekiyordu:

| Koşul | 2.2.9 |
|---|---|
| Bulgu "kesin" (confirmed) olmalı | Kaldırıldı: şüpheli, muhtemel ve kesin bulgular engeller |
| En az iki bağımsız sensör/kaynak | Kaldırıldı: tek tespit yeterli |
| Açılış bütünlük kilidi açılmış olmalı | Kaldırıldı: bütünlük sorunu bildirilir, engellemeyi durdurmaz |
| Hedef yerel ağda olmamalı | Kaldırıldı: yerel ağdaki saldırgan da engellenir |
| Dakikada en fazla 20 otomatik ağ engeli | Kaldırıldı |
| Otomatik ağ engelini açmak için açılış doğrulaması | Kaldırıldı |

Program durdurma artık her önem düzeyindeki şüpheli, muhtemel ve kesin
kurallarda, kritik göstergelerde ve saldırı aracı göstergelerinde (ters
shell, Metasploit, netcat ve socat tünelleri) çalışır.

## Hâlâ hiç engellenmeyenler

Bunları engellemek saldırganı değil sizi keser:

- Bu bilgisayarın modemi (varsayılan ağ geçidi) ve kullandığı DNS
  sunucuları.
- Loopback, multicast ve belirsiz adresler.
- Satsuma'nın kendisi, TeamViewer, AnyDesk, masaüstü (GNOME), paket
  yöneticisi ve temel sistem servisleri.
- Sıradan program davranışı olan göstergeler (pano erişimi, tarayıcının
  kendi geçmişini okuması, `ps`, `git` vb.): bunlar bildirilir.
- 5 dakikadan eski olaylar: eski kayıtlar yeniden okununca engelleme
  yapılmaz.

Bir işlevi kapatmak isterseniz panelden kapatabilirsiniz; "Aksiyonları
duraklat" da çalışır.

## Anahtar gerekenler

- **OTX:** `sudo satsuma-admin set-otx-key`
- **DeepSeek:** anahtarı `/etc/satsuma-core/deepseek.key` dosyasına yazın
  (sahibi `root`, grubu `satsuma-reader`, izin `0640`). DeepSeek açıkken
  araştırma soruları DeepSeek'in sunucusuna gönderilir.

## Bilinen eksikler

- `sudo_autoblock_enabled` (parolasız sudo oto-bloğu) anahtarı açık, ama
  bu anahtarı kullanan kod üründe yok; şimdilik etkisi yok.
- Virüs taramasının (ClamAV vb.) bulduğu dosyaların otomatik karantinası üründe desteklenmiyor.
