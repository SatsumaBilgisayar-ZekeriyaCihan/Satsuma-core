# SatsumaSecurity 2.2.14 — acil düzeltme

2.2.13'ün yerini alır ve onun her şeyini içerir.

## Düzeltilen: gerçek sistem programları "paketsiz" görünüyordu

- 2.2.13'ün `/bin`-`/sbin` denetimi, Fedora'nın `/usr/sbin`'i `/usr/bin`'e
  bağlamasından sonra paketlerin hâlâ `/usr/sbin/...` diye kaydettiği
  programları bulamıyor ve **yanlışlıkla "paketsiz"** gösteriyordu. Bu
  programlardan birini silmek makineyi açılmaz yapabilir.
- Artık paket kayıtları dosyanın gerçek yeriyle eşleşiyor.
- 50'den fazla paketsiz program çıkarsa denetim "güvenilmez" der ve hiçbir
  bulgu yazmaz.
- Her bulgu **"SİLMEYİN"** der ve güvenli yolu yazar (değiştirilmiş program
  için `sudo dnf reinstall <paket>`). Doğrulanmış zararlıyı Satsuma
  kendisi karantinaya alır; sizden dosya silmeniz istenmez.
- 2.2.13'ün yazdığı yanlış bulgular bir sonraki denetimde "temizlendi"
  olarak işaretlenir.

Kurulumdan sonra yeni denetim için:
`sudo systemctl start satsuma-core-security-scan-now.service`
