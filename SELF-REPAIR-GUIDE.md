# Satsuma kendi kendini onarma ve bakım kiti

## Üç katman

| Ne | Ne zaman | Kapsam |
|---|---|---|
| `satsuma-self-health` | 10 dakikada bir | 14 temel servis, işçi kalp atışları, DNS filtresi |
| `satsuma-maintenance` (bakım kiti) | açılıştan 15 dk sonra, sonra 6 saatte bir | ürünün tamamı (aşağıda) |
| `sudo satsuma-admin tam-kontrol` | elle | koruma anahtarlarını açar, ardından bakım kitini çalıştırır |

Yalnızca bakım kiti: `sudo satsuma-admin bakim` (`--yalniz-kontrol` hiçbir şey
değiştirmez, `--json` makine çıktısı verir).

## Bakım kitinin denetledikleri

1. Kurulum bütünlüğü (imzalı envanter). Doğrulanmazsa **hiçbir onarım yapılmaz**.
2. Uygulama imajı (`/opt/satsuma-core` salt okunur bağlı mı).
3. Paketin kurduğu her `satsuma-*` birimi: çalışmayan/başarısız birim başlatılır
   (başlatma sınırı sıfırlanarak), paketin etkinleştirdiği ama kapatılmış birim
   yeniden etkinleştirilir. Bir kez çalışıp biten birimler başlatılmaz.
4. Derin motor bağlantısı (motor soketi ve teams sonuç soketi).
5. Panel okuyucusu (reader) soketi yanıt veriyor mu.
6. Olay akışı ve çekirdek bekçisi güncel mi.
7. Veritabanları (`PRAGMA quick_check`) ve veri diskindeki boş alan.
8. Sistem hesapları: parolalı sistem hesabı, ikinci UID 0 → kanıt alınır, kilitlenir.
   Hesap özeti yoksa alınır.
9. Servis kimlikleri (satsuma-* kullanıcı ve grupları) → eksikse `systemd-sysusers`.
10. Dosya izinleri (`/usr/bin/satsuma-*`, `/usr/libexec/satsuma-*`,
    `/var/lib/satsuma-core`, manifest anahtarı).
11. Fedora Atomic'te ertelenmiş kurulum adımları tamamlandı mı.

## Hiçbir zaman kendiliğinden yapılmayanlar

- Maskelenmiş birim açılmaz: yöneticinin kararıdır (`sudo systemctl unmask <birim>`).
- Bütünlüğü bozuk kurulum "onarılmaz": paket yeniden kurulur, neden incelenir.
- Sahibi root olmayan Satsuma dosyası değiştirilmez: kurcalama işaretidir.
- Bozuk veritabanı onarılmaz: kayıtlar kanıttır; kopya alınıp incelenir.
- Bir şey 30 dakikada en çok üç kez onarılır (sonsuz döngü olmaz).

## Kayıtlar

`/var/lib/satsuma-core/maintenance/` (yalnız root):
`last.json` son rapor, `history.jsonl` geçmiş, `history.json` onarım sınırı.
