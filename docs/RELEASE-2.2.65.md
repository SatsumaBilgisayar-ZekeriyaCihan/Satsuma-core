# Satsuma Core 2.2.65

## bootc yanlış alarmı (saha 2026-11-18)
- `bootc status` kendini SELinux için `/tmp/.tmpXXXXXX` adlı geçici bir kopyadan yeniden çalıştırır.
  SATSUMA-FILELESS-002 iki dakikada 90 kez tetiklendi; 76 durdurma kararının hepsi süreç çoktan bittiği için
  kimlik doğrulamasında kaldı (hiçbir süreç durdurulmadı).
- Geçici kopya yalnız **içeriği `/usr/bin/bootc` ile birebir aynıysa** (çalışan sürecin `/proc/<pid>/exe`
  özeti) bootc sayılır. Ad, komut satırı ya da ebeveyn yetmez; süreç bitmişse bulgu olduğu gibi kalır.

## Hız
- GAP-076 (posta programları) ve GAP-077 (çıkarılan paketlerin programları) yalnız kendi programlarında
  denenir; her olayda değil.

## Kurulum
`sudo rpm-ostree uninstall satsuma-core --install ./satsuma-core-2.2.65-1.fc44.x86_64.rpm` ve yeniden başlatma.
En sıkı mod Satsuma güncellemesini durdurmaz (2.2.64'ten beri).
