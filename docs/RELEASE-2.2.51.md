# Satsuma Core 2.2.51 (2026-11-19) — dengeleme 1. faz, ilk adım

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## DNS filtresi yeni engelde yeniden başlamıyor

Önce: listeye her yeni alan adı girdiğinde (OTX her bulduğunda) dnsmasq yeniden
başlatılıyordu; bu sırada hiçbir ad çözülmüyor, sayfalar ara ara açılmıyordu.

Şimdi: yeni engellenen adlar imzalı `added.hosts` dosyasına yazılır. dnsmasq bu
dosyayı `addn-hosts` ile okur ve SIGHUP sinyaliyle, durmadan yeniden okur; DNS
cevap vermeyi hiç kesmez. Sinyal yalnızca `/usr/sbin/dnsmasq` olduğu doğrulanan
PID'e doğrudan gönderilir. Tam liste (alt alan adlarıyla birlikte) en fazla 30
dakikada bir yeniden yüklenir; listeden çıkan adlar zaten böyle bekliyordu.

Sınır: hosts satırı adın kendisini engeller; o adın alt alan adları bir sonraki
tam yüklemede (en geç 30 dakika) engellenir.

Yükseltmede yapılandırma bir kez değiştiği için dnsmasq bir kez yeniden başlar.

## Kabul ölçütü (48 saat yerine)

Otomatik testler ve CI ekran görüntüleri temiz; kurulumdan sonra 10 dakikalık
kontrol listesi sorunsuz; sorun çıkarsa `rpm-ostree rollback` ile tek komutta
önceki sürüme dönülür.
