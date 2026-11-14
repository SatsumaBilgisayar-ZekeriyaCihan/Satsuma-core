# SatsumaSecurity 2.2.1 — 2.2.0 saha testi düzeltmeleri

2.2.0, kullanıcının Fedora makinesinde test edildi; bu sürüm o testte
bulunan sorunları ve K7'yi kapatır. Hâlâ bir **test sürümüdür**.

## Saha testinde bulunan ve düzeltilenler

- **Koruma "doğrulanamıyor" kalıyordu:** systemd-sysctl, Satsuma'nın bellek
  sertleştirmesini (ptrace_scope, suid_dumpable, core_pattern) açılışta geri
  alıyordu; müdahale kilitli kalıyordu. Sertleştirme artık systemd-sysctl'den
  sonra çalışıyor ve değerler `/usr/lib/sysctl.d/90-satsuma-memory.conf`
  ile kalıcı; systemd güncellenince de korunuyor.
- **Modem onayı "Too many open files" veriyordu:** okuyucu ve operatör her
  sorguda bir veritabanı bağlantısını açık bırakıyordu (okuyucuda 1023/1024,
  operatörde 240). Bütün bu bağlantılar artık kapanıyor.
- **D-Bus izlemesi kesiliyordu:** yoğun anlarda izleme tamamen duruyordu.
  Artık sürüyor; kaybolan mesaj sayısı sağlık kaydında gösteriliyor.
- **DNS uyumsuzluğu fark edilmiyordu:** sistem çözücüsü Satsuma'nın izin
  verdiği adreslerden biri değilse sağlık durumu artık iki tarafı da
  göstererek uyarıyor.
- **`/etc/hosts`'a yazabilen ölü kod** (DNS sinkhole) kaldırıldı:
  doğrulanmamış adla MITM kapısı açabiliyordu.

## Denetimden kapatılan

- **K7:** korumayı azaltan her işlem (duraklatma, servis durdurma, IP/alan
  adı izni, engel kaldırma, bütünlük tabanını sıfırlama, filtreleri kapatma)
  yönetici parolasını yeniden istiyor ve kritik olarak kaydediliyor.

## Bilinen ve açık kalanlar

- `satsuma-teams` durdurulurken "deactivating" durumunda takılması:
  kayıtlarda neyi beklediği görünmüyor; ayrıntılı günlükle incelenecek.
- Modem kaydı "değişti" görünüyor: ağ ayarı değiştiği için; modem yeniden
  onaylanınca geçer, bir MITM bulgusu değil.
- K8, K9, kritik dosya kilidi, belge koruması, telefon/tethering tespiti,
  font ve man taraması, yeni arayüz, sabitlenmiş Fedora anahtarı.
