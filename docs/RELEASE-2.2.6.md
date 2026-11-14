# SatsumaSecurity 2.2.6 — düzeltme sürümü

2.2.5'in yerini alır ve onun her şeyini içerir. 2.x serisinin yeni özellik
almayan düzeltme sürümüdür; yeni geliştirme 3.0'da yapılıyor.

## Düzeltilen

- **Modemin donanım adresi (MAC) değişirse kritik uyarı:** Onayladığınız
  modemin adresi başka bir MAC'ten yanıt verirse bu artık "ARP sahteciliği
  (ortadaki adam) olabilir" diye kritik bulgu olarak, eski ve yeni adresle
  ve ne yapacağınızla birlikte bildiriliyor. Önceden her değişiklik aynı
  genel "uyarı" idi. Ek ya da farklı ağ geçidi "yüksek", yalnızca rota
  değişikliği "uyarı". Hiçbir şey otomatik engellenmez.
- **Ağ geçidi izleyicisi açılışta sıfırlanmıyor:** ikinci izleyici her
  başlangıçta o anki durumu "normal" kabul ediyordu; açılışta araya
  girmiş biri fark edilmezdi. Artık ilk kaydı koruyor.
- **"memory — Sorunlu çalışıyor" sürekli görünüyordu:** tam
  karşılaştırılamayan tek bir süreç (JIT kullanan tarayıcı, güncellenmiş
  program) bütün bileşeni sorunlu gösteriyordu. Artık "Sorunlu" yalnızca
  denetim gerçekten çalışamıyorsa görünüyor; kısmi kapsam ayrıca, nedenleriyle
  bildiriliyor. Doğrulanmış kod farkı yine bulgu üretir.
- **Engellenen adresler sayfası:** üstteki "Veri alınamıyor" yazısı, tek
  bir kaynağın okunamamasından geliyordu; artık liste okunduğu sürece
  görünmüyor. Sayfa OTX satırlarının ne anlama geldiğini açıklıyor
  (raporların başlıkları size yapılan saldırının türü değildir), nedenler
  Türkçe ve IP sütunu görünür kalıyor.
- **Sistem sağlığı sayfası yeniden yazıldı:** sorun yoksa her kart tek
  satır "sorun yok" ve neyin denetlendiğini söylüyor; sorun varsa neyin
  bozulduğunu, ne anlama geldiğini ve ne yapılacağını. Kartlar yeşil, sarı
  ya da kırmızı; kırmızı bir kart varken üstte "Sağlıklı" yazmıyor.

Önceki sürüm: `docs/RELEASE-2.2.5.md`.
