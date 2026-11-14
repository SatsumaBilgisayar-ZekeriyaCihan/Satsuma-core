# SatsumaSecurity 2.2.3 — sahte alarmların ayıklanması

2.2.2'nin üzerine kurulur; 2.2.2'deki her şeyi içerir.

## Düzeltilen (saha testi)

- **Panelden yapılan işlemler saldırı sanılıyordu:** Satsuma panelinden bir
  servisi durdurmak `SATSUMA-EVASION-002` olarak kritik bulgu üretiyordu.
  Artık `satsuma-operator` servisinin başlattığı komutlar "Panelden yönetici
  işlemi" etiketiyle bilgi düzeyinde kaydediliyor; asıl önem derecesi
  `original_severity` alanında saklanıyor. Başka bir yerden gelen aynı
  komut yine kritik.
- **Bulgu saatleri olayın saatini gösteriyor:** gecikmeli işlenen olaylar
  işlendikleri anla değil, gerçekleştikleri anla tarihleniyor
  (`timestamp`); işlenme anı `detected_at` alanında.
- **`SATSUMA-CLOUD-001` yanlış alarmı:** bulut meta veri adresini
  (`169.254.169.254`, `metadata.google.internal`) yalnızca *arayan* komutlar
  (`grep`, `journalctl` ile log okumak gibi) artık alarm üretmiyor; kural
  yalnızca bu adrese gerçekten bağlanan komutlarda (ör. `curl`, `wget`)
  tetikleniyor, `sh -c` içindeki komutlar dahil.

2.2.2 ve öncesi için: `docs/RELEASE-2.2.2.md`, `docs/RELEASE-2.2.1.md`.
