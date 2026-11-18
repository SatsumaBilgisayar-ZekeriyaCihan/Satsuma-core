# Satsuma Core 2.2.43 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

- Saha kaydı: bir Satsuma servisinden `/etc` için "mkdirat ... success=no
  exit=-17" (EEXIST) audit kaydı, "Güvenlik incelemesi gerekli" olarak. Saldırı
  değil: klasör yürütücüleri her adımda önce mkdir deniyordu; var olan her
  klasör başarısız çağrı ve audit kaydı üretiyordu. remote_containment,
  protected_storage ve browser_policy artık önce açar, yalnızca eksik klasörü
  oluşturur; sahiplik ve izin denetimleri aynıdır.

## Açık konu

- DNS filtresi: DEVAM-TALIMATI adım 1 (dnsmasq kendi ağ ad alanında,
  169.254.53.2) yapılmadı; sağlık denetimi "DNS filtresi kapalı" der. DNS kilidi
  (satsuma_dns) cihazda kapalı görünüyor; sorgular yine Suricata kuyruğundan geçer.
