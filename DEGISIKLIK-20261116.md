# Değişiklikler 2026-11-16

1. RAM-001: root sahipli, kimsenin yazamadığı yoldaki program (JIT) kaydedilir, durdurulmaz. /tmp, ev klasörü, memfd, silinmiş dosya yine durdurulur. (enforcement.rwx_kept, auto_process)
2. Panel: ISO imza kanıtı ve TPM credential activation satırları eklendi (dashboard_api).
3. account_guard: UID 1-999 hesapta kullanılabilir parola varsa kanıt alınır, hesap kilitlenir (kernel_guard her turda). chattr +i kullanılmadı.
4. OSTree: %pre/%preun/%posttrans ostree'de ertelenir; satsuma-ostree-firstboot gerçek sistemde çalıştırır; işaret sürüm tutar.

Doğrulanmadı: pytest/pydantic bu ortamda yok, tam test koşulmadı; Fedora Silverblue'da denenmedi; RPM derlenmedi.
