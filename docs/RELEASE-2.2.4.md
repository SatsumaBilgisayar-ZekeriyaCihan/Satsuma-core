# SatsumaSecurity 2.2.4 — hafifletilmiş beyin servisi

2.2.3'ün üzerine kurulur; 2.2.3'teki her şeyi içerir.

## Düzeltilen (saha testi)

- **satsuma-teams bilgisayarı yoruyordu:** her tur yaklaşık 22 saniye
  sürüyor, servis bir çekirdeğin yaklaşık dörtte üçünü ve 470 MB bellek
  kullanıyordu. Takımlar ve korelasyon motoru her turda şimdiye dek
  kaydedilmiş bütün olayları baştan okuyordu. Artık yalnızca son 5 dakikayı
  okuyorlar; kayıt geçmişi büyüdükçe yavaşlama olmuyor.
- **Durdurma/yeniden başlatma ~20 saniye "deactivating"de takılıyordu:**
  servis durdurma isteğinde çalışan turun bitmesini bekliyordu. Artık turu
  hemen bırakıyor; okunmamış olaylar yeniden başlayınca işleniyor.

## Kaldırma

Her sürüm için tek betik: `release/kaldir.sh` (`kur.sh --kaldir` da onu
çalıştırır). Önce `bash kaldir.sh --kuru` ile ne yapacağını görebilirsiniz.

Önceki sürümler için: `docs/RELEASE-2.2.3.md`, `docs/RELEASE-2.2.2.md`.
