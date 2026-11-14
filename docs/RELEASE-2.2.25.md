# SatsumaSecurity 2.2.25

**DeepSeek kuralları süreci durdurabilir.** Onayladığınız, mühürlenen ve etkinleştirilen, `process_kill` öneren bir yapay zekâ kuralı eşleşen süreci durdurur. İki teyit gerekir; audit kullanılmaz:

1. **Satsuma veritabanı:** Satsuma'nın kendi sensörlerinden aynı sürecin (PID + başlangıç zamanı + program) son 60 saniyedeki kaydı.
2. **Canlı teyit:** Karardan hemen önce süreç `/proc`'tan yeniden okunur; aynı süreç olmalı ve kural canlı komut satırında da eşleşmeli. Bellek kurallarında bellek tarayıcısının taze kaydı aranır.

TeamViewer/AnyDesk ve sistem süreçleri istisnası, bütünlük kilidi ve son kimlik denetimi aynen geçerlidir. Etkinleştirilmemiş ya da durdurma önermeyen kurallar yalnızca bildirir.
