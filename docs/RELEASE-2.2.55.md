# Satsuma Core 2.2.55 — bağımsız ölçüm: Atomic Red Team

2.2.54'teki %93, kurallarla aynı elden çıkan 109 komutluk listeyle ölçülmüştü.
Bu sürüm Satsuma'yı bağımsız bir test kümesiyle ölçer: Red Canary'nin açık
kaynaklı Atomic Red Team deposundaki Linux testleri (423 sh/bash testi,
117 MITRE ATT&CK tekniği, depo 2026-11-06). Araç: `tools/atomic_benchmark.py`.

| Sürüm | Durdurulan test | Teknik bazında durdurulan | Hiç kuralı olmayan teknik |
|---|---|---|---|
| 2.2.53 | 63 / 423 (%15) | 35 / 117 (%30) | 55 |
| 2.2.54 | 100 / 423 (%24) | 52 / 117 (%44) | 48 |
| 2.2.55 | 156 / 423 (%37) | 72 / 117 (%62) | 32 |

Sınırlar: yalnızca komut satırları değerlendirilir (dosya yazma olayları
benzetilmez, dosya kuralları sayılmaz); `PathToAtomicsFolder` altındaki derlenmiş
programlar adlarıyla değerlendirilir. Kalan 32 tekniğin çoğu keşif komutları
(`date`, `ps`, `uname`, `ss`; normal kullanımla aynı) ile bulut/AD testleridir;
bunlar tek komutla değil, ilişkilendirmeyle (kısa sürede çok sayıda keşif)
yakalanmalıdır.

## 21 yeni kural (toplam 302)

Dosya şifreleme (ccencrypt, 7z -p, gpg -c, openssl rsautl/pkeyutl), kök sertifika
ekleme (komut: yalnızca alarm; dosya yazma), Python başlangıç kancası (.pth,
usercustomize), kabuk tuzağı (trap, PROMPT_COMMAND), paket yakalama, PAM
dosyasını komutla değiştirme, audit kuralı ekleme, komut geçmişinden parola
arama, X11 ekran görüntüsü, /tmp'de derleme, kılık değiştirmiş program yolu ve
uzantısı, servisleri sinyalle durdurma ve sysrq, Tor/proxychains/ssh -D,
sshpass/chpasswd, geçici klasörde gizli klasör, betikle hassas dosya okuma,
LaZagne/mimipenguin, tarayıcı parola/çerez veritabanı, posta kutusu.

Yalnızca alarm: SATSUMA-GAP-052 (update-ca-trust vb.; sistemin kendisi de
çalıştırabilir, durdurmak sertifika deposunu yarım bırakabilir).
