# SatsumaSecurity 2.2.36

## Kurulum artık tek komut
- Paket kurulduktan sonra **`sudo satsuma-kur`** çalıştırın. Araçları yapılandırır (ClamAV imzaları, Suricata kuralları, auditd); masaüstü kullanıcısını, yönetici parolasını, modemi (otomatik ya da etiketindeki MAC ile) ve isteğe bağlı OTX anahtarını sırayla sorar; en sıkı çekirdek profilini ve tarayıcı politikalarını uygular; tam kontrolü çalıştırır; en son, bütün adımlar geçtiyse AIDE örneğini alır.

## Ağ koruması OTX'e bağlı değil
- Ağ koruması (güvenlik duvarı, Suricata, alt ağ engelleyici, PTR kuralı) OTX anahtarı olmadan çalışır; OTX isteğe bağlı ek istihbarattır.
- Alt ağ engelleyici sağlık denetimine, "Trafik engelleme" kartına ve `tam-kontrol`e eklendi; kapalı, sessiz ya da açılış bütünlüğü kilidindeyse açıkça görünür.

## En sıkı çekirdek profili ve kayıtlı deseni
- kexec, SysRq, ayrıcalıksız BPF ve userfaultfd kapalı; perf 3; dosya korumaları; kullanıcı ad alanları kapalı (Flatpak, podman ve tarayıcı korumalı alanı etkilenebilir). ptrace_scope 2 kalır; bellek taraması çalışır.
- Açılış komut satırı: lockdown=integrity, init_on_alloc/free, slab_nomerge, sayfa karıştırma, yığın ofseti, vsyscall=none, debugfs=off; yeni kurulan her çekirdeğe de eklenir. İmzasız modül yüklüyken lockdown eklenmez ve bildirilir.
- Çekirdek bekçisi ayarları her saniye, açılış girdilerini ve modül kilidini beş dakikada bir geri koyar; desen kernel-guard/profile.json'a kaydedilir, değiştirilirse koddan yeniden yazılır. Yeniden başlatma gerekir.

## AIDE bekçisi
- Örnek, Satsuma her şeyi ayarladıktan sonra alınır; ayar dosyalarının kopyası da saklanır (yalnızca root).
- Saatte bir karşılaştırılır. Her değişiklik geri alma yoluyla listelenir: kopyadan, eklenen dosya bekletme klasörüne (silinmez) ya da imzalı paketten.
- Her geri alma **Satsuma yönetici parolası** ister: `sudo satsuma-admin aide geri-al <yol>`. /etc/hosts her satırı doğrulandıktan sonra geri yazılır.

## Tarayıcı koruması (satsuma-omni V62'den)
- Firefox, Chrome, Chromium: yalnızca HTTPS (http:// adresleri, modemin http yönetim sayfası dahil, engelli), vekil sunucu yok, sertifika uyarısı geçilemez, onaylı eklenti dışındakiler engelli, native messaging kapalı. Açık tarayıcıları yeniden başlatın.

## Bellek
- Yazılabilir ve çalıştırılabilir heap, yığın ve adlandırılmış anonim bölgeler artık yakalanıyor.
- Yeni kurallar: herkesin yazabildiği klasörden belleğe yüklenen kod (SATSUMA-RAM-008), ptrace ile izlenen süreç (SATSUMA-RAM-009). Çekirdek iş parçacıkları artık kaybolan süreç sayılmıyor.

## 2.2.36 düzeltmeler dalından
- tam-kontrol DNS filtresini bildirir ve kapalıysa açar; OpenSnitch DNS kuralı DNS kurulumundan önce yazılır; network-modes hatası kurulumu yarıda kesmez; 2.2 öncesi anahtar benimsenmez; unhide Fedora adıyla bulunur; 2026-11-04 bütünlük anahtarı kara listede.

## Doğrulama sınırı
- Kaynak testleri: 2117 geçti, 0 başarısız (Ubuntu 24.04 kapsayıcısı; yalnızca Fedora'da çalışan testler atlandı). Fedora cihazında deneme yapılmadı. Kurulumdan sonra `dns_filter_health` doğrulanmalı.
