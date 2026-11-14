# Devam talimatı — 2026-11-13

Bu dosya, önceki Claude oturumunun (session_01WbrEvdEq6EzRP6bKwBcuRJ) yarım bıraktığı işleri bir sonraki yapay zekâya aktarmak için yazıldı. Sahibi kullanıcıdır; kurallar `CLAUDE.md` içindedir ve önce okunmalıdır. Kullanıcıyla yalnızca Türkçe konuşulur. Commit mesajları iki dilli (İngilizce, `---`, Türkçe), her davranış değişikliği ayrı commit ve testle gelir. Kullanıcı `main` dalına doğrudan gönderilmesini istedi.

## Şu anki durum (main = fe85b04)

Bu oturumda yapılıp `main`'e gönderilenler (en eskiden en yeniye):

1. `8dd473e` ptrace_scope=3 RAM tarayıcısını kör eden saldırı sayılır; kaynağı (sysctl satırı, gölgeleyen dosya, açılış argümanı) geri alınır (`satsuma/ptrace_guard.py`, `kernel_guard`, `kernel_profile.apply_boot`).
2. `b40bba5` RAM tarayıcısı yalnızca `satsuma-ram-clamd.service` cgroup'undaki clamd'ye güvenir.
3. `b014ea9` Çekirdek bekçisi ptrace_scope ve kaynaklarını dakikada bir denetler.
4. `eca9e87` `satsuma-ram-clamd` ve `satsuma-core` durdurulursa yeniden başlatılır.
5. `cb199dc`, `5979e4c` Sürüm 2.2.37 (paket `release/2.2.37/`, SHA-256 `50559af9…f67d7`).
6. `e38d401` Eşitlik tablosu.
7. `c0e25af`, `ed03857`, `1932086` CLAUDE.md: sahibine ait olmayan "Platformlar" ve "Koruma ilkeleri" bölümleri kaldırıldı; sahibinin tek ve değişmez kararı en üste yazıldı.
8. `be6c782` Ada/birime göre muafiyet kaldırıldı (Linux `enforcement.exempt` ve `process_identity.verify_process_identity`). Yalnızca PID 1 (kritik alarm), müdahale eden sürecin kendisi ve sahibinin panelden parolayla başlattığı komut durdurulmaz.
9. `0c94153` Bütün RAM kuralları süreci durdurur (RAM-002/003/004/009/107 dahil).
10. `1d52529` Windows'ta da ada göre muafiyet kaldırıldı.
11. `fe85b04` dnsmasq ve HaGeZi devre dışı bırakıldı; DNS kilidi sorguları doğrudan OpenDNS'e DNAT eder; loopback 53053 kapalı. **Bu commit'in bir kısmı aşağıdaki yeni kararla geri alınacak.**

2.2.37'den sonraki değişiklikler (8–11) henüz pakette değil. Testler: 2260 geçti, 7 atlandı (Fedora'ya özgü).

## Testleri çalıştırma (bu ortamda)

- Python 3.13 sanal ortamı: `pytest`, `pytest-timeout`, `psutil`, `PyYAML`, `pydantic`, `jsonschema`, `PyQt6`, `cryptography`. Qt için `libegl1 libgl1 libxkbcommon0 libfontconfig1 libdbus-1-3` ve `QT_QPA_PLATFORM=offscreen`.
- RPM derlemek için `apt-get install rpm rpm2cpio cpio squashfs-tools`. **Ama `tests/test_architecture_rpm.py` iki testi `rpm` kurulu Ubuntu'da başarısız olur** (Fedora RPM veritabanı arar). Tam test çalıştırırken `/usr/bin/rpm`'i geçici olarak kenara alın, bittikten sonra geri koyun.
- Komut: `set -o pipefail; QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider --timeout 300 tests`. Windows testleri `tests/test_windows_project.py` içinden çalışır.
- Bir test bile başarısızsa paket yapılmaz, commit edilmez.

## Yapılacaklar (sırayla)

### 1. DNS: dnsmasq geri gelir, kendi ağ alanında (sahibinin kararı 2026-11-13)

Sahibinin son kararı `fe85b04`'teki "dnsmasq'ı kaldır" kararının yerine geçer:

- **dnsmasq kendi network namespace'inde çalışır** (sahibi bunu seçti). Önerilen yapı: `satsuma-dns` adlı netns; veth çifti, ana taraf `satsuma-dns0` 169.254.53.1/30, ad alanı tarafı 169.254.53.2/30. dnsmasq yalnızca 169.254.53.2:53'te dinler. Loopback (lo, 127.0.0.0/8, 53053) **hiç kullanılmaz**; 53053 kapalı kalır.
- DNS kilidi (`satsuma/network_modes.py` `dns_script`): bu makineden çıkan her DNS sorgusu (127.0.0.0/8 hedefli sistem ara katmanı hariç; onun üst sorguları da yakalanır) `dnat ip to 169.254.53.2` ile dnsmasq'a gider. dnsmasq'ın kendi sorguları yalnızca sabit çözümleyiciye (varsayılan OpenDNS 208.67.222.222 / 208.67.220.220) gidebilir: ana tablonun `forward` zinciri (bugün `policy drop`) için yalnızca `satsuma-dns0`'dan OpenDNS:53'e giden ve dönen trafiğe izin, masquerade; Suricata kuyruğu (queue 100) korunur. 853 hiçbir kuralda açılmaz.
- netns, veth ve adresler `satsuma-core-dns.service` öncesinde root olarak kurulur (ör. `ExecStartPre=+`); dnsmasq `NetworkNamespacePath=/run/netns/satsuma-dns` ile çalışır. `satsuma/network_control.py` sıkı doğrulaması (validate_layout, render_ruleset, `packaging/root/etc/satsuma-core/nftables.nft`) yeni kurallarla birlikte güncellenir; `tests/network_fixture.py` de.
- `fe85b04` içinde geri alınacaklar: `dnsmasq_control.refresh` (şu an dnsmasq'ı durdurup yapılandırmasını siliyor; eski `_refresh_retired` gövdesi yeni adrese uyarlanarak geri gelir), `network_modes_setup.configure` (dnsmasq hazır olma sınaması yeni adrese), `dns_readiness` (127.0.0.1:53053 yerine 169.254.53.2:53), `application_control.PORTS['dns']`.
- **Ürünün içinde hiçbir GitHub adresi kalmaz:** `satsuma/domain_lists.py` `HAGEZI_URL`, `satsuma/threat_domain_lists.py` `FEEDS` ve onlara bağlı hazır listeler (`data/dns-feeds/` ve `sources.json`, spec'teki kurulum satırı) kaldırılır. Ürün kendiliğinden hiçbir liste indirmez.
- **Listeyi kullanıcı ekler:** panelden (`custom_dns_lists`, `operator_service` `custom_list_update`) eklenen liste bir kez indirilir, doğrulanır ve **salt okunur** kaydedilir: root'a ait, 0444, HMAC imzalı (mevcut `installer.integrity.sign` ile), kendiliğinden yenilenmez; liste kaynağı değişse bile kopya değişmez. Güncelleme yalnızca kullanıcı listeyi yeniden eklerse olur. `custom_dns_lists.download` şu an reddediyor (fe85b04); bu salt okunur modelle yeniden açılır.
- **Kurulumda dnsmasq'ı Satsuma kurar ve sıfırdan devreye alır:** paket yoksa `dnf install dnsmasq` (spec'te zaten `Requires: dnsmasq`); sistemde var olan dnsmasq yapılandırması (Fedora `dnsmasq.service` → durdur, kapat, maskele; `/etc/dnsmasq.conf`, `/etc/dnsmasq.d/*`; NetworkManager `dns=dnsmasq` ayarı) **silinmez, kanıt klasörüne taşınır**, ardından Satsuma'nın yapılandırması devreye alınır. Yeri: `installer/dns_setup.py` ve spec `%posttrans`.
- DNS filtresinin durumu (`dns_filter_health`) değişiklikten sonra doğrulanır.

### 2. ClamAV'yi bellek taramasından çıkar (sahibi onayladı)

Gerekçe: clamd kanalı şifrelenemiyor, bellek başka bileşene taşınıyor; Windows'ta 127.0.0.1:3311 üzerinden saldırı bildirildi; imzalar belleğe zor uyuyor. Davranış kuralları (RAM-001..009) ve kod bütünlüğü kalır.

- Linux: `satsuma/worker_memory.py` içindeki `ram_v2` (`MemoryMonitor`) bağlantısı; `satsuma/auto_process.py` ve `satsuma/response.py` içindeki RAM-106/107 yeniden doğrulama dalları; `rules/memory_integrity.yaml` RAM-106/107; `satsuma/enforcement.py` `ATTACK_INDICATORS` içindeki RAM-107; `satsuma/ram/clamd.py`, `coordinator.py`, `revalidate.py`, `engine.py` (Windows da kullanıyor, onunla birlikte); `systemd/satsuma-ram-clamd.service`; `packaging/root/etc/clamd.d/satsuma-ram.conf`; `installer/ram_scanner_setup.py`; spec'teki etkinleştirme/durdurma satırları; `satsuma/kernel_guard.py` `REQUIRED_RUNNING`; `systemd/satsuma-core.service` `Wants/After`; `installer/service_setup.py` `UNITS`; `installer/image_runtime.py`; `satsuma/dashboard_api.py`, `memory_health_view.py`, `process_followup.py`, `schemas/rule-response-catalog-v1.json` atıfları. `satsuma/ram/proc.py` (`kernel_thread`) kalır.
- `satsuma/temporary_scan.py` RAM clamd yerine diskteki dosyayı `clamdscan --fdpass` / `clamscan` ile tarar; `systemd/satsuma-temporary-scan.service` bağımlılığı düzeltilir.
- Windows: `satsuma-core-windows/satsuma_win/clamav.py`, `ramscan.py`, `guard.py` bağlantısı, `--install`/`--uninstall` ClamAV adımları, `.github/workflows/satsuma-core-windows.yml` içindeki RAM v2 gizli içe aktarmaları ve bellek raporu adımı. 3311 portu tamamen kalkar.
- `docs/PLATFORM-PARITY.md` güncellenir.

### 3. Sürüm 2.2.38

`docs/RELEASE-2.2.38.md` ve `BUILD-VALIDATION.json` yazılır; tam test geçtikten sonra `SATSUMA_RPM_BUILD_ROOT=<geçici> bash packaging/release.sh 2.2.38 <mesaj-dosyası>`. Ardından paket açılıp (`rpm2cpio | cpio`) içeriği kaynakla dosya dosya karşılaştırılır (2.2.36'da paket ile kaynak farklı çıkmıştı). Paket imzasızdır ve Fedora'da denenmemiştir; kullanıcıya bu açıkça söylenir.

### 4. ostree (Fedora Silverblue/Kinoite) kurulumu (sahibinin isteği 2026-11-13)

Bugün `rpm-ostree install satsuma-core-*.rpm` başarısız olur. Nedenleri (koddan): rpm-ostree paket betiklerini kapalı ortamda çalıştırır (systemctl yok, `/var` ve `/etc` yazılamaz, `/usr` salt okunur); spec `%pre` `/var/lib/satsuma-core` hazırlar, `%posttrans` ilk satırda `/usr/libexec/satsuma-image build` ile `/var/lib` altında kalıp kurar ve bağlar; paket `%dir /opt/satsuma-core` içerir (ostree'de `/opt` → `/var/opt`); çekirdek ayarları `grubby` ile (ostree'de `rpm-ostree kargs`); `ptrace_guard` ve sysctl dosyaları `/usr/lib/sysctl.d` altına yazmaya çalışır.

Önerilen yapı (iki aşama; normal Fedora kurulumu değişmez):
1. Paket aşaması: `%pre`/`%posttrans`/`%preun` ostree'yi algılar ve yalnızca dosya yerleştirir; `/var`, `/etc`, systemctl adımları ertelenir. `/opt/satsuma-core` paketten çıkarılır, ilk açılışta oluşturulur. Algılama yöntemi (rpm-ostree kapalı ortamında `/run/ostree-booted` görünür mü) cihazda doğrulanmalı; varsayım olarak yazılmalı.
2. İlk açılış aşaması: yeni `satsuma-ostree-firstboot.service` (oneshot, `ConditionPathExists=!/var/lib/satsuma-core/.ostree-installed`), bugün `%posttrans`'ın yaptığı her şeyi aynı sırayla gerçek sistemde yapar; her adımı TAMAM/SORUN olarak kaydeder; en son işaret dosyasını yazar.
3. `satsuma/kernel_profile.py` `apply_boot` ostree'de `rpm-ostree kargs --append/--delete` kullanır; `ptrace_guard` ostree'de `/usr/lib` yerine yalnız `/etc/sysctl.d` ve `/run/sysctl.d` üzerinde çalışır.
4. `exec_guard` ve paket yöneticisi denetimleri `rpm-ostree` sürecini de paket yöneticisi saymalı.
5. Testler: ostree algılaması, ertelenen adımlar ve kargs yolu için birim testleri; Silverblue/Kinoite cihazında kurulum denemesi yapılmadan kullanıcıya "çalışıyor" denmez.

Eski `eski/fix/rpm-ostree-preinstall-safety` dalı (2026-11-02) eskidir, kullanılmaz.

## Açık konular (sahibine sorulacak ya da kanıt bekleyen)

- Panelden otomatik durdurma ve DNS kilidi kapatılabiliyor (parola ister). Sahibinin "hiçbir modül kapalı gelemez" kararıyla çelişiyor; ne yapılacağı sorulmadı.
- "satsuma-reader sıfırlanmadan panel açılmıyor": kök neden bulunamadı; kurulumdan hemen sonra `systemctl status satsuma-reader` ve `journalctl -u satsuma-reader -b` çıktısı gerekiyor (varsayım: başlatma sınırına takılıp kapalı kalıyor).
- "Bütün servisleri `enable --now` yapınca bir kısmı kalkmıyor": `Requires=` zincirleri (satsuma-image, satsuma-network, satsuma-suricata-ips, satsuma-memory-hardening) incelendi, değiştirilmedi; `systemctl --failed` çıktısı gerekiyor.
- Reader soketi 16 eşzamanlı bağlantıyla kilitlenebilir (`satsuma/dashboard_api.py` `Server`).
- Loopback kararı ("Satsuma'nın loopback ile tek ilişkisi engelleme"): `integrations/network_health_probe.py` 127.0.0.1'de geçici alıcı açıyor; `satsuma/unhide_scan.py` portları 0.0.0.0'da kısa süre açıyor. İkisi de değiştirilmedi.
- `satsuma-core.qt6.zip` ve YARA kuralları `CLAUDE.md`'de; dokunulmaz.
