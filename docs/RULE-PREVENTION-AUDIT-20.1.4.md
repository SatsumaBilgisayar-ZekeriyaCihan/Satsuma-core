# 20.1.4 — 227 kuralın müdahale envanteri

22 Ekim 2026. Bu sayım `rules/` altındaki SmartRuleEngine kuralları içindir; Suricata imza sayısı değildir.

- Toplam: **227**.
- Doğrudan engelleme/sonlandırma/karantina aksiyonu tanımlı: **0**.
- Bu aksiyonlardan hiçbiri tanımlı olmayan: **227**.
- Canlı trafikle bu çalışma sırasında koruması kanıtlanmış önleme kuralı: **0**.

`ticket` çalışma anında AutoAction akışına yönlenebilir. Ayrı firewall/IPS ve OTX politikaları da engelleme yapabilir. Bu durum, 227 kuralın her birinde bir durdurma yöntemi veya doğrulanmış saldırı önleme kanıtı bulunduğu anlamına gelmez.

## Kategori dağılımı

| Kategori | Kural | Doğrudan durdurma |
|---|---:|---:|
| bpf_linux_current | 11 | 0 |
| collection | 20 | 0 |
| command_control | 5 | 0 |
| credential_access | 6 | 0 |
| custom_linux_exploits | 32 | 0 |
| defense_evasion | 20 | 0 |
| device_access | 3 | 0 |
| device_permissions | 1 | 0 |
| discovery | 6 | 0 |
| execution | 15 | 0 |
| exfiltration | 20 | 0 |
| impact | 6 | 0 |
| lateral_movement | 6 | 0 |
| memory | 4 | 0 |
| network | 3 | 0 |
| persistence | 8 | 0 |
| privilege_escalation | 8 | 0 |
| privilege_escalation_extra | 22 | 0 |
| rootkit | 4 | 0 |
| sudo_hardening | 3 | 0 |
| threat_intel_extra | 24 | 0 |

## Hangi kurallar?

Aşağıdaki 227 kuralın tamamında doğrudan durdurma aksiyonu eksiktir. Tespit göstergelerinin tamamını otomatik saldırı kabul ederek engellemeye dönüştürmek doğru bir düzeltme değildir.

| Kimlik | Ad | Mevcut aksiyonlar |
|---|---|---|
| SATSUMA-BPF-CLI-001 | BPF utility invocation | record |
| SATSUMA-BPF-CLI-002 | BPF program load/attach attempt | record, evidence, ticket, bpf_inventory, bpffs_inventory, correlation_request |
| SATSUMA-BPF-CLI-003 | BPF map creation/update or object pin attempt | record, evidence, ticket, bpf_inventory, bpffs_inventory |
| SATSUMA-BPF-CLI-004 | BPF detach or map delete attempt | record, evidence, ticket, correlation_request |
| SATSUMA-BPF-CLI-005 | bpftrace sensitive hook expression | record, evidence, ticket, correlation_request |
| SATSUMA-BPF-CLI-006 | TC BPF filter change attempt | record, evidence, ticket, network_inventory, bpf_inventory |
| SATSUMA-BPF-CLI-007 | XDP attachment/removal attempt | record, evidence, ticket, network_inventory, bpf_inventory |
| SATSUMA-LINUX-CLI-001 | Explicit LD_PRELOAD command-line indicator | record |
| SATSUMA-LINUX-CLI-002 | System preload file read | record |
| SATSUMA-LINUX-CLI-003 | System preload file write via tee | record, evidence, ticket, correlation_request |
| SATSUMA-LINUX-CLI-004 | Interpreter shell execution indicator | record |
| SATSUMA-COLL-001 | Toplu dosya kopyalama | log_only |
| SATSUMA-COLL-002 | Ekran goruntusu | log_only |
| SATSUMA-COLL-003 | Klavye kaydi | log_only |
| SATSUMA-COLL-004 | Pano erisimi | log_only |
| SATSUMA-COLL-005 | E-posta toplama | log_only |
| SATSUMA-COLL-006 | Tarayici gecmisi | log_only |
| SATSUMA-COLL-007 | Tarayici cerezleri | log_only |
| SATSUMA-COLL-008 | SSH bilgileri | log_only |
| SATSUMA-COLL-009 | Veritabani dosyalari | log_only |
| SATSUMA-COLL-010 | Kaynak kod toplama | log_only |
| SATSUMA-COLL-011 | Ev dizini arsiv | log_only |
| SATSUMA-COLL-012 | Tum disk arsiv | log_only |
| SATSUMA-COLL-013 | Sistem loglari | log_only |
| SATSUMA-COLL-014 | Veritabani dump | log_only |
| SATSUMA-COLL-015 | Parola dosyalari | log_only |
| SATSUMA-COLL-016 | SSH private key | log_only |
| SATSUMA-COLL-017 | GPG key | log_only |
| SATSUMA-COLL-018 | Kubernetes config | log_only |
| SATSUMA-COLL-019 | AWS credentials | log_only |
| SATSUMA-COLL-020 | Docker config | log_only |
| SATSUMA-C2-001 | Ters shell | record, evidence, ticket, correlation_request |
| SATSUMA-C2-002 | Netcat kullanımı | record, evidence, ticket, correlation_request |
| SATSUMA-C2-003 | DNS tünelleme | record, evidence, ticket, correlation_request |
| SATSUMA-C2-004 | HTTP POST aktarım göstergesi | log_only |
| SATSUMA-C2-005 | ICMP tünelleme | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-001 | /etc/shadow okuma | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-002 | SSH private key erişimi | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-003 | Memory dump | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-004 | Browser credential erişimi | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-005 | Kerberos ticket | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-006 | GPG key çalma | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-001 | Dirty Pipe | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-002 | Dirty COW | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-003 | CVE-2024-1086 nf_tables exploit göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-004 | CVE-2021-41073 io_uring exploit göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-005 | CVE-2023-6931 perf_event exploit göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-006 | CVE-2021-3493 OverlayFS exploit göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-007 | PLP Rose UAF | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-008 | CVE-2026-46331 pedit partial-COW exploit göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-009 | CVE-2026-43503 shared-frag exploit göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-KERNEL-010 | Shared-frag kernel exploit göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-POLKIT-001 | Şüpheli pkexec hedef/argüman kullanımı | record, evidence, ticket, correlation_request |
| SATSUMA-SUDO-001 | Baron Samedit | record, evidence, ticket, correlation_request |
| SATSUMA-SUDO-002 | Sudo Chroot LPE | record, evidence, ticket, correlation_request |
| SATSUMA-SUDO-003 | Sudoedit | log_only |
| SATSUMA-SUDO-004 | Sudo Parolasiz | log_only |
| SATSUMA-SUDO-005 | Sudoers Degistirme | record, evidence, ticket, correlation_request |
| SATSUMA-SUID-001 | SUID Kesfi | log_only |
| SATSUMA-SUID-002 | SGID Kesfi | log_only |
| SATSUMA-SUID-003 | SUID Shell | record, evidence, ticket, correlation_request |
| SATSUMA-SUID-004 | Capabilities Kullanimi | log_only |
| SATSUMA-CONT-001 | runc 2025 container escape CVE göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-CONT-002 | Docker Privileged | record, evidence, ticket, correlation_request |
| SATSUMA-CONT-003 | Namespace Kacisi | record, evidence, ticket, correlation_request |
| SATSUMA-LNX-EVAS-001 | Immutable bayrak kaldırma göstergesi | log_only |
| SATSUMA-LNX-EVAS-002 | Firewall Silme | record, evidence, ticket, correlation_request |
| SATSUMA-LNX-EVAS-003 | Auditd Durdurma | record, evidence, ticket, correlation_request |
| SATSUMA-LNX-EVAS-004 | Log Temizleme | record, evidence, ticket, correlation_request |
| SATSUMA-LNX-EVAS-005 | Kernel modül yönetimi göstergesi | log_only |
| SATSUMA-LNX-DISC-001 | LinPEAS / LinEnum | record, evidence, ticket, correlation_request |
| SATSUMA-LNX-DISC-002 | Exploit Indirme | record, evidence, ticket, correlation_request |
| SATSUMA-LNX-DISC-003 | Exploit Derleme | record, evidence, ticket, correlation_request |
| SATSUMA-LNX-EXFIL-001 | Veri Sizdirma | record, evidence, ticket, correlation_request |
| SATSUMA-EVAS-001 | Log silme | record, evidence, ticket, correlation_request |
| SATSUMA-EVAS-002 | Auditd durdurma | record, evidence, ticket, correlation_request |
| SATSUMA-EVAS-003 | SELinux devre disi | record, evidence, ticket, correlation_request |
| SATSUMA-EVAS-004 | AppArmor devre disi | record, evidence, ticket, correlation_request |
| SATSUMA-EVAS-005 | Firewall kurali silme | record, evidence, ticket, correlation_request |
| SATSUMA-EVAS-006 | Firewall panic modu/varsayılan zone değişikliği — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-007 | Zaman degistirme — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-008 | Dosya zaman damgasi — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-009 | Immutable bayrak kaldırma göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-010 | LD_PRELOAD kullanım göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-011 | LD_LIBRARY_PATH — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-012 | Rootkit tarama aracı çalıştırıldı — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-013 | SELinux policy yukleme — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-014 | Kernel module kaldirma — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-015 | Sysctl degistirme — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-016 | Kernel taint — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-017 | History temizleme — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-018 | Utmp/Wtmp temizleme | record, evidence, ticket, correlation_request |
| SATSUMA-EVAS-019 | Process gizleme — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EVAS-020 | Dosya silme (shred) — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-DEV-001 | Fiziksel bellek veya I/O aygıt erişimi gözlendi | record, evidence, correlation_request |
| SATSUMA-DEV-002 | Girdi aygıtına erişim gözlendi | record, evidence, correlation_request |
| SATSUMA-DEV-003 | Ham disk aygıtına yazma gözlendi | record, evidence, correlation_request |
| SATSUMA-DEV-004 | Hassas aygıtta herkese açık erişim izni | record, evidence, correlation_request |
| SATSUMA-DISC-001 | Sistem bilgisi toplama | log_only |
| SATSUMA-DISC-002 | Ağ keşfi | log_only |
| SATSUMA-DISC-003 | Kullanıcı keşfi | log_only |
| SATSUMA-DISC-004 | Süreç keşfi | log_only |
| SATSUMA-DISC-005 | Dosya keşfi | log_only |
| SATSUMA-DISC-006 | Servis keşfi | log_only |
| SATSUMA-EXEC-001 | Ters shell (bash) | record, evidence, ticket, correlation_request |
| SATSUMA-EXEC-002 | Ters shell (python) — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-003 | Ters shell (perl) — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-004 | Ters shell (ruby) — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-005 | Ters shell (php) — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-006 | Shell çalıştıran socat tüneli — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-007 | Ters shell (nc) | record, evidence, ticket, correlation_request |
| SATSUMA-EXEC-008 | Base64 decode + exec | record, evidence, ticket, correlation_request |
| SATSUMA-EXEC-009 | Curl pipe bash | record, evidence, ticket, correlation_request |
| SATSUMA-EXEC-010 | Eval kullanimi — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-011 | Xterm ters shell — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-012 | Awk ters shell | record, evidence, ticket, correlation_request |
| SATSUMA-EXEC-013 | Telnet ters shell | record, evidence, ticket, correlation_request |
| SATSUMA-EXEC-014 | Nmap script engine — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXEC-015 | Metasploit — faaliyet göstergesi | log_only |
| SATSUMA-EXFIL-001 | DNS exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-002 | HTTP POST exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-003 | FTP exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-004 | SCP exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-005 | Rsync exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-006 | Netcat exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-007 | ICMP exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-008 | Base64 exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-009 | Arşivleme ve aktarım komut zinciri göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-010 | SSH tunnel exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-011 | Socat exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-012 | Tor exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-013 | WebDAV exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-014 | SMB/CIFS aktarım göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-015 | NFS exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-016 | Git exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-017 | Docker exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-018 | Kubernetes exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-019 | Email exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-EXFIL-020 | Pastebin exfiltration — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-IMP-001 | Şifreleme/arşivleme aracı kullanımı — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-IMP-002 | Disk silme | record, evidence, ticket, correlation_request |
| SATSUMA-IMP-003 | Veri sızdırma — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-IMP-004 | Servis durdurma/deaktivasyon komutu — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-IMP-005 | Defacement — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-IMP-006 | Kaynak tüketimi — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-LAT-001 | SSH yanal hareket — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-LAT-002 | SCP/Rsync transfer — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-LAT-003 | SMB/CIFS aktarım göstergesi | record, evidence, correlation_request |
| SATSUMA-LAT-004 | RDP bağlantısı — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-LAT-005 | VNC bağlantısı — faaliyet göstergesi | record, evidence, correlation_request |
| SATSUMA-LAT-006 | Ayrıcalıklı container/namespace yönetim göstergesi | record, evidence, correlation_request |
| SATSUMA-NET-201 | Yeni dinleme portu göstergesi | record, evidence, network_inventory, correlation_request |
| SATSUMA-NET-202 | Kalıcı firewall yapılandırmasına yazma | record, evidence, network_inventory, correlation_request |
| SATSUMA-NET-203 | DNS resolver yapılandırmasına yazma | record, evidence, network_inventory, correlation_request |
| SATSUMA-PERS-001 | Crontab değişikliği | record, evidence, ticket, correlation_request |
| SATSUMA-PERS-002 | Systemd servis ekleme | record, evidence, ticket, correlation_request |
| SATSUMA-PERS-003 | SSH authorized_keys ekleme | record, evidence, ticket, correlation_request |
| SATSUMA-PERS-004 | Bashrc/Profile değişikliği | record, evidence, ticket, correlation_request |
| SATSUMA-PERS-005 | Init.d/SysV servis | record, evidence, ticket, correlation_request |
| SATSUMA-PERS-006 | XDG autostart | record, evidence, ticket, correlation_request |
| SATSUMA-PERS-007 | Kernel modülü kalıcılık | record, evidence, ticket, correlation_request |
| SATSUMA-PERS-008 | PAM backdoor | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-001 | Etkileşimli root shell isteği | log_only |
| SATSUMA-PRIV-002 | Sudoedit exploit | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-003 | Şüpheli pkexec kullanımı | log_only |
| SATSUMA-PRIV-004 | SUID binary keşfi | log_only |
| SATSUMA-PRIV-005 | Kernel exploit | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-006 | Dirty Pipe komut adı göstergesi (dosya etkisi doğrulanmadı) | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-007 | Sudo chroot exploit | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-008 | Capabilities exploit | log_only |
| SATSUMA-PRIV-009 | SUID binary kesfi | log_only |
| SATSUMA-PRIV-010 | SGID binary kesfi | log_only |
| SATSUMA-PRIV-011 | SUID shell | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-012 | Polkit exploit | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-013 | Sudo exploit | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-014 | Sudo chroot kullanımı göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-015 | Capabilities exploit | log_only |
| SATSUMA-PRIV-016 | Kernel exploit | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-017 | Kernel module yukleme | log_only |
| SATSUMA-PRIV-018 | Exploit derleme | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-019 | Exploit indirme | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-020 | LinEnum | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-021 | LinPEAS | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-022 | WinPEAS | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-023 | PSPY | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-024 | Etkileşimsiz veya stdin kullanan sudo göstergesi | log_only |
| SATSUMA-PRIV-025 | Sudoers degistirme | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-026 | Passwd degistirme | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-027 | Shadow degistirme | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-028 | Root shell yönetim komutu | log_only |
| SATSUMA-PRIV-029 | Docker escape | record, evidence, ticket, correlation_request |
| SATSUMA-PRIV-030 | Namespace giriş göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-RAM-001 | Anonim yazılabilir/çalıştırılabilir bellek bölgesi | record, evidence, correlation_request |
| SATSUMA-RAM-002 | Memfd üzerinden çalışan süreç | record, evidence, correlation_request |
| SATSUMA-RAM-003 | Çalıştırılabilir memfd eşlemesi | record, evidence, correlation_request |
| SATSUMA-RAM-004 | Silinmiş yürütülebilir dosyadan çalışan süreç | record, evidence, correlation_request |
| SATSUMA-ROOT-001 | Kernel modül yönetimi | log_only |
| SATSUMA-ROOT-002 | LD_PRELOAD kullanım göstergesi | log_only |
| SATSUMA-ROOT-003 | /dev altında dosyaya yazma göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-ROOT-004 | Rootkit tarama aracı çalıştırıldı | log_only |
| SATSUMA-SUDO-HARD-001 | Sudoers dosyasına yazma (içerik doğrulanmadı) | record, evidence, ticket, correlation_request |
| SATSUMA-SUDO-HARD-002 | Etkileşimsiz veya stdin kullanan sudo göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-SUDO-HARD-003 | Sudoers dosyası okunması (keşif) | record, evidence, correlation_request |
| SATSUMA-LOL-001 | LOLBin — curl/wget ile uzaktan script yürütme | record, evidence, ticket, correlation_request |
| SATSUMA-LOL-002 | LOLBin — base64 decode + shell | record, evidence, ticket, correlation_request |
| SATSUMA-LOL-003 | LOLBin — eval/exec ile dinamik kod | record, evidence, ticket, correlation_request |
| SATSUMA-LOL-004 | LOLBin — xterm/script ile TTY kaçışı | record, evidence, ticket, correlation_request |
| SATSUMA-FILELESS-001 | Fileless — memfd_create ile bellek-içi binary | record, evidence, ticket, correlation_request |
| SATSUMA-FILELESS-002 | Fileless — /dev/shm veya /tmp'den yürütme | record, evidence, ticket, correlation_request |
| SATSUMA-FILELESS-003 | Fileless — ptrace ile süreç enjeksiyonu | record, evidence, ticket, correlation_request |
| SATSUMA-CONT-101 | Container escape — docker.sock erişimi | record, evidence, ticket, correlation_request |
| SATSUMA-CONT-102 | Container escape — host mount / namespace kaçışı | record, evidence, ticket, correlation_request |
| SATSUMA-CLOUD-001 | Cloud metadata servisi erişimi | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-101 | SSH anahtar hırsızlığı girişimi | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-102 | Tarayıcı/uygulama kimlik deposu erişimi | record, evidence, ticket, correlation_request |
| SATSUMA-CRED-103 | Ortam değişkeninden kimlik bilgisi sızdırma | record, evidence, ticket, correlation_request |
| SATSUMA-PERSIST-001 | Kalıcılık — systemd timer/service oluşturma | record, evidence, ticket, correlation_request |
| SATSUMA-PERSIST-002 | Kalıcılık — shell profil dosyası değişikliği | record, evidence, ticket, correlation_request |
| SATSUMA-PERSIST-003 | Kalıcılık — cron/at job ekleme | record, evidence, ticket, correlation_request |
| SATSUMA-EVASION-001 | Savunma atlatma — log temizleme | record, evidence, ticket, correlation_request |
| SATSUMA-EVASION-002 | Savunma atlatma — güvenlik aracı devre dışı | record, evidence, ticket, correlation_request |
| SATSUMA-EVASION-003 | Savunma atlatma — zaman damgası manipülasyonu | record, evidence, ticket, correlation_request |
| SATSUMA-EXFIL-101 | Veri sızdırma — bulut depolamaya yükleme | record, evidence, ticket, correlation_request |
| SATSUMA-EXFIL-102 | Veri sızdırma — DNS/ICMP üzerinden | record, evidence, ticket, correlation_request |
| SATSUMA-MINE-001 | Kripto madencilik — bilinen miner | record, evidence, ticket, correlation_request |
| SATSUMA-RANSOM-001 | Fidye yazılımı — toplu dosya şifreleme göstergesi | record, evidence, ticket, correlation_request |
| SATSUMA-RANSOM-002 | Fidye yazılımı — gölge kopya silme | record, evidence, ticket, correlation_request |
