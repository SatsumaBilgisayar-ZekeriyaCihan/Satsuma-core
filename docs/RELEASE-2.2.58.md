# Satsuma Core 2.2.58

Saha 2026-11-19: "konsol benden şifre istemeden paket kuruyor".

## Paket ve dağıtım değişiklikleri parola ister

Fedora Atomic'in `org.projectatomic.rpmostree1.rules` kuralı wheel grubundaki etkin kullanıcıya paket
kurma/kaldırma, rollback, cleanup, iptal ve istemci yönetimini; her yerel etkin kullanıcıya da güncellemeyi
parolasız açıyordu. Kullanıcı hesabıyla çalışan bir program `rpm-ostree uninstall satsuma-core` ile Satsuma'yı
kaldırabilir ya da eski bir dağıtıma dönebilirdi.

Yeni `/usr/share/polkit-1/rules.d/10-satsuma-package-auth.rules` (ad sırasıyla Fedora'nınkinden önce okunur)
tüm `org.projectatomic.rpmostree1.*` işlemlerini her seferinde yönetici parolasına bağlar. root (otomatik
güncellemeler, rpm-ostreed) etkilenmez; depo üst verisini yenileme (`repo-refresh`) serbest kalır.

## polkit kuralı yazma (SATSUMA-GAP-074)

`/etc/polkit-1/rules.d`, localauthority ve /usr/local altındaki polkit kural dizinlerine yazma kritik bulgudur;
dosya karantinaya alınır (otomatik geri alma). Paket yöneticilerinin yazmaları muaftır. Daha önce hiç
izlenmiyordu: tek satırlık bir "her şeye izin ver" kuralı parolasız root demekti.

## Satsuma ya da güvenlik paketini kaldırma, eski dağıtıma dönme (SATSUMA-GAP-075)

`rpm-ostree uninstall|override remove` ile satsuma, clamav, suricata, audit, aide, firewalld, nftables,
selinux-policy; `rpm-ostree rollback|reset`, `cleanup -r`: kritik alarm. Yalnız alarm (durdurulmaz): işlem artık
yönetici parolası istiyor, sahibin kendi işlemi kesilmez.

Kural sayısı: 306.
