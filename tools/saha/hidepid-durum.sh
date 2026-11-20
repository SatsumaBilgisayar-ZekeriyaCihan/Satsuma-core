#!/bin/sh
# Satsuma: hidepid ve unhide durumu (yalnızca okuma). sudo ile çalıştırın. Çıktı: /root/satsuma-hidepid.txt
out=/root/satsuma-hidepid.txt
{
echo "== /proc bağlama seçenekleri"; findmnt -no OPTIONS /proc; grep -E '[[:space:]]/proc[[:space:]]' /etc/fstab || echo "fstab'da /proc yok"
for f in /etc/systemd/system/proc.mount /etc/systemd/system/*.d/*hidepid* /etc/systemd/system/*/hidepid*; do [ -e "$f" ] && { echo "--- $f"; cat "$f"; }; done
echo; echo "== gid grubu"; g=$(findmnt -no OPTIONS /proc | tr ',' '\n' | sed -n 's/^gid=//p'); echo "gid=$g -> $(getent group "$g" 2>/dev/null)"
echo; echo "== polkit / logind drop-in"; systemctl cat polkit.service systemd-logind.service 2>/dev/null | grep -E '^# /|SupplementaryGroups'
echo; echo "== Satsuma sürümü ve tarama servisi"; rpm -q satsuma-core; systemctl show satsuma-core-security-scan.service -p SupplementaryGroups -p CapabilityBoundingSet -p ProtectProc
echo; echo "== Süreç sayıları"; echo "root görünümü: $(ls -d /proc/[0-9]* | wc -l)"; echo "kullanıcı görünümü: $(sudo -u "${SUDO_USER:-nobody}" sh -c 'ls -d /proc/[0-9]* | wc -l')"
echo; echo "== unhide (hızlı)"; u=$(mktemp); timeout 300 /usr/sbin/unhide -m quick reverse > "$u" 2>&1; echo "gizli PID sayısı: $(grep -c 'Found HIDDEN PID' "$u")"; grep -A3 'Found HIDDEN PID' "$u" | head -24
for p in $(grep -o 'Found HIDDEN PID: *[0-9]*' "$u" | grep -o '[0-9]*$' | head -5); do echo "PID $p: $(grep -E '^(Name|Tgid|Uid)' /proc/$p/status 2>&1 | tr '\n' ' ')"; done; rm -f "$u"
echo; echo "== Flatpak Boxes kurulum denemesi (yalnız erişim kontrolü, kurmaz)"; sudo -u "${SUDO_USER:-nobody}" flatpak remotes 2>&1; sudo -u "${SUDO_USER:-nobody}" flatpak remote-info flathub org.gnome.Boxes 2>&1 | head -8
} > "$out" 2>&1
echo "Tamam: $out"
