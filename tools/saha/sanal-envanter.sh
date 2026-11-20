#!/bin/sh
# Satsuma: sanal makine ve Bluetooth bileşenlerinin içeriği (yalnızca okuma). Çıktı: ~/satsuma-sanal-envanter.txt
out="$HOME/satsuma-sanal-envanter.txt"
{
echo "== 1. Açılışta modül yükleyen dosyalar ve içerikleri"
for f in /usr/lib/modules-load.d/* /etc/modules-load.d/* /run/modules-load.d/*; do
  [ -f "$f" ] || continue; echo "--- $f ($(rpm -qf "$f" 2>/dev/null))"; cat "$f"; done
echo; echo "== 2. Sanal makine ve Bluetooth birimleri"
for u in vmtoolsd vgauthd vboxservice vboxadd vboxadd-service qemu-guest-agent spice-vdagentd hypervkvpd hypervvssd hypervfcopyd bluetooth libvirtd virtqemud; do
  echo "--- $u: etkin=$(systemctl is-enabled $u.service 2>&1) çalışıyor=$(systemctl is-active $u.service 2>&1)"
  systemctl cat $u.service 2>/dev/null | grep -E '^(# /|ExecStart|Condition|User|Requires|After|WantedBy|BindsTo)'
done
echo; echo "== 3. Paketler ve dosyaları"
for p in open-vm-tools open-vm-tools-desktop qemu-guest-agent virtualbox-guest-additions spice-vdagent hyperv-daemons bluez; do
  if rpm -q $p >/dev/null 2>&1; then echo "--- $(rpm -q $p)"; rpm -ql $p | grep -vE '/usr/share/(doc|man|locale|licenses)/'; else echo "--- $p: kurulu değil"; fi
done
echo; echo "== 4. udev kuralları (sanal makine / Bluetooth)"
grep -lsiE 'vmware|vmw_|vbox|qemu|virtio|hyperv|bluetooth|btusb' /usr/lib/udev/rules.d/* /etc/udev/rules.d/* | while read f; do echo "--- $f ($(rpm -qf "$f" 2>/dev/null))"; grep -iE 'vmware|vmw_|vbox|qemu|virtio|hyperv|bluetooth|btusb|RUN|MODALIAS|kmod' "$f"; done
echo; echo "== 5. Yüklü ilgili modüller"
lsmod | grep -iE '^(vmw|vsock|vhost|virtio|kvm|bluetooth|bt|hv_|vbox)' || echo "yok"
echo; echo "== 6. Sanallaştırma tespiti: $(systemd-detect-virt 2>&1)"
echo; echo "== 7. rfkill"; rfkill list 2>&1
} > "$out" 2>&1
echo "Tamam: $out"
