#!/bin/sh
# Satsuma: Boxes sanal makinesinin ağ bağlantısını ölçer (yalnızca okuma).
# Bir sanal makine Boxes'ta ÇALIŞIRKEN, normal kullanıcıyla çalıştırın. Çıktı: ~/satsuma-boxes-ag.txt
out="$HOME/satsuma-boxes-ag.txt"
{
echo "== Boxes kurulumu"; flatpak list --app --columns=application,version,origin 2>&1 | grep -i boxes
snap list 2>/dev/null | grep -i boxes || echo "snap boxes yok"
echo; echo "== Boxes içindeki sanal makinelerin ağ tanımı"
for vm in $(flatpak run --command=virsh org.gnome.Boxes -c qemu:///session list --all --name 2>/dev/null); do
  echo "--- $vm"; flatpak run --command=virsh org.gnome.Boxes -c qemu:///session dumpxml "$vm" 2>&1 | sed -n '/<interface/,/<\/interface>/p'
done
echo; echo "== Ana makinedeki köprü / tap / macvtap arayüzleri"; ip -d -br link show 2>&1 | grep -viE '^lo ' 
ip -d link show type bridge 2>&1
echo; echo "== qemu süreçlerinin ağ argümanları"; ps -eo pid,user,args | grep -E 'qemu-system|passt|slirp' | grep -v grep | sed -E 's/(-netdev|-nic) /\n   \1 /g' | grep -E 'pid|netdev|nic|passt|slirp' 
echo; echo "== İlgili modüller"; lsmod | grep -E '^(bridge|stp|llc|br_netfilter|tun|tap|macvtap|macvlan|vhost_net|vhost) ' || echo yok
} > "$out" 2>&1
echo "Tamam: $out"
