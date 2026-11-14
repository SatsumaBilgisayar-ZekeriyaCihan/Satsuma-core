#!/usr/bin/env bash
# SatsumaSecurity'yi güvenli kaldırma — bütün sürümler için tek betik
# (2.1.6, aday sürümler, 2.2.x ve sonrası; Fedora).
#
# Sürüme göre ayrı kaldırma betiği yoktur; her yeni sürüm bu betiği kullanır.
# Betik kurulu sürüme bakmaz, sistemde ne bulursa onu ele alır:
#   1. USB: usbcore.authorized_default=2 parametresi ve yetkisiz bırakılmış
#      aygıtlar (paketten ÖNCE; yoksa klavye/fare açılışta çalışmaz).
#   2. Eski sürümlerin sudo/PAM onay kapısı (paket gidince sudo kilitlenmesin).
#   3. nftables.service'in Satsuma dosyasına yönlendirilmesi.
#   4. Bütün satsuma* paketleri; paketsiz (betikle) kurulmuş kalıntılar.
#   5. /etc/systemd/system altındaki satsuma* birim, bağlantı ve ek dosyaları.
#   6. Satsuma audit kuralları ve Satsuma'nın kapattığı başka audit kuralları.
#   7. Kalan inet satsuma* güvenlik duvarı tabloları (ağ kesilmesin).
#   8. USBGuard servisi.
#   9. Uzak sunucu maskeleri (sshd vb.; varsayılan: maskeli kalır).
#  10. Veriler: yedeklenip silinir.
#  11. Yalnızca rapor: /usr/local/bin/sudo gibi elle incelenecek dosyalar.
#
# satsuma-core.qt6.zip hiçbir adımda açılmaz, taşınmaz, silinmez; Satsuma
# klasörlerinde bulunursa veri adımı atlanır.
# Her çağrı /usr/bin/sudo ile yapılır: PATH'teki sahte bir "sudo" kullanılmaz.
#
# Kullanım:
#   bash kaldir.sh --kuru   # yalnızca rapor; hiçbir şey değiştirmez
#   bash kaldir.sh          # her adımda onay sorarak kaldırır
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C.UTF-8

KURU=0; [[ ${1:-} == --kuru ]] && KURU=1
NFT_YENIDEN_KUR=0
S=/usr/bin/sudo
ARG=usbcore.authorized_default=2
ZAMAN=$(date +%Y%m%d-%H%M%S)
YEDEK=/root/satsuma-kaldirma-$ZAMAN
KORUNAN=satsuma-core.qt6.zip
VERI=(/var/lib/satsuma-core /etc/satsuma-core /opt/satsuma-core /usr/lib/satsuma-core /var/log/satsuma-core /var/lib/satsuma-admin)
CONTAINMENT=/var/lib/satsuma-core/containment

# grep -q bir boru hattında erken çıkınca pipefail yanlış "yok" der; metni yakala.
arg_var() { [[ $($S grubby --info=ALL 2>/dev/null) == *"$ARG"* ]]; }
nft_satsuma() { [[ $(systemctl cat nftables.service 2>/dev/null) == *satsuma* ]]; }
satsuma_tablolari() { $S nft list tables 2>/dev/null | awk '$2=="inet" && $3 ~ /^satsuma/ {print $3}'; }

bilgi() { printf '\n== %s\n' "$*"; }
uyar()  { printf '  ! %s\n' "$*"; }
tamam() { printf '  ✓ %s\n' "$*"; }
sor() {  # sor "soru" -> 0 evet; --kuru modunda daima hayır
  (( KURU )) && { echo "  (kuru çalışma: atlandı) $1"; return 1; }
  local c; read -r -p "  $1 [e/H] " c; [[ $c == e || $c == E ]]
}
yap() { (( KURU )) && { echo "  (kuru çalışma) $*"; return 0; }; $S "$@"; }

$S -v
source /etc/os-release
[[ $ID == fedora ]] || { echo "Bu betik Fedora içindir ($ID)." >&2; exit 1; }

bilgi "Bulunan Satsuma kurulumu"
mapfile -t PAKETLER < <(rpm -qa --qf '%{NAME}\n' 'satsuma*' | sort -u)
if (( ${#PAKETLER[@]} )); then
  for p in "${PAKETLER[@]}"; do tamam "$(rpm -q "$p")"; done
else
  uyar "Kurulu satsuma paketi yok; yalnızca kalıntılar temizlenecek."
fi
mapfile -t BIRIMLER < <(systemctl list-unit-files --no-legend --no-pager 'satsuma*' 2>/dev/null | awk '{print $1}')
(( ${#BIRIMLER[@]} )) && tamam "${#BIRIMLER[@]} satsuma birimi bulundu."

# 1) USB: paket kaldırılmadan önce.
bilgi "1/11 USB girişi ($ARG)"
# 2.2.2 ve sonrası USBGuard ayarlarını da kurulumdan önceki hâline döndürür.
if [[ -f /opt/satsuma-core/satsuma/app.py ]] && $S grep -q -- '--usbguard-restore' /opt/satsuma-core/satsuma/app.py; then
  if (( KURU )) || sor "Ürünün kendi USB geri yükleme adımı çalıştırılsın mı? (önerilir)"; then
    yap /usr/bin/python3 -I -B /opt/satsuma-core/main.py --usbguard-restore || uyar "Geri yükleme tamamlanamadı; elle devam ediliyor."
  fi
fi
if arg_var; then
  uyar "Açılış girdilerinde var. Kaldırılmazsa USB klavye/fare açılışta çalışmayabilir."
  if (( KURU )) || sor "Bütün açılış girdilerinden kaldırılsın mı? (önerilir)"; then
    yap grubby --update-kernel=ALL --remove-args="$ARG"
  fi
else
  tamam "Açılış girdilerinde yok."
fi
yetkisiz=0
for f in /sys/bus/usb/devices/usb*/authorized_default /sys/bus/usb/devices/*/authorized; do
  [[ -e $f ]] || continue
  case $f in *authorized_default) [[ $(cat "$f") == 1 ]] || yetkisiz=1;; *) [[ $(cat "$f") == 0 ]] && yetkisiz=1;; esac
done
if (( yetkisiz )); then
  uyar "Çalışan sistemde yetkisiz USB aygıtı ya da kısıtlı USB yolu var."
  if (( KURU )) || sor "Hepsine şimdi izin verilsin mi? (önerilir)"; then
    yap sh -c 'for f in /sys/bus/usb/devices/usb*/authorized_default; do echo 1 > "$f"; done
               for f in /sys/bus/usb/devices/*/authorized; do [ "$(cat "$f")" = 0 ] && echo 1 > "$f"; done; true'
  fi
else
  tamam "Bütün USB aygıtları yetkili."
fi
if (( ! KURU )) && arg_var; then
  echo "Parametre hâlâ duruyor. Paket kaldırılırsa USB klavye/fare çalışmayabilir; durduruldu." >&2
  exit 1
fi

# 2) Eski sürümlerin sudo onay kapısı: paket gidince sudo'yu kilitleyebilir.
bilgi "2/11 sudo/PAM onay kapısı"
kapi=()
for f in /etc/pam.d/sudo /etc/pam.d/sudo-i; do
  [[ -f $f && $($S cat "$f") == *SATSUMA_SUDO_GATE* ]] && kapi+=("$f")
done
$S test -e /etc/sudoers.d/99-satsuma-approval && kapi+=(/etc/sudoers.d/99-satsuma-approval)
if (( ${#kapi[@]} )); then
  printf '  ! %s\n' "${kapi[@]}"
  if (( KURU )) || sor "Satsuma satırları çıkarılsın mı? (yedek alınır, sudoers denetlenir)"; then
    yap mkdir -p "$YEDEK/sudo"
    for f in "${kapi[@]}"; do yap cp -a "$f" "$YEDEK/sudo/"; done
    for f in /etc/pam.d/sudo /etc/pam.d/sudo-i; do
      [[ " ${kapi[*]} " == *" $f "* ]] && yap sed -i '/SATSUMA_SUDO_GATE/d' "$f"
    done
    [[ " ${kapi[*]} " == *" /etc/sudoers.d/99-satsuma-approval "* ]] && yap rm -f /etc/sudoers.d/99-satsuma-approval
    yap visudo -c
  fi
else
  tamam "Yok."
fi

# 3) nftables.service Satsuma dosyasına yönlendirilmiş mi?
bilgi "3/11 nftables.service yapılandırması"
if nft_satsuma; then
  uyar "nftables.service Satsuma'ya ait bir dosyayı gösteriyor:"
  systemctl cat nftables.service | grep -n satsuma | sed 's/^/    /'
  if (( KURU )) || sor "Fedora'nın özgün nftables ayarına dönülsün mü? (önerilir; yedek alınır)"; then
    yap mkdir -p "$YEDEK/nftables"
    for f in /etc/systemd/system/nftables.service /etc/systemd/system/nftables.service.d/*.conf; do
      [[ -e $f ]] && $S grep -q satsuma "$f" && { yap cp -a "$f" "$YEDEK/nftables/"; yap rm -f "$f"; }
    done
    if grep -q satsuma /usr/lib/systemd/system/nftables.service 2>/dev/null; then
      # Paket dosyası elle değiştirilmiş. Yeniden kurulum ağ ister; Satsuma'nın
      # güvenlik duvarı kalkmadan ağa çıkılamaz. Bu yüzden 7. adımdan sonra yapılır.
      yap cp -a /usr/lib/systemd/system/nftables.service "$YEDEK/nftables/usr-lib-nftables.service"
      NFT_YENIDEN_KUR=1
      uyar "Paket dosyası değiştirilmiş; nftables paketi güvenlik duvarı kaldırıldıktan sonra (7. adımdan sonra) yeniden kurulacak."
    fi
    yap systemctl daemon-reload
  fi
else
  tamam "Satsuma'ya yönlendirme yok."
fi

# 4) Paketler ve paketsiz kalıntılar.
bilgi "4/11 Paketler ve servisler"
if (( ${#PAKETLER[@]} )); then
  if (( KURU )) || sor "Kaldırılsın mı: ${PAKETLER[*]}"; then
    yap dnf remove -y "${PAKETLER[@]}" || { echo "Paket kaldırılamadı; çıktıyı bana gösterin. Durduruldu." >&2; exit 1; }
  fi
fi
mapfile -t calisan < <(systemctl list-units --all --plain --no-legend --no-pager 'satsuma*' 2>/dev/null | awk '$3!="inactive" {print $1}')
if (( ${#calisan[@]} )); then
  uyar "Hâlâ yüklü satsuma birimleri: ${calisan[*]}"
  if (( KURU )) || sor "Durdurulsun mu?"; then yap systemctl stop "${calisan[@]}" || true; fi
fi
if mountpoint -q /opt/satsuma-core; then
  uyar "/opt/satsuma-core hâlâ bağlı (eski imaj)."
  if (( KURU )) || sor "Ayrılsın mı?"; then yap umount /opt/satsuma-core; fi
fi
tamam "Paket adımı bitti."

# 5) Paketin dışında kalan birim dosyaları (betikle kurulan sürümler, elle eklenenler).
bilgi "5/11 /etc/systemd/system altındaki satsuma dosyaları"
mapfile -t ekler < <(find /etc/systemd/system -maxdepth 2 -name 'satsuma*' -not -path '/etc/systemd/system/satsuma*/*' 2>/dev/null | sort)
if (( ${#ekler[@]} )); then
  printf '    %s\n' "${ekler[@]}"
  if (( KURU )) || sor "Yedeklenip kaldırılsın mı? (önerilir)"; then
    yap mkdir -p "$YEDEK/systemd"
    yap cp -a "${ekler[@]}" "$YEDEK/systemd/"
    yap rm -rf "${ekler[@]}"
    yap systemctl daemon-reload
  fi
else
  tamam "Yok."
fi

# 6) Audit kuralları: önce Satsuma'nın kapattığı kuralları aslına döndür.
bilgi "6/11 Audit kuralları"
isaret='# Disabled by Satsuma (audit K6), original kept in '
for f in /etc/audit/rules.d/*.rules; do
  [[ -f $f && $(basename "$f") != 99-satsuma-core.rules ]] || continue
  $S grep -q -- "$isaret" "$f" || continue
  asil=$($S grep -o -- "${isaret}[^:]*" "$f" | head -1 | sed "s|^$isaret||")
  case $asil in /var/lib/satsuma-core/audit-backup/*) ;; *) uyar "$f: beklenmeyen yedek yolu ($asil); dokunulmadı."; continue;; esac
  if $S test -f "$asil"; then
    uyar "$f içinde Satsuma'nın kapattığı satırlar var; asıl hali: $asil"
    if (( KURU )) || sor "Asıl haline döndürülsün mü?"; then
      yap mkdir -p "$YEDEK/audit"; yap cp -a "$f" "$YEDEK/audit/"; yap cp "$asil" "$f"
    fi
  else
    uyar "$f: yedek bulunamadı ($asil); dokunulmadı."
  fi
done
if [[ -f /etc/audit/rules.d/99-satsuma-core.rules ]]; then
  uyar "99-satsuma-core.rules var (kilitli; yeniden başlatınca tamamen kalkar)."
  if (( KURU )) || sor "Kaldırılsın mı? (önerilir)"; then
    yap mkdir -p "$YEDEK/audit"; yap mv /etc/audit/rules.d/99-satsuma-core.rules "$YEDEK/audit/"
  fi
else
  tamam "Satsuma audit dosyası yok."
fi

# 7) Güvenlik duvarı: Satsuma'nın kuyruk kuralları IPS yokken trafiği keser.
bilgi "7/11 Güvenlik duvarı tabloları"
mapfile -t tablolar < <(satsuma_tablolari)
if (( ${#tablolar[@]} )); then
  uyar "Kalan tablolar: ${tablolar[*]} (Suricata durunca ağ kesilebilir)"
  if (( KURU )) || sor "Silinsin mi? (önerilir)"; then
    yap mkdir -p "$YEDEK/nft"
    for t in "${tablolar[@]}"; do
      yap sh -c "nft list table inet $t > '$YEDEK/nft/$t.nft'"
      yap nft delete table inet "$t"
    done
  fi
else
  tamam "Yok."
fi

# 7b) nftables paketi: ağ artık açık. Başarısız olursa yeniden başlatılmaz;
# Satsuma'yı gösteren bir nftables.service açılışta ağı kesebilir.
if (( NFT_YENIDEN_KUR )); then
  bilgi "7/11 (devam) nftables paketinin yeniden kurulumu"
  f=/usr/lib/systemd/system/nftables.service
  if [[ $(lsattr -d "$f" 2>/dev/null | cut -d' ' -f1) == *i* ]]; then
    uyar "$f değiştirilemez (chattr +i) işaretli; paket yeniden kurulamaz."
    if sor "İşaret kaldırılsın mı? (yeniden kurulum için gerekli)"; then yap chattr -i "$f"; fi
  fi
  if (( KURU )) || sor "nftables paketi Fedora deposundan yeniden kurulsun mu? (önerilir)"; then
    yap dnf reinstall -y nftables || uyar "Yeniden kurulum başarısız (ağ ya da depo)."
    yap systemctl daemon-reload
  fi
fi
if (( ! KURU )) && nft_satsuma; then
  echo >&2
  echo "nftables.service hâlâ Satsuma'yı gösteriyor. Bu hâlde YENİDEN BAŞLATMAYIN:" >&2
  echo "açılışta Satsuma kuralları Suricata olmadan yüklenip ağı kesebilir." >&2
  echo "Ağ çalışırken şunu çalıştırın, sonra betiği yeniden çalıştırın:" >&2
  echo "  sudo dnf reinstall nftables" >&2
  echo "Yedekler: $YEDEK" >&2
  exit 1
fi

# 8) USBGuard.
bilgi "8/11 USBGuard"
if rpm -q usbguard >/dev/null 2>&1 && systemctl is-enabled usbguard >/dev/null 2>&1; then
  uyar "USBGuard açık (yeni USB aygıtlarını engeller)."
  if (( KURU )) || sor "Kapatılsın mı? (yeni Satsuma sürümü kurulurken yeniden açar)"; then
    yap systemctl disable --now usbguard
  fi
else
  tamam "Kapalı ya da kurulu değil."
fi

# 9) Uzak sunucu maskeleri: dışarıdan gelen bağlantı kabul edilmesin diye
# varsayılan cevap "hayır"dır; maskeler yerinde kalır.
bilgi "9/11 Uzak sunucu maskeleri (sshd, samba, VNC…)"
mapfile -t maskeli < <($S /usr/bin/python3 -I -c 'import json,sys
try: d=json.load(open(sys.argv[1]))
except (OSError,ValueError): raise SystemExit
for k,yer in (("server_units_masked","system"),("global_user_units_masked","user")):
    for n in d.get(k) or []: print(yer+" "+n)' "$CONTAINMENT/status.json" 2>/dev/null)
gercek=()
for satir in "${maskeli[@]}"; do
  yol=/etc/systemd/${satir%% *}/${satir#* }
  [[ -L $yol && $(readlink "$yol") == /dev/null ]] && gercek+=("$yol")
done
if (( ${#gercek[@]} )); then
  printf '    %s\n' "${gercek[@]}"
  echo "  Bunlar dışarıdan bağlantı kabul eden sunuculardır. Maske kalırsa çalışamazlar."
  echo "  TeamViewer/AnyDesk ile dışarıya bağlanmanızı etkilemez."
  if sor "Maskeler kaldırılsın mı? (önerilmez; yeni sürüm kurulacaksa gerek yok)"; then
    for yol in "${gercek[@]}"; do
      yap rm -f "$yol"
      asil=$($S find "$CONTAINMENT/backups" -name "$(basename "$yol")" 2>/dev/null | sort | tail -1)
      [[ -n $asil ]] && yap cp -a "$asil" "$yol"
    done
    yap systemctl daemon-reload
  fi
else
  tamam "Yok."
fi

# 10) Veriler: yedeklenip silinir; korunan dosya bulunursa durulur.
bilgi "10/11 Satsuma verileri"
var=()
for p in "${VERI[@]}"; do $S test -e "$p" && var+=("$p"); done
if (( ${#var[@]} )); then
  printf '  %s\n' "${var[@]}"
  if [[ -n $($S find "${var[@]}" -name "$KORUNAN" -print -quit) ]]; then
    uyar "$KORUNAN bu klasörlerde bulundu. Veri adımı ATLANDI; kullanıcıyla birlikte ele alınacak."
  elif (( KURU )) || sor "Bunlar $YEDEK/veri.tar.gz olarak yedeklenip silinsin mi? (temiz kurulum için önerilir)"; then
    yap mkdir -p "$YEDEK"
    yap tar --acls --xattrs -czf "$YEDEK/veri.tar.gz" "${var[@]}"
    yap sha256sum "$YEDEK/veri.tar.gz"
    yap rm -rf "${var[@]}"
  fi
else
  tamam "Kalan veri yok."
fi

# 11) Yalnızca rapor: eski sürümlerin bıraktığı, elle incelenecek dosyalar.
bilgi "11/11 Denetim (değiştirilmez)"
for f in /usr/local/bin/sudo /usr/local/bin/satsuma-zack /usr/local/bin/satsuma-admin-passwd; do
  if $S test -e "$f"; then uyar "$f VAR — silinmedi; bana gösterin: sudo ls -la $f"; fi
done
if systemctl is-enabled suricata.service >/dev/null 2>&1 || systemctl is-active suricata.service >/dev/null 2>&1; then
  uyar "Sistem paketinin suricata.service'i açık. Yeni Satsuma sürümü kendi IPS'ini kuyruk 100'de çalıştırır; ikisi çakışır."
  uyar "  Önerilen: sudo systemctl disable --now suricata.service"
fi
for f in /usr/lib/systemd/system/suricata.service /usr/lib/systemd/system/nftables.service; do
  [[ -e $f && $(lsattr -d "$f" 2>/dev/null | cut -d' ' -f1) == *i* ]] && uyar "$f değiştirilemez (chattr +i) işaretli; paket güncellemeleri bu dosyayı onaramaz."
done
if systemctl cat opensnitch.service >/dev/null 2>&1 && ! systemctl is-enabled opensnitch >/dev/null 2>&1; then
  uyar "OpenSnitch kurulu ama kapalı (Satsuma kapatmış olabilir). İsterseniz: sudo systemctl enable --now opensnitch"
fi
tamam "Denetim bitti."

echo
if (( KURU )); then
  echo "Kuru çalışma bitti; hiçbir şey değiştirilmedi. Kaldırmak için: bash $0"
  exit 0
fi
echo "Kaldırma bitti. Yedekler: $YEDEK"
echo "Audit kilidinin ve çekirdek ayarlarının tamamen kalkması için yeniden başlatın,"
echo "sonra yeni sürümü kurun: bash kur.sh"
sor "Şimdi yeniden başlatılsın mı?" && $S systemctl reboot
exit 0
