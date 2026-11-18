#!/bin/sh
# Satsuma ostree first boot: runs the package's own %pre and %posttrans scripts on
# the real system, because rpm-ostree could not run them while composing the image.
# Satsuma ostree ilk açılışı: rpm-ostree imajı kurarken çalıştıramadığı %pre ve
# %posttrans betiklerini gerçek sistemde çalıştırır.
STATE=/var/lib/satsuma-core
LOG=$STATE/ostree-firstboot.log
umask 077
mkdir -p "$STATE" || exit 1
chmod 0700 "$STATE"
export SATSUMA_OSTREE_FIRSTBOOT=1
# The marker holds the installed version-release, so a package update on ostree runs the
# steps again; the same version is not repeated. İşaret sürümü tutar: güncelleme yeniden çalıştırır.
version=$(rpm -q --qf '%{VERSION}-%{RELEASE}' satsuma-core 2>/dev/null) || { echo "SORUN: satsuma-core paketi okunamadi" >&2; exit 1; }
if [ -f "$STATE/.ostree-installed" ] && [ "$(cat "$STATE/.ostree-installed")" = "$version" ]; then exit 0; fi
failed=0
run_step() {  # run_step TAG NAME
 tmp=$(mktemp /run/satsuma-ostree-step.XXXXXX) || { failed=1; return; }
 rpm -q --qf "%{$1}" satsuma-core > "$tmp" 2>>"$LOG" || { echo "SORUN: $2 (betik okunamadi)" >> "$LOG"; failed=1; rm -f "$tmp"; return; }
 if [ ! -s "$tmp" ] || [ "$(cat "$tmp")" = "(none)" ]; then echo "ATLANDI: $2 (betik yok)" >> "$LOG"; rm -f "$tmp"; return; fi
 if /bin/sh "$tmp" 1 >>"$LOG" 2>&1; then echo "TAMAM: $2" >> "$LOG"; else echo "SORUN: $2" >> "$LOG"; failed=1; fi
 rm -f "$tmp"
}
date -u +"== %Y-%m-%dT%H:%M:%SZ ostree ilk acilis" >> "$LOG"
run_step PREIN pre
[ "$failed" -eq 0 ] && run_step POSTTRANS posttrans
if [ "$failed" -eq 0 ]; then printf "%s" "$version" > "$STATE/.ostree-installed"; echo "TAMAM: kurulum islendi ($version)" >> "$LOG"; exit 0; fi
echo "SORUN: kurulum tamamlanamadi; bir sonraki acilista yeniden denenir. Gunluk: $LOG" >&2
exit 1
