#!/usr/bin/env bash
# Prepare a release in ONE commit: version bump, built package, release folder
# with the package and its real SHA-256 only. A published digest line is
# written once and never edited afterwards.
#
# Bir sürümü TEK commit'te hazırlar: sürüm yükseltme, derlenmiş paket ve paketin
# gerçek SHA-256'sını taşıyan sürüm klasörü. Yayımlanan özet satırı bir kez
# yazılır ve sonradan değiştirilmez.
#
# Kullanım: bash packaging/release.sh <yeni-sürüm> <commit-mesajı-dosyası>
# Ön koşul: docs/RELEASE-<yeni-sürüm>.md yazılmış; ağaçta başka değişiklik yok.
set -euo pipefail
export LC_ALL=C.UTF-8

new=${1:?yeni sürüm gerekli (ör. 2.2.8)}
message=${2:?commit mesajı dosyası gerekli}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

[[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Geçersiz sürüm: $new" >&2; exit 1; }
[[ -s $message ]] || { echo "Commit mesajı boş: $message" >&2; exit 1; }
old=$(<VERSION)
[[ $old != "$new" ]] || { echo "Sürüm zaten $new" >&2; exit 1; }
notes=docs/RELEASE-$new.md
[[ -s $notes ]] || { echo "$notes yok; önce sürüm notunu yazın." >&2; exit 1; }
[[ ! -e release/$new ]] || { echo "release/$new zaten var; yayımlanmış sürüm değiştirilmez." >&2; exit 1; }
other=$(git status --porcelain --untracked-files=all | grep -v -- " $notes\$" || true)
[[ -z $other ]] || { echo "Ağaçta başka değişiklik var:" >&2; echo "$other" >&2; exit 1; }

rpm_old=satsuma-core-$old-1.fc44.x86_64.rpm
rpm_new=satsuma-core-$new-1.fc44.x86_64.rpm
sha_old=$(cut -d' ' -f1 "release/$old/SHA256SUMS")

# 1) Sürüm numarası.
sed -i "s/^$old\$/$new/" VERSION
sed -i "s/__version__ = '$old'/__version__ = '$new'/" satsuma/__init__.py
sed -i "s/satsuma-core-$old/satsuma-core-$new/g" packaging/build.sh installer/release_install.py
sed -i "s/^Version: $old\$/Version: $new/; s#docs/RELEASE-$old.md\$#docs/RELEASE-$old.md docs/RELEASE-$new.md#" packaging/satsuma-core.spec
for f in VERSION satsuma/__init__.py packaging/build.sh installer/release_install.py packaging/satsuma-core.spec; do
  grep -q -- "$new" "$f" || { echo "$f güncellenemedi" >&2; git checkout -- .; exit 1; }
done

# 2) Paket.
build=${SATSUMA_RPM_BUILD_ROOT:-$(mktemp -d)}
SATSUMA_RPM_BUILD_ROOT=$build bash packaging/build.sh >"$build.log" 2>&1 || {
  echo "Derleme başarısız; günlük: $build.log" >&2; git checkout -- .; exit 1; }
built=$build/RPMS/x86_64/$rpm_new
[[ -f $built ]] || { echo "$built üretilmedi" >&2; git checkout -- .; exit 1; }
sha_new=$(sha256sum -- "$built" | cut -d' ' -f1)

# 3) Sürüm klasörü: yalnızca paket ve gerçek özeti (kullanıcı kararı
#    2026-10-26: kurulum ve yama betikleri yayımlanmaz).
#    Release folder: the package and its real digest only.
mkdir "release/$new"
cp "$built" "release/$new/"
(cd "release/$new" && sha256sum -- "$rpm_new" > SHA256SUMS)

# 4) Denetim: özet gerçek paketle tutmalı, klasörde başka dosya olmamalı.
(cd "release/$new" && sha256sum -c --quiet SHA256SUMS)
[[ $(ls -A "release/$new" | wc -l) -eq 2 ]] || { echo "release/$new içinde fazladan dosya var" >&2; exit 1; }
if grep -q -- "$sha_old" "release/$new/SHA256SUMS"; then
  echo "Eski sürümün özeti kaldı; commit yapılmadı." >&2; exit 1
fi

# 5) Tek commit.
git add VERSION satsuma/__init__.py packaging/build.sh installer/release_install.py packaging/satsuma-core.spec "$notes" "release/$new"
git commit -q -F "$message"
echo "Sürüm $new hazır: $(git log --oneline -1)"
echo "SHA-256: $sha_new"
