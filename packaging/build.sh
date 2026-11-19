#!/usr/bin/env bash
set -euo pipefail
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_root=${SATSUMA_RPM_BUILD_ROOT:-/workspace/setup/satsuma-rpmbuild}
mkdir -p "$build_root"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,tmp,rpmdb}
tar --exclude='./.git' --exclude='./.venv' --exclude='./.pytest_cache' --exclude='./test-evidence' --exclude='__pycache__' --exclude='*.pyc' --exclude='node_modules' --exclude='dist' --transform='s,^\.,satsuma-core-2.2.55,' -czf "$build_root/SOURCES/satsuma-core-2.2.55.tar.gz" -C "$source_root" .
if [[ ${1:-} == --source-only ]]; then
  exit 0
fi
rpmbuild -bb --define "_topdir $build_root" --define "_tmppath $build_root/tmp" \
  --define "_dbpath $build_root/rpmdb" --define "dist ${SATSUMA_RPM_DIST:-.fc44}" \
  --define '_unitdir /usr/lib/systemd/system' "$source_root/packaging/satsuma-core.spec"

