#!/bin/bash
set -euo pipefail
[[ $EUID = 0 ]] || { echo 'Acik root konsolundan calistirin.'; exit 1; }
python3 - <<'PY'
from pathlib import Path
for name in ('sudo','sudo-i'):
 p=Path('/etc/pam.d')/name
 if p.exists():p.write_text(''.join(x for x in p.read_text().splitlines(True) if 'SATSUMA_SUDO_GATE' not in x))
p=Path('/etc/sudoers.d/99-satsuma-approval')
if p.exists():p.unlink()
PY
visudo -c
