"""Audit G3: bare program names in root services never resolve to /usr/local.

systemd's default PATH starts with /usr/local/sbin, and the code calls nft,
systemctl, mount, tar, sqlite3, ss and others by name. Every unit therefore
pins PATH, and no subprocess environment in the code adds /usr/local.

Denetim G3: root servislerdeki çıplak program adları hiçbir zaman
/usr/local altında aranmaz. Her birim PATH'i sabitler; koddaki hiçbir alt
süreç ortamı /usr/local eklemez.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize('unit', sorted((ROOT / 'systemd').glob('*.service')), ids=lambda p: p.name)
def test_every_service_pins_path(unit):
    lines = unit.read_text().splitlines()
    service = lines[lines.index('[Service]') + 1:]
    paths = [line for line in service if line.startswith('Environment=PATH=')]
    assert paths == ['Environment=PATH=/usr/sbin:/usr/bin']


def test_no_code_or_unit_puts_usr_local_on_a_path():
    offenders = []
    for path in [*ROOT.glob('systemd/*'), *ROOT.glob('satsuma/**/*.py'), *ROOT.glob('integrations/*.py'),
                 *ROOT.glob('installer/*.py'), *ROOT.glob('packaging/root/usr/bin/*')]:
        text = path.read_text(errors='replace')
        if re.search(r"PATH['\"]?\s*[:=]\s*['\"]?[^'\"\n]*/usr/local", text):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders
