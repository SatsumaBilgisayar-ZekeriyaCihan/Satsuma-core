"""YARA is excluded from Satsuma by the owner's decision.

The product's first sabotage came in through a YARA integration, so no
YARA library, rule file, worker, service or package dependency may enter
this tree. This test fails the build if one does. It widens
tests/test_scanner_removal.py, which checks the removed YARA worker in
detail; that guard test itself necessarily names YARA and is exempt.

---

YARA, sahibinin kararıyla Satsuma'dan dışlanmıştır.

Ürüne ilk sabotaj bir YARA entegrasyonuyla geldi; bu yüzden hiçbir YARA
kütüphanesi, kural dosyası, işçisi, servisi ya da paket bağımlılığı bu
ağaca giremez. Biri girerse bu test derlemeyi bozar. Kaldırılan YARA
işçisini ayrıntılı denetleyen tests/test_scanner_removal.py'yi genişletir;
o koruma testi YARA adını zorunlu olarak andığı için muaftır.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORD = re.compile(r'\b(?:yara|libyara|yarac|yara-python)\b', re.IGNORECASE)
GUARDS = {'test_scanner_removal.py'}  # the existing YARA-removal guard / mevcut YARA koruma testi
CODE_SUFFIXES = {'.py', '.service', '.timer', '.spec', '.sh', '.conf', '.nft', '.toml', '.json', '.cfg'}


def files():
    for path in ROOT.rglob('*'):
        if (path.is_file() and '.git' not in path.parts and path != Path(__file__).resolve()
                and path.name not in GUARDS):
            yield path


def test_no_yara_rule_files():
    assert [p for p in files() if p.suffix.lower() in ('.yar', '.yara')] == []


def test_no_yara_in_code_services_or_packaging():
    hits = []
    for path in files():
        if path.suffix in CODE_SUFFIXES:
            text = path.read_text(errors='replace')
            if WORD.search(text):
                hits.append(str(path.relative_to(ROOT)))
    assert hits == []
