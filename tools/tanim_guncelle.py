"""Refresh the MITRE ATT&CK and CISA KEV definition files (satsuma/definitions-v1).

Usage: python3 tools/tanim_guncelle.py ATTACK_JSON KEV_JSON OUTPUT_DIR
ATTACK_JSON: github.com/mitre/cti enterprise-attack/enterprise-attack.json
KEV_JSON:    github.com/cisagov/kev-data known_exploited_vulnerabilities.json

MITRE ATT&CK ve CISA KEV tanım dosyalarını yeniler. Ağ bağlantısı kurmaz;
indirilen iki JSON dosyasını YAML tanımlarına çevirir.
"""
import sys, os, shutil, tempfile, json, re, yaml, datetime, glob
attack, kev, out = sys.argv[1:4]
work = tempfile.mkdtemp()
shutil.copy(attack, os.path.join(work, "attack.json")); shutil.copy(kev, os.path.join(work, "kev.json"))
sys.argv = ["tanim", work, out]
src, out = work, out
def first_sentence(text, limit=400):
    text = re.sub(r'\(Citation:[^)]*\)', '', text or '')
    text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = ' '.join(text.split())
    m = re.match(r'(.+?[.!?])(\s|$)', text)
    s = m.group(1) if m else text
    return s[:limit]
bundle = json.load(open(f'{src}/attack.json'))
objs = bundle['objects']
def ext(o):
    for r in o.get('external_references', []):
        if r.get('source_name') == 'mitre-attack':
            return r.get('external_id'), r.get('url')
    return None, None
live = lambda o: not o.get('revoked') and not o.get('x_mitre_deprecated')
tactics = []
for o in objs:
    if o.get('type') == 'x-mitre-tactic' and live(o):
        tid, url = ext(o)
        tactics.append({'id': tid, 'name': o['name'], 'shortname': o.get('x_mitre_shortname'),
                        'description': first_sentence(o.get('description')), 'url': url})
tactics.sort(key=lambda t: t['id'])
techniques = []
for o in objs:
    if o.get('type') == 'attack-pattern' and live(o):
        tid, url = ext(o)
        if not tid: continue
        techniques.append({'id': tid, 'name': o['name'],
            'tactics': sorted({p['phase_name'] for p in o.get('kill_chain_phases', []) if p.get('kill_chain_name') == 'mitre-attack'}),
            'platforms': o.get('x_mitre_platforms', []), 'subtechnique': bool(o.get('x_mitre_is_subtechnique')),
            'description': first_sentence(o.get('description')), 'url': url})
techniques.sort(key=lambda t: [int(x) if x.isdigit() else x for x in re.split(r'[T.]', t['id']) if x])
version = 'veri tarihi ' + max(o.get('modified', '') for o in objs)[:10]
linux = [t for t in techniques if 'Linux' in t['platforms']]
head = lambda title, n, extra: {
    'schema': 'satsuma/definitions-v1', 'kind': title, 'source': 'MITRE ATT&CK Enterprise (github.com/mitre/cti)',
    'attack_version': version, 'generated_at': datetime.date.today().isoformat(), 'count': n,
    'license': 'ATT&CK® MITRE Corporation; çoğaltma ve dağıtım MITRE kullanım koşullarına göre serbesttir, atıf gerekir (attack.mitre.org/resources/legal-and-branding/terms-of-use/).',
    'note': 'Tanım/zenginleştirme verisidir, tespit kuralı değildir: rules/ klasörüne konmaz.', **extra}
dump = lambda path, data: open(path, 'w').write(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120))
dump(f'{out}/mitre-attack-taktikler.yaml', {**head('mitre_tactics', len(tactics), {}), 'tactics': tactics})
dump(f'{out}/mitre-attack-teknikler.yaml', {**head('mitre_techniques', len(techniques), {}), 'techniques': techniques})
dump(f'{out}/mitre-attack-linux-teknikler.yaml', {**head('mitre_techniques_linux', len(linux), {'filter': 'platforms içinde Linux'}), 'techniques': linux})
kev = json.load(open(f'{src}/kev.json'))
items = [{'cve': v['cveID'], 'vendor': v.get('vendorProject'), 'product': v.get('product'), 'name': v.get('vulnerabilityName'),
          'date_added': v.get('dateAdded'), 'due_date': v.get('dueDate'),
          'ransomware_use': v.get('knownRansomwareCampaignUse'), 'cwes': v.get('cwes', []),
          'description': ' '.join((v.get('shortDescription') or '').split()), 'required_action': ' '.join((v.get('requiredAction') or '').split())}
         for v in kev['vulnerabilities']]
items.sort(key=lambda v: v['date_added'] or '', reverse=True)
dump(f'{out}/cisa-kev.yaml', {'schema': 'satsuma/definitions-v1', 'kind': 'cisa_known_exploited_vulnerabilities',
    'source': 'CISA Known Exploited Vulnerabilities Catalog (github.com/cisagov/kev-data)',
    'catalog_version': kev.get('catalogVersion'), 'catalog_date': kev.get('dateReleased'),
    'generated_at': datetime.date.today().isoformat(), 'count': len(items),
    'license': 'ABD kamu malı (U.S. Government work); serbestçe kullanılabilir.',
    'note': 'Tanım/zenginleştirme verisidir, tespit kuralı değildir: rules/ klasörüne konmaz.', 'vulnerabilities': items})
print(version, len(tactics), len(techniques), len(linux), len(items), kev.get('catalogVersion'))

# Revoked-technique map
b = json.load(open(f'{src}/attack.json')); objs = {o['id']: o for o in b['objects']}
def ext(o):
    for r in o.get('external_references', []):
        if r.get('source_name') == 'mitre-attack': return r.get('external_id')
rev = {}
for o in b['objects']:
    if o['type'] == 'relationship' and o.get('relationship_type') == 'revoked-by':
        s, t = objs.get(o['source_ref']), objs.get(o['target_ref'])
        if s and t and s['type'] == 'attack-pattern' and ext(s) and ext(t):
            rev[ext(s)] = {'old_id': ext(s), 'old_name': s['name'], 'new_id': ext(t), 'new_name': t['name'],
                           'new_url': f"https://attack.mitre.org/techniques/{ext(t).replace('.', '/')}"}
deprecated = sorted(ext(o) for o in b['objects'] if o['type'] == 'attack-pattern' and o.get('x_mitre_deprecated') and not o.get('revoked') and ext(o))
items = sorted(rev.values(), key=lambda r: r['old_id'])
used = {}
for f in []:
    for tid in re.findall(r'\bT\d{4}(?:\.\d{3})?\b', open(f).read()):
        used.setdefault(tid, set()).add(f.split('/')[-1])
hits = {t: sorted(v) for t, v in used.items() if t in rev or t in deprecated}
open(f'{out}/mitre-attack-iptal-edilenler.yaml', 'w').write(yaml.safe_dump({
    'schema': 'satsuma/definitions-v1', 'kind': 'mitre_revoked_techniques',
    'source': 'MITRE ATT&CK Enterprise (github.com/mitre/cti), revoked-by ilişkileri',
    'generated_at': datetime.date.today().isoformat(), 'count': len(items),
    'note': 'Eski teknik numarasını yenisine çevirmek için. Tanım verisidir, tespit kuralı değildir.',
    'revoked': items, 'deprecated_without_replacement': deprecated}, allow_unicode=True, sort_keys=False, width=120))
