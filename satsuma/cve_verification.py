"""CVE applicability via Fedora's local advisory metadata and installed RPM EVR.

A vulnerability is considered covered by a pending fix only when the real
installed EVR compares lower than Fedora's fixed EVR. Unverified trust of local
RPM DB and advisory cache is explicitly retained as a limitation.
"""
from __future__ import annotations
import json
import re
import subprocess
from .host_provenance import _run

CVE_COMMAND = ['/usr/bin/dnf5', '--cacheonly', 'advisory', 'list', '--security', '--with-cve', '--json']
RPM_COMMAND = ['/usr/bin/rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,8}\Z')
ADVISORY_RE = re.compile(r'FEDORA-\d{4}-[a-zA-Z0-9]+\Z')


def parse_installed(text):
    packages = {}
    for line in text.splitlines()[:10000]:
        parts = line.split('\t')
        if len(parts) != 5: continue
        name, epoch, version, release, arch = parts
        if not all((name, version, release, arch)) or len(name) > 150: continue
        try: e = str(int(epoch))
        except (ValueError, TypeError): continue
        packages.setdefault((name, arch), []).append((e, version, release))
    return packages


def _parse_nevra(nevra, installed):
    # Anchor using actual installed name and architecture; do not parse at first dash.
    if not isinstance(nevra, str) or len(nevra) > 260: return None
    for name, arch in sorted(installed, key=lambda x: len(x[0]), reverse=True):
        prefix, suffix = name + '-', '.' + arch
        if not nevra.startswith(prefix) or not nevra.endswith(suffix): continue
        evr = nevra[len(prefix):-len(suffix)]
        if ':' not in evr: continue
        epoch, vr = evr.split(':', 1)
        if '-' not in vr or not epoch.isdigit(): continue
        version, release = vr.rsplit('-', 1)
        if version and release: return (name, arch), (epoch, version, release)
    return None


def parse_cve_advisories(text, installed, compare):
    rows = json.loads(text)
    if not isinstance(rows, list) or len(rows) > 10000: raise ValueError('invalid advisory data')
    results = []
    for row in rows:
        if not isinstance(row, dict) or row.get('advisory_type') != 'security': continue
        adv = row.get('advisory_name')
        if not isinstance(adv, str) or not ADVISORY_RE.fullmatch(adv): continue
        pkg = _parse_nevra(row.get('nevra'), installed)
        if not pkg: continue
        key, fixed_evr = pkg
        references = row.get('references', [])
        if not isinstance(references, list): continue
        for ref in references[:50]:
            if not isinstance(ref, dict) or str(ref.get('reference_type', '')).lower() != 'cve': continue
            cve = ref.get('reference_id')
            if not isinstance(cve, str) or not CVE_RE.fullmatch(cve): continue
            comparisons = []
            for installed_evr in installed[key]:
                try: comparisons.append(compare(installed_evr, fixed_evr))
                except (ValueError, TypeError, AttributeError): comparisons.append(None)
            applicability = ('FIX_PENDING_INSTALLED_OLDER' if comparisons and all(v is not None and v < 0 for v in comparisons)
                            else 'MIXED_OR_UNKNOWN' if any(v is None for v in comparisons) or len(set(comparisons)) > 1
                            else 'NOT_OLDER_THAN_FIX' if comparisons and all(v >= 0 for v in comparisons)
                            else 'UNKNOWN')
            results.append({'cve': cve, 'advisory': adv, 'package': key[0], 'arch': key[1],
                            'applicability': applicability, 'severity': str(row.get('advisory_severity') or 'Unknown')[:32],
                            'confidence': 'local_rpm_db_and_cached_fedora_advisory_unattested'})
            if len(results) >= 500: return results
    return results


def collect_cve_evidence(*, runner=subprocess.run, compare=None):
    advisory_text, advisory_error = _run(CVE_COMMAND, runner=runner)
    packages_text, packages_error = _run(RPM_COMMAND, runner=runner)
    if advisory_text is None or packages_text is None:
        return {'status': 'UNAVAILABLE', 'items': [], 'errors': {'advisory': advisory_error, 'rpm': packages_error}}
    if compare is None:
        try:
            import rpm
            compare = rpm.labelCompare
        except ImportError:
            return {'status': 'RPM_VERSION_COMPARATOR_UNAVAILABLE', 'items': []}
    try:
        items = parse_cve_advisories(advisory_text, parse_installed(packages_text), compare)
    except (ValueError, TypeError, AttributeError):
        return {'status': 'INVALID_EVIDENCE', 'items': []}
    return {'status': 'LOCAL_VERSION_COMPARED', 'items': items,
            'caveat': 'Local metadata may be tampered with; patched version comparison does not prove runtime immunity'}
