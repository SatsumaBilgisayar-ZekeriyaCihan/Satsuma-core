"""Plain-language view of scanner records (2.2.47); no Qt, no I/O.

ClamAV prints a SCAN SUMMARY even with --infected; the scan record keeps the
output excerpt, so older records are read the same way as new ones.

Tarayıcı kayıtlarının sade görünümü. ClamAV --infected ile de özet yazar;
kayıt çıktının bir parçasını sakladığı için eski kayıtlar da okunur.
"""
import re

_SUMMARY = (('scanned_files', r'Scanned files:\s*(\d+)', int),
            ('infected_files', r'Infected files:\s*(\d+)', int),
            ('scanned_directories', r'Scanned directories:\s*(\d+)', int),
            ('data_scanned', r'Data scanned:\s*([0-9.]+\s*[KMGT]?i?B)', str),
            ('duration', r'Time:\s*([0-9.]+\s*sec[^\n]*)', str))


def clam_summary(text):
    """Numbers from ClamAV's SCAN SUMMARY; keys are missing when ClamAV did not print them."""
    result = {}
    for key, pattern, kind in _SUMMARY:
        match = re.search(pattern, str(text or ''), re.I)
        if match:
            result[key] = kind(match.group(1).strip())
    return result


def summary_of(item):
    """The stored summary, or one read from the stored output excerpt."""
    item = item if isinstance(item, dict) else {}
    stored = item.get('summary')
    if isinstance(stored, dict) and stored:
        return stored
    return clam_summary(item.get('output_excerpt')) if item.get('tool') == 'clamav' else {}


def scanned_text(item):
    summary = summary_of(item)
    if 'scanned_files' in summary:
        text = f"{summary['scanned_files']:,}".replace(',', '.') + ' dosya'
        if summary.get('data_scanned'):
            text += ' · ' + summary['data_scanned']
        return text
    return '—'


def problem_text(item):
    item = item if isinstance(item, dict) else {}
    if item.get('error'):
        return str(item['error'])
    if item.get('fallback_from'):
        return 'clamd yanıt vermedi; clamscan ile tarandı'
    if item.get('status') == 'WARNING' and item.get('exit_code') not in (None, 0, 1):
        return 'Tarayıcı çıkış kodu ' + str(item['exit_code'])
    return '—'


def files_text(item):
    """Files ClamAV reported, one per line, with signature and quarantine state."""
    item = item if isinstance(item, dict) else {}
    states = {q.get('source'): q.get('status') for q in item.get('quarantine') or [] if isinstance(q, dict)}
    lines = []
    for entry in item.get('files') or []:
        if not isinstance(entry, dict):
            continue
        line = str(entry.get('path')) + ' · ' + str(entry.get('signature') or 'imza yok')
        state = states.get(entry.get('path'))
        if state == 'quarantined':
            line += ' · karantinada'
        elif state:
            line += ' · karantinaya alınamadı'
        elif entry.get('unavailable_reason'):
            line += ' · dosya okunamadı'
        lines.append(line)
    return lines
