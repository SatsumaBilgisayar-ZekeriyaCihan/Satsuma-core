"""Bounded redaction for untrusted, read-only dashboard details.

No security decision should ever use this presentation-only representation.
"""
import re

_SECRET = re.compile(r'(?:pass(?:word|phrase)?|parola|sifre|şifre|secret|token|authorization|api[_-]?key|private[_-]?key|credential|bearer|cookie|client[_-]?secret)', re.I)
# Covers both `token=abc` and serialized `\"token\": \"abc\"` values.
# Presentation-only masking; callers must never log the original input.
_INLINE = re.compile(
    r'(?i)(\b(?:authorization|api[_-]?key|token|password|parola|sifre|şifre|secret|credential|client[_-]?secret)\b[\"\']?\s*[:=]\s*[\"\']?)(?:bearer\s+)?([^\s,;\"\'&}]+)'
    r'|\b(bearer\s+)([A-Za-z0-9._~+/-]+)'
)

_MAX_DEPTH = 6
_MAX_ITEMS = 250
_MAX_TEXT = 1200


def redact_detail(value):
    """Return a bounded, redacted copy; preserve unknown/empty state explicitly."""
    seen = [0]

    def limit(text):
        text = _INLINE.sub(lambda m: (m.group(1) or m.group(3)) + '[GİZLENDİ]', str(text))
        return text[:_MAX_TEXT] + ('… [KISALTILDI]' if len(text) > _MAX_TEXT else '')

    def walk(item, depth):
        seen[0] += 1
        if seen[0] > _MAX_ITEMS:
            return '[GÖSTERİM SINIRI]'
        if depth > _MAX_DEPTH:
            return '[DERİNLİK SINIRI]'
        if isinstance(item, dict):
            result = {}
            for index, (key, value) in enumerate(item.items()):
                if index >= _MAX_ITEMS or seen[0] >= _MAX_ITEMS:
                    result['…'] = '[GÖSTERİM SINIRI]'
                    break
                safe_key = limit(key)
                result[safe_key] = '[GİZLENDİ]' if _SECRET.search(str(key)) else walk(value, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            result = [walk(part, depth + 1) for part in item[:_MAX_ITEMS]]
            if len(item) > _MAX_ITEMS:
                result.append('[GÖSTERİM SINIRI]')
            return result
        if item is None or isinstance(item, (bool, int, float)):
            return item
        return limit(item)

    return walk(value, 0)


def detail_lines(value):
    """Render nested entries in Turkish labels, without dumping raw JSON."""
    safe = redact_detail(value)
    output = []

    def render(node, depth=0):
        indentation = '  ' * depth
        if isinstance(node, dict):
            for key, part in node.items():
                if isinstance(part, (dict, list)):
                    output.append(f'{indentation}{key}:')
                    render(part, depth + 1)
                else:
                    output.append(f'{indentation}{key}: {part}')
        elif isinstance(node, list):
            for pos, part in enumerate(node, 1):
                if isinstance(part, (dict, list)):
                    output.append(f'{indentation}{pos}.')
                    render(part, depth + 1)
                else:
                    output.append(f'{indentation}{pos}. {part}')
        else:
            output.append(indentation + str(node))

    render(safe)
    return '\n'.join(output)[:65536]
