"""Ticket — operatörün ayırt edebileceği görünüm.

Ticket tablosundaki teknik alanları (evidence JSON, type kodları, level)
insan diline çevirir. Finding SUMMARY ile aynı fikir.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple


STATUS_TR = {
    "open": "AÇIK",
    "in_progress": "İNCELENİYOR",
    "resolved": "ÇÖZÜLDÜ",
    "closed": "KAPALI",
    "false_positive": "YANLIŞ ALARM",
    "ack": "İNCELENİYOR",
}

SEVERITY_TR = {
    "critical": "KRİTİK",
    "high": "YÜKSEK",
    "medium": "ORTA",
    "low": "DÜŞÜK",
    "info": "BİLGİ",
}

# type kodu → kısa Türkçe başlık (bilinenler)
TYPE_TR = {
    "ransomware_detected": "Ransomware belirtisi",
    "c2_communication": "C2 / komuta-kontrol şüphesi",
    "rootkit_detected": "Rootkit belirtisi",
    "virus_detected": "Zararlı yazılım",
    "privilege_escalation_attempt": "Yetki yükseltme girişimi",
    "root_login_unknown": "Bilinmeyen root girişi",
    "passwd_modified": "/etc/passwd değişti",
    "shadow_modified": "/etc/shadow değişti",
    "suspicious_process_chain": "Şüpheli süreç zinciri",
    "sensitive_file_then_module": "Hassas dosya + modül yükleme",
}


def _time_text(value: Any) -> str:
    try:
        return time.strftime("%d.%m %H:%M:%S", time.localtime(float(value)))
    except (TypeError, ValueError, OverflowError):
        return str(value or "-")


def _type_label(ticket: Dict[str, Any]) -> str:
    t = str(ticket.get("type") or "")
    if t in TYPE_TR:
        return TYPE_TR[t]
    title = str(ticket.get("title") or "").strip()
    if title and title.lower() != t.lower():
        return title[:80]
    return t.replace("_", " ")[:80] or "Bilinmeyen olay"


def _parse_evidence(ticket: Dict[str, Any]) -> Dict[str, Any]:
    raw = ticket.get("evidence")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def build_ticket_summary(ticket: Dict[str, Any]) -> str:
    """3–5 saniyede okunan ticket özeti."""
    label = _type_label(ticket)
    sev = SEVERITY_TR.get(
        str(ticket.get("severity") or "").lower(),
        str(ticket.get("severity") or "?"),
    )
    status = STATUS_TR.get(
        str(ticket.get("status") or "").lower(),
        str(ticket.get("status") or "?"),
    )
    level = ticket.get("ticket_level")
    level_s = f"S{level}" if level is not None else ""
    count = int(ticket.get("occurrence_count") or 1)
    conf = str(ticket.get("confidence") or "")

    parts = [f"{label}."]
    parts.append(f"Önem: {sev}" + (f" ({level_s})" if level_s else "") + ".")
    if conf:
        parts.append(f"Güven: {conf}.")
    parts.append(f"Durum: {status}.")
    if count > 1:
        parts.append(f"{count} kez tekrarlandı.")

    desc = str(ticket.get("description") or "").strip()
    if desc and desc not in label:
        # Tek cümle ek kanıt
        parts.append(desc[:160] + ("…" if len(desc) > 160 else ""))

    return " ".join(parts)


def build_ticket_list_line(ticket: Dict[str, Any]) -> str:
    """Liste satırı — yan yana ayırt edilebilir alanlar."""
    sev = str(ticket.get("severity") or "-")[:4].upper()
    status = STATUS_TR.get(str(ticket.get("status") or "").lower(), "?")[:10]
    tid = str(ticket.get("ticket_id") or "")[-8:]
    label = _type_label(ticket)
    if len(label) > 36:
        label = label[:35] + "…"
    count = int(ticket.get("occurrence_count") or 1)
    cnt = f"×{count}" if count > 1 else "  "
    return f"{sev:<5} {status:<10} {cnt} {tid}  {label}"


def render_ticket_detail(ticket: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Detay paneli satırları (section, value). value='' = başlık."""
    lines: List[Tuple[str, str]] = []

    lines.append(("ÖZET", ""))
    summary = ticket.get("summary") or build_ticket_summary(ticket)
    for chunk in _wrap(str(summary), 70):
        lines.append(("", chunk))

    lines.append(("KİMLİK", ""))
    lines.append(("  Ticket", str(ticket.get("ticket_id") or "-")))
    lines.append(("  Bulgu", str(ticket.get("finding_id") or "-")))
    lines.append(("  Tür", _type_label(ticket)))
    if ticket.get("team"):
        lines.append(("  Takım", str(ticket.get("team"))))

    lines.append(("ÖNEM / DURUM", ""))
    sev = str(ticket.get("severity") or "-")
    lines.append(
        (
            "  Önem",
            f"{SEVERITY_TR.get(sev.lower(), sev)}  "
            f"(S{ticket.get('ticket_level', '?')}, öncelik {ticket.get('priority', '-')})",
        )
    )
    st = str(ticket.get("status") or "-")
    lines.append(("  Durum", STATUS_TR.get(st.lower(), st)))
    lines.append(("  Güven", str(ticket.get("confidence") or "-")))
    lines.append(("  Tekrar", str(ticket.get("occurrence_count") or 1)))

    lines.append(("ZAMAN", ""))
    lines.append(("  İlk", _time_text(ticket.get("first_seen") or ticket.get("created_at"))))
    lines.append(("  Son", _time_text(ticket.get("last_seen") or ticket.get("updated_at"))))

    # Evidence'den seçilmiş alanlar — tüm JSON duvarı değil
    ev = _parse_evidence(ticket)
    lines.append(("KANIT (özet)", ""))
    if not ev:
        desc = str(ticket.get("description") or "").strip()
        lines.append(("", desc[:200] if desc else "  (kanıt yok)"))
    else:
        for key in (
            "summary",
            "type",
            "rule_id",
            "path",
            "sha256",
            "cmd",
            "exe",
            "pid",
            "severity",
            "classification",
        ):
            if key in ev and ev[key] not in (None, "", [], {}):
                val = ev[key]
                if isinstance(val, (dict, list)):
                    val = json.dumps(val, ensure_ascii=False)[:80]
                lines.append((f"  {key}", str(val)[:90]))
        for nested in ("FILE", "CORRELATION"):
            block = ev.get(nested)
            if isinstance(block, dict) and block:
                lines.append((f"  [{nested}]", ""))
                for k, v in list(block.items())[:6]:
                    if v in (None, "", [], {}):
                        continue
                    lines.append((f"    {k}", str(v)[:80]))

    notes = ticket.get("notes")
    if isinstance(notes, str):
        try:
            notes = json.loads(notes)
        except (json.JSONDecodeError, TypeError):
            notes = []
    if notes:
        lines.append(("NOTLAR", ""))
        for n in notes[-5:]:
            if isinstance(n, dict):
                lines.append(
                    (
                        f"  {_time_text(n.get('timestamp'))}",
                        str(n.get("note") or n.get("status") or "")[:70],
                    )
                )

    return lines


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    lines: List[str] = []
    current: List[str] = []
    length = 0
    for w in words:
        add = len(w) + (1 if current else 0)
        if length + add > width and current:
            lines.append(" ".join(current))
            current = [w]
            length = len(w)
        else:
            current.append(w)
            length += add
    if current:
        lines.append(" ".join(current))
    return lines or [""]


def enrich_ticket_row(ticket: Dict[str, Any]) -> Dict[str, Any]:
    """Liste/detay için summary alanını doldur (mevcut satırı bozmadan)."""
    out = dict(ticket)
    out["summary"] = build_ticket_summary(ticket)
    out["list_line"] = build_ticket_list_line(ticket)
    out["type_label"] = _type_label(ticket)
    out["status_label"] = STATUS_TR.get(
        str(ticket.get("status") or "").lower(), str(ticket.get("status") or "?")
    )
    return out
