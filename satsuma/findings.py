"""Review and archive retained findings; no scanner execution or ingestion."""
import json
import time
STATUS_REVIEW = "REVIEW"
STATUS_EXPLAINED = "EXPLAINED"
STATUS_UNRESOLVED = "UNRESOLVED"

def build_summary(finding):
    return str(finding.get('summary') or finding.get('title') or finding.get('type') or 'Finding')[:2000]

def review(store, ident: str, status: str, note: str):
    """Operator marks a finding REVIEW / EXPLAINED / UNRESOLVED and archives it."""
    if status not in (STATUS_REVIEW, STATUS_EXPLAINED, STATUS_UNRESOLVED):
        raise ValueError("Geçersiz inceleme durumu")
    if not isinstance(note, str) or not note.strip() or len(note) > 1000:
        raise ValueError("İnceleme notu zorunlu, en fazla 1000 karakter")

    row = store.db.execute(
        "SELECT body FROM findings WHERE finding_id=?", (ident,)
    ).fetchone()
    if not row:
        raise ValueError("Finding artık tutulmuyor")

    finding = json.loads(row[0])
    finding["status"] = status
    finding["CORRELATION"] = dict(finding.get("CORRELATION") or {})
    finding["CORRELATION"]["status"] = status
    finding.setdefault("review_history", []).append({
        "timestamp": time.time(),
        "status": status,
        "note": note,
    })
    # Refresh narrative
    finding["SUMMARY"] = build_summary(finding)

    archived = store.archive(finding)
    finding["archive"] = archived
    store.db.execute(
        "UPDATE findings SET body=? WHERE finding_id=?",
        (json.dumps(finding, ensure_ascii=False), ident),
    )
    store.db.commit()
    return archived
