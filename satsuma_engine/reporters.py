"""Rapor üreticileri: JSON, SARIF 2.1.0 ve tek dosyalık HTML raporu.

HTML raporu tamamen kendi kendine yeterlidir: gömülü CSS ve küçük bir filtre
betiği dışında hiçbir dış kaynağa bağlanmaz, yani çevrimdışı açılabilir ve
e-posta eki olarak paylaşılabilir.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Iterable

from . import ENGINE_NAME, __version__
from .engine import ScanResult, sort_findings
from .findings import priority_of, severity_label
from .util import iso

SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#0369a1",
    "info": "#475569",
}

PRIORITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#0369a1",
}


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def build_json_report(result: ScanResult, include_suppressed: bool = True) -> dict[str, Any]:
    """Ham JSON rapor yükü."""
    findings = sort_findings(record.finding for record in result.reported)
    payload: dict[str, Any] = {
        "schema": "satsuma-report/v1",
        "engine": {"name": ENGINE_NAME, "version": __version__},
        "generated_at": iso(),
        "summary": result.summary_dict(),
        "findings": findings,
    }
    if include_suppressed:
        payload["suppressed"] = [
            {
                "finding_id": item.finding.get("finding_id"),
                "rule_id": item.finding.get("rule_id"),
                "title": item.finding.get("title"),
                "severity": item.finding.get("severity"),
                "host": item.finding.get("host"),
                "timestamp": item.finding.get("timestamp"),
                "suppression_id": item.suppression_id,
                "reason": item.reason,
            }
            for item in result.suppressed
        ]
    return payload


def write_json_report(result: ScanResult, path: Path, include_suppressed: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_json_report(result, include_suppressed)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------
def build_sarif_report(result: ScanResult) -> dict[str, Any]:
    """SARIF 2.1.0 raporu (CI/GitHub Code Scanning uyumlu)."""
    findings = sort_findings(record.finding for record in result.reported)
    rules_used: dict[str, int] = {}
    sarif_rules: list[dict[str, Any]] = []

    for rule in result.rules:
        rules_used[rule.id] = len(sarif_rules)
        sarif_rules.append(
            {
                "id": rule.id,
                "name": rule.id,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description or rule.title},
                "help": {"text": _rule_help(rule)},
                "defaultConfiguration": {"level": SEVERITY_TO_SARIF[rule.severity]},
                "properties": {
                    "tags": ["security", *(rule.tags or [])],
                    "severity": rule.severity,
                    "classification": rule.classification,
                    "category": rule.category or "uncategorized",
                    "mitre": [m["technique"] for m in rule.mitre],
                    "security-severity": _security_severity(rule.severity),
                },
            }
        )

    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        index = rules_used.get(rule_id)
        location: dict[str, Any] = {
            "logicalLocations": [
                {
                    "name": str(finding.get("host", "unknown")),
                    "kind": "host",
                    "fullyQualifiedName": str(finding.get("host", "unknown")),
                }
            ],
        }
        source_file = (finding.get("evidence") or [{}])
        event_index = next(
            (e.get("value") for e in source_file if e.get("type") == "source_file"),
            None,
        )
        physical: dict[str, Any] = {}
        events_file = result.stats.events_file
        if events_file:
            artifact: dict[str, Any] = {"uri": Path(events_file).as_posix()}
            region: dict[str, Any] = {"startLine": int(event_index) if event_index else 1, "startColumn": 1}
            physical = {"artifactLocation": artifact, "region": region}
            location["physicalLocation"] = physical

        entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(str(finding.get("severity", "info")), "note"),
            "message": {"text": f"{finding.get('title')} — {_evidence_digest(finding)}"},
            "locations": [location],
            "fingerprints": {
                "satsumaFindingId": str(finding.get("finding_id", "")),
                "satsumaDedupKey": str(finding.get("dedup_key", "")),
            },
            "properties": {
                "score": finding.get("score"),
                "priority": priority_of(finding),
                "classification": finding.get("classification"),
                "confidence": finding.get("confidence"),
                "host": finding.get("host"),
                "timestamp": finding.get("timestamp"),
                "occurrences": (finding.get("observations") or {}).get("occurrences", 1),
                "mitre": [m.get("technique") for m in finding.get("mitre") or []],
                "entity": finding.get("entity"),
            },
        }
        if index is not None:
            entry["ruleIndex"] = index
        results.append(entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": ENGINE_NAME,
                        "version": __version__,
                        "informationUri": "https://satsuma.local/engine",
                        "rules": sarif_rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": iso(),
                        "properties": {"stats": result.stats.as_dict()},
                    }
                ],
                "results": results,
                "properties": {"suppressedFindings": len(result.suppressed)},
            }
        ],
    }


def _security_severity(severity: str) -> str:
    return {"info": "1.0", "low": "3.0", "medium": "5.5", "high": "8.0", "critical": "9.5"}.get(severity, "5.0")


def _rule_help(rule: Any) -> str:
    lines = [rule.title]
    if rule.description:
        lines += ["", rule.description]
    if rule.mitre:
        lines += ["", "MITRE ATT&CK: " + ", ".join(f"{m['technique']}" for m in rule.mitre)]
    if rule.actions:
        lines += ["", "Önerilen aksiyonlar: " + ", ".join(rule.actions)]
    return "\n".join(lines)


def _evidence_digest(finding: dict[str, Any], limit: int = 3) -> str:
    chunks = []
    for item in (finding.get("evidence") or [])[:limit]:
        if item.get("type") == "field" and item.get("field"):
            chunks.append(f"{item['field']}={item.get('value')}")
        elif item.get("type") == "aggregation":
            chunks.append(str(item.get("detail", "")))
    return "; ".join(chunks) or str(finding.get("entity", {}).get("value", ""))


def write_sarif_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_sarif_report(result)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _sev_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#475569")
    return f'<span class="badge" style="background:{color}">{_e(severity_label(severity))}</span>'


def _bar(label: str, count: int, total: int, color: str) -> str:
    width = 0 if total <= 0 else max(2 if count else 0, round(count * 100 / total))
    return (
        f'<div class="bar-row"><span class="bar-label">{_e(label)}</span>'
        f'<span class="bar-track"><span class="bar-fill" style="width:{width}%;background:{color}"></span></span>'
        f'<span class="bar-value">{count}</span></div>'
    )


def write_html_report(result: ScanResult, path: Path, include_suppressed: bool = True) -> Path:
    """Tek dosyada açılabilen görsel HTML bulgu raporu."""
    findings = sort_findings(record.finding for record in result.reported)
    stats = result.stats
    severity_counts = result.severity_counts()
    priority_counts = result.priority_counts()
    mitre_rows = result.mitre_rows()
    total = len(findings)
    max_severity = max(severity_counts.values()) if severity_counts else 0

    rows = []
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        priority = priority_of(finding)
        mitre_text = ", ".join(m.get("technique", "") for m in finding.get("mitre") or []) or "—"
        evidence_rows = []
        for item in finding.get("evidence") or []:
            if item.get("type") == "event":
                continue
            evidence_rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    _e(item.get("type")),
                    _e(item.get("field") or item.get("detail") or ""),
                    _e(item.get("value")),
                )
            )
        evidence_table = (
            '<table class="evidence"><thead><tr><th>Kanıt tipi</th><th>Alan</th><th>Değer</th></tr></thead><tbody>'
            + "".join(evidence_rows)
            + "</tbody></table>"
            if evidence_rows
            else '<p class="muted">Ek alan kanıtı yok.</p>'
        )
        breakdown = finding.get("score_breakdown") or {}
        modifier_rows = "".join(
            f"<li>{_e(m.get('reason'))}: <strong>{int(m.get('delta', 0)):+d}</strong></li>"
            for m in breakdown.get("modifiers") or []
        )
        rows.append(
            f"""
            <article class="finding" data-severity="{_e(severity)}" data-priority="{_e(priority)}">
              <header>
                <div class="finding-head">
                  <span class="rule-id">{_e(finding.get('rule_id'))}</span>
                  {_sev_badge(severity)}
                  <span class="score">skor {_e(finding.get('score'))}</span>
                  <span class="badge ghost" style="border-color:{PRIORITY_COLORS.get(priority, '#475569')};color:{PRIORITY_COLORS.get(priority, '#475569')}">öncelik: {_e(priority)}</span>
                  <span class="badge ghost">{_e(finding.get('classification'))}</span>
                </div>
                <h3>{_e(finding.get('title'))}</h3>
                <p class="meta">
                  <span><strong>Kimlik:</strong> {_e(finding.get('finding_id'))}</span>
                  <span><strong>Makine:</strong> {_e(finding.get('host'))}</span>
                  <span><strong>Zaman:</strong> {_e(finding.get('timestamp'))}</span>
                  <span><strong>Görülme:</strong> {(finding.get('observations') or {}).get('occurrences', 1)}</span>
                  <span><strong>Varlık:</strong> {_e((finding.get('entity') or {}).get('kind'))}={_e((finding.get('entity') or {}).get('value'))}</span>
                </p>
              </header>
              <details>
                <summary>Kanıt, skor kırılımı ve MITRE ayrıntısı</summary>
                <div class="detail-grid">
                  <div>
                    <h4>Kanıt</h4>
                    {evidence_table}
                  </div>
                  <div>
                    <h4>Skor kırılımı</h4>
                    <p class="muted">Temel puan: <strong>{_e(breakdown.get('base'))}</strong> · Toplam: <strong>{_e(breakdown.get('total'))}</strong></p>
                    <ul class="modifiers">{modifier_rows or '<li class="muted">Skor değiştirici tetiklenmedi.</li>'}</ul>
                    <h4>MITRE ATT&CK</h4>
                    <p>{_e(mitre_text)}</p>
                    <h4>Önerilen aksiyonlar</h4>
                    <p>{_e(", ".join(finding.get('actions') or ["log_only"]))}</p>
                    <h4>Kural dosyası</h4>
                    <p class="muted">{_e((finding.get('source') or {}).get('rule_file'))}</p>
                  </div>
                </div>
              </details>
            </article>
            """
        )

    suppressed_section = ""
    if include_suppressed and result.suppressed:
        suppressed_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _e(item.finding.get("finding_id")),
                _e(item.finding.get("rule_id")),
                _e(item.finding.get("severity")),
                _e(item.suppression_id),
                _e(item.reason),
            )
            for item in result.suppressed
        )
        suppressed_section = f"""
        <section>
          <h2>Bastırılan bulgular ({len(result.suppressed)})</h2>
          <p class="muted">Bu bulgular bastırma/allowlist kuralları nedeniyle raporlanmadı, ancak şeffaflık için burada listelenir.</p>
          <table class="grid">
            <thead><tr><th>Bulgu</th><th>Kural</th><th>Önem</th><th>Bastırma kaydı</th><th>Gerekçe</th></tr></thead>
            <tbody>{suppressed_rows}</tbody>
          </table>
        </section>
        """

    mitre_table = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _e(row["technique"]),
            _e(row["tactic"]),
            _e(row["name"]),
            row["count"],
            _e(", ".join(row["rules"])),
        )
        for row in mitre_rows
    ) or '<tr><td colspan="5" class="muted">MITRE eşlemesi olan bulgu yok.</td></tr>'

    severity_bars = "".join(
        _bar(severity_label(level), severity_counts.get(level, 0), max_severity, SEVERITY_COLORS[level])
        for level in ("critical", "high", "medium", "low", "info")
    )
    priority_bars = "".join(
        _bar(level, priority_counts.get(level, 0), max(priority_counts.values()) if priority_counts else 0, PRIORITY_COLORS.get(level, "#475569"))
        for level in ("critical", "high", "medium", "low")
    )

    document = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Satsuma Engine — Bulgu Raporu</title>
<style>
  :root {{
    --bg: #0b1120; --panel: #ffffff; --ink: #0f172a; --muted: #64748b;
    --line: #e2e8f0; --accent: #0f766e;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #f1f5f9; color: var(--ink);
    font: 15px/1.55 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }}
  header.top {{ background: linear-gradient(135deg, #0b1120, #123a3a 70%); color: #f8fafc; padding: 28px 32px; }}
  header.top h1 {{ margin: 0 0 6px; font-size: 24px; letter-spacing: .2px; }}
  header.top p {{ margin: 0; color: #a8c0bd; font-size: 13.5px; }}
  main {{ max-width: 1180px; margin: 0 auto; padding: 24px 20px 60px; }}
  section {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
    padding: 20px 22px; margin-bottom: 20px; box-shadow: 0 1px 2px rgba(15,23,42,.05); }}
  h2 {{ font-size: 18px; margin: 0 0 14px; }}
  h3 {{ font-size: 16px; margin: 10px 0 8px; }}
  h4 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 14px 0 6px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }}
  .card {{ background: #f8fafc; border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }}
  .card .k {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
  .card .v {{ font-size: 22px; font-weight: 650; margin-top: 4px; }}
  .two-col {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; }}
  .bar-row {{ display: grid; grid-template-columns: 70px 1fr 42px; align-items: center; gap: 8px; margin-bottom: 7px; }}
  .bar-label {{ font-size: 13px; color: var(--muted); }}
  .bar-track {{ background: #e2e8f0; border-radius: 999px; height: 10px; overflow: hidden; }}
  .bar-fill {{ display: block; height: 100%; border-radius: 999px; }}
  .bar-value {{ font-size: 13px; text-align: right; font-variant-numeric: tabular-nums; }}
  .finding {{ border: 1px solid var(--line); border-left: 4px solid #cbd5e1; border-radius: 10px;
    padding: 14px 16px; margin-bottom: 12px; background: #fff; }}
  .finding[data-severity="critical"] {{ border-left-color: #7f1d1d; }}
  .finding[data-severity="high"] {{ border-left-color: #b91c1c; }}
  .finding[data-severity="medium"] {{ border-left-color: #b45309; }}
  .finding[data-severity="low"] {{ border-left-color: #0369a1; }}
  .finding[data-severity="info"] {{ border-left-color: #64748b; }}
  .finding-head {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
  .rule-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px;
    background: #0f172a; color: #e2e8f0; padding: 3px 8px; border-radius: 6px; }}
  .badge {{ color: #fff; font-size: 12px; padding: 3px 9px; border-radius: 999px; font-weight: 600; }}
  .badge.ghost {{ background: #fff; border: 1px solid var(--line); color: var(--muted); font-weight: 500; }}
  .score {{ font-size: 12.5px; color: var(--muted); }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 4px 18px; font-size: 13px; color: var(--muted); margin: 6px 0 0; }}
  details summary {{ cursor: pointer; color: var(--accent); font-size: 13.5px; font-weight: 600; margin-top: 6px; }}
  .detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  th, td {{ text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--line); vertical-align: top; }}
  th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }}
  table.evidence td:nth-child(3) {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }}
  .modifiers {{ margin: 0; padding-left: 18px; font-size: 13.5px; }}
  .muted {{ color: var(--muted); }}
  .filters {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }}
  .filters button {{ border: 1px solid var(--line); background: #fff; border-radius: 999px;
    padding: 6px 14px; font-size: 13px; cursor: pointer; }}
  .filters button.active {{ background: #0f172a; color: #fff; border-color: #0f172a; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12.5px; padding: 8px 0 0; }}
</style>
</head>
<body>
<header class="top">
  <h1>Satsuma Engine — Bulgu Raporu</h1>
  <p>{_e(ENGINE_NAME)} v{_e(__version__)} · oluşturma: {_e(iso())} · olay dosyası: {_e(stats.events_file or "—")} · kural seti: {_e(stats.ruleset_hash)}</p>
</header>
<main>
  <section>
    <h2>Özet</h2>
    <div class="cards">
      <div class="card"><div class="k">Yüklenen kural</div><div class="v">{stats.rules_loaded}</div></div>
      <div class="card"><div class="k">Taranan olay</div><div class="v">{stats.events_scanned}</div></div>
      <div class="card"><div class="k">Ham tespit</div><div class="v">{stats.raw_detections}</div></div>
      <div class="card"><div class="k">Tekil bulgu</div><div class="v">{stats.unique_findings}</div></div>
      <div class="card"><div class="k">Dedup ile birleşen</div><div class="v">{stats.merged_events}</div></div>
      <div class="card"><div class="k">Bastırılan</div><div class="v">{stats.suppressed_findings}</div></div>
      <div class="card"><div class="k">Tespit üreten kural</div><div class="v">{stats.rules_matched}</div></div>
      <div class="card"><div class="k">Süre</div><div class="v">{stats.elapsed_ms} ms</div></div>
    </div>
  </section>

  <section>
    <h2>Dağılım</h2>
    <div class="two-col">
      <div>
        <h4>Önem seviyesi</h4>
        {severity_bars}
      </div>
      <div>
        <h4>Öncelik</h4>
        {priority_bars}
      </div>
    </div>
  </section>

  <section>
    <h2>MITRE ATT&CK eşlemesi</h2>
    <table class="grid">
      <thead><tr><th>Teknik</th><th>Taktik</th><th>Ad</th><th>Bulgu</th><th>Kurallar</th></tr></thead>
      <tbody>{mitre_table}</tbody>
    </table>
  </section>

  <section>
    <h2>Bulgular ({total})</h2>
    <div class="filters">
      <button class="active" data-filter="all">Tümü</button>
      <button data-filter="critical">Kritik</button>
      <button data-filter="high">Yüksek</button>
      <button data-filter="medium">Orta</button>
      <button data-filter="low">Düşük</button>
      <button data-filter="info">Bilgi</button>
    </div>
    <div id="findings">
      {''.join(rows) if rows else '<p class="muted">Bu taramada raporlanan bulgu yok.</p>'}
    </div>
  </section>

  {suppressed_section}

  <footer>Satsuma Engine tarafından otomatik üretildi · bulgular kural setine ve bastırma listesine göre değişebilir.</footer>
</main>
<script>
  const buttons = document.querySelectorAll('.filters button');
  const items = document.querySelectorAll('#findings .finding');
  buttons.forEach(function (button) {{
    button.addEventListener('click', function () {{
      buttons.forEach(function (b) {{ b.classList.remove('active'); }});
      button.classList.add('active');
      const filter = button.dataset.filter;
      items.forEach(function (item) {{
        item.style.display = (filter === 'all' || item.dataset.severity === filter) ? '' : 'none';
      }});
    }});
  }});
</script>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path


def write_all_reports(result: ScanResult, out_dir: Path, include_suppressed: bool = True) -> dict[str, Path]:
    """Üç formatı birlikte yazar."""
    out_dir.mkdir(parents=True, exist_ok=True)
    return {
        "json": write_json_report(result, out_dir / "report.json", include_suppressed),
        "sarif": write_sarif_report(result, out_dir / "report.sarif"),
        "html": write_html_report(result, out_dir / "report.html", include_suppressed),
    }


def summarize_text(result: ScanResult) -> str:
    """Terminal için kısa özet metni."""
    stats = result.stats
    severity_counts = result.severity_counts()
    lines = [
        f"Kural seti: {stats.rules_loaded} kural ({stats.rules_enabled} etkin), hash {stats.ruleset_hash}",
        f"Olay dosyası: {stats.events_file or '—'} · taranan olay: {stats.events_scanned}",
        f"Ham tespit: {stats.raw_detections} · tekil bulgu: {stats.unique_findings} "
        f"· dedup ile birleşen: {stats.merged_events} · bastırılan: {stats.suppressed_findings}",
        "Önem dağılımı: " + ", ".join(f"{severity_label(k)}={v}" for k, v in severity_counts.items()),
        f"Tespit üreten kural: {stats.rules_matched}/{stats.rules_enabled} · süre: {stats.elapsed_ms} ms",
    ]
    return "\n".join(lines)
