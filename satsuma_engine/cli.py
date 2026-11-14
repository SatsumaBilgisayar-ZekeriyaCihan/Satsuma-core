"""`satsuma` komut satırı arayüzü.

Komutlar::

    satsuma rules validate [YOL...]     # YAML/JSON kuralları şema + anlam denetimi
    satsuma rules list     [YOL...]     # kural envanteri (tablo/json/csv)
    satsuma rules schema   --kind rule  # sözleşme şemasını yazdır
    satsuma scan           --events F   # JSONL olaylar üzerinde tarama + raporlar
    satsuma verify         --events F   # uçtan uca doğrulama (bulgular şemaya karşı denetlenir)

Çıkış kodları: 0 başarılı, 1 kural eşleşti ama `--fail-on` eşiği aşıldı, 2 doğrulama/IO hatası.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import ENGINE_NAME, __version__
from .engine import Engine, ScanResult, describe_finding_line, sort_findings
from .errors import ConfigurationError, Issue, RuleValidationError, SatsumaEngineError
from .findings import priority_of, severity_label
from .reporters import (
    build_json_report,
    build_sarif_report,
    summarize_text,
    write_all_reports,
)
from .rule_model import (
    SEVERITY_BASE_SCORE,
    load_rules,
    load_ruleset,
)
from .schema_store import SCHEMA_FILES, load_schema
from .suppression import SuppressionList
from .util import iso

PROJECT_ROOT = Path(__file__).resolve().parent

DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_EVENTS = PROJECT_ROOT / "samples" / "events.jsonl"
if not DEFAULT_EVENTS.is_file():
    DEFAULT_EVENTS = Path("/usr/share/doc/satsuma-core/examples/events.jsonl")
DEFAULT_SUPPRESSION = PROJECT_ROOT / "suppressions" / "allowlist.yaml"

SEVERITY_CHOICES = ["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Ortak yardımcılar
# ---------------------------------------------------------------------------
def _resolve_rules_paths(values: Sequence[str] | None) -> list[Path]:
    if values:
        return [Path(v) for v in values]
    if DEFAULT_RULES_DIR.exists():
        return [DEFAULT_RULES_DIR]
    raise SatsumaEngineError(
        "Kural yolu verilmedi ve varsayılan `rules/` dizini bulunamadı. "
        "Örnek: `satsuma rules validate ./rules`"
    )


def _load_suppressions(path: str | None, optional: bool = True) -> SuppressionList:
    target = Path(path) if path else DEFAULT_SUPPRESSION
    if not target.exists():
        if optional:
            return SuppressionList()
        raise SatsumaEngineError(f"Bastırma dosyası bulunamadı: {target}")
    return SuppressionList.load(target)


def _render_table(rows: list[dict[str, Any]], columns: list[str], headers: dict[str, str] | None = None) -> str:
    if not rows:
        return "(kayıt yok)"
    headers = headers or {c: c for c in columns}
    widths = {c: max(len(headers.get(c, c)), *(len(str(row.get(c, ""))) for row in rows)) for c in columns}
    lines = ["  ".join(headers.get(c, c).ljust(widths[c]) for c in columns).rstrip()]
    lines.append("  ".join("-" * widths[c] for c in columns))
    for row in rows:
        lines.append("  ".join(str(row.get(c, "")).ljust(widths[c]) for c in columns).rstrip())
    return "\n".join(lines)


def _print_issues(issues: Iterable[Issue], label: str) -> int:
    issues = list(issues)
    if not issues:
        return 0
    print(f"\n{label}:")
    for issue in issues:
        prefix = "UYARI" if issue.severity != "error" else "HATA "
        print(f"  {prefix} {issue.format()}")
    return len(issues)


def _severity_at_least(severity: str, threshold: str) -> bool:
    order = ["info", "low", "medium", "high", "critical"]
    try:
        return order.index(severity) >= order.index(threshold)
    except ValueError:
        return False


def _csv(rows: list[dict[str, Any]], columns: list[str]) -> str:
    def cell(value: Any) -> str:
        text = "" if value is None else str(value)
        return '"' + text.replace('"', '""') + '"' if any(ch in text for ch in ',"\n') else text

    lines = [",".join(columns)]
    lines.extend(",".join(cell(row.get(c, "")) for c in columns) for row in rows)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------
def cmd_rules_validate(args: argparse.Namespace) -> int:
    paths = _resolve_rules_paths(args.paths)
    report = load_rules(paths, strict=False)

    suppression_issues: list[Issue] = []
    if args.suppression or DEFAULT_SUPPRESSION.exists():
        suppression_list = _load_suppressions(args.suppression)
        warning_count = len(suppression_list.warnings)
        suppression_issues.extend(suppression_list.warnings)
        suppression_issues.extend(suppression_list.check_rule_references({rule.id for rule in report.rules}))
        if suppression_list.source and not warning_count:
            print(f"Bastırma dosyası: {suppression_list.source} ({len(suppression_list.entries)} kayıt)")

    if args.format == "json":
        payload = {
            "ok": report.ok and not suppression_issues,
            "rules_dir": [str(p) for p in paths],
            "files_scanned": report.files_scanned,
            "files_failed": report.files_failed,
            "rules_loaded": len(report.rules),
            "ruleset_hash": report.ruleset_hash,
            "errors": [i.format() for i in report.errors],
            "warnings": [i.format() for i in list(report.warnings) + suppression_issues],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Satsuma Engine {__version__} — kural doğrulaması")
        print(f"Taranan dosya: {report.files_scanned} (başarısız: {report.files_failed})")
        print(f"Geçerli kural: {len(report.rules)} · kural seti hash: {report.ruleset_hash}")
        categories: dict[str, int] = {}
        severities: dict[str, int] = {}
        for rule in report.rules:
            categories[rule.category or "(kategorisiz)"] = categories.get(rule.category or "(kategorisiz)", 0) + 1
            severities[rule.severity] = severities.get(rule.severity, 0) + 1
        if categories:
            print("Kategoriler: " + ", ".join(f"{k}={v}" for k, v in sorted(categories.items())))
        if severities:
            print("Önem: " + ", ".join(f"{severity_label(k)}={v}" for k, v in sorted(severities.items(), key=lambda kv: SEVERITY_BASE_SCORE[kv[0]])))

        error_count = _print_issues(report.errors, "Hatalar")
        warning_total = _print_issues(list(report.warnings) + suppression_issues, "Uyarılar")
        if error_count:
            print(f"\nSONUÇ: BAŞARISIZ ({error_count} hata, {warning_total} uyarı)")
            return 2
        print(f"\nSONUÇ: BAŞARILI ({len(report.rules)} kural geçerli, {warning_total} uyarı)")

    if report.errors:
        return 2
    if args.strict and suppression_issues:
        return 2
    return 0


def cmd_rules_list(args: argparse.Namespace) -> int:
    paths = _resolve_rules_paths(args.paths)
    report = load_rules(paths, strict=False)

    rules = report.rules
    if args.severity:
        rules = [r for r in rules if r.severity == args.severity]
    if args.category:
        rules = [r for r in rules if r.category == args.category]
    if args.enabled_only:
        rules = [r for r in rules if r.enabled]
    if args.aggregation_only:
        rules = [r for r in rules if r.aggregation]
    if args.tag:
        rules = [r for r in rules if args.tag in r.tags]

    rules = sorted(rules, key=lambda r: (-SEVERITY_BASE_SCORE[r.severity], r.id))
    rows = [rule.summary_row() for rule in rules]

    if args.format == "json":
        print(
            json.dumps(
                {
                    "count": len(rules),
                    "ruleset_hash": report.ruleset_hash,
                    "rules": [rule.to_dict() for rule in rules],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    elif args.format == "csv":
        print(_csv(rows, ["id", "title", "severity", "classification", "confidence", "category", "aggregation", "actions", "mitre", "source_file"]))
    else:
        columns = ["id", "severity", "classification", "enabled", "agg", "category", "actions", "mitre"]
        headers = {
            "id": "KURAL",
            "severity": "ÖNEM",
            "classification": "SINIF",
            "enabled": "AKTİF",
            "agg": "AGG",
            "category": "KATEGORİ",
            "actions": "AKSİYONLAR",
            "mitre": "MITRE",
        }
        table_rows = [
            {
                "id": row["id"],
                "severity": row["severity"],
                "classification": row["classification"],
                "enabled": "evet" if row["enabled"] else "hayır",
                "agg": "evet" if row["aggregation"] else "-",
                "category": row["category"] or "-",
                "actions": row["actions"],
                "mitre": row["mitre"],
            }
            for row in rows
        ]
        print(f"Satsuma Engine {__version__} — kural envanteri ({len(rules)} kural, hash {report.ruleset_hash})")
        print()
        print(_render_table(table_rows, columns, headers))

    if report.errors:
        _print_issues(report.errors, "Yükleme hataları")
        return 2
    return 0


def cmd_rules_schema(args: argparse.Namespace) -> int:
    kinds: list[str] = args.kind or list(SCHEMA_FILES)
    payload: Any = {kind: load_schema(kind) for kind in kinds} if len(kinds) > 1 else load_schema(kinds[0])
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
        print(f"Şema yazıldı: {target}")
    else:
        print(text)
    return 0


# ---------------------------------------------------------------------------
# scan / verify
# ---------------------------------------------------------------------------
def _run_scan(args: argparse.Namespace) -> tuple[ScanResult, Engine]:
    rule_paths = _resolve_rules_paths(args.rules)
    suppression_list = _load_suppressions(args.suppression)
    rules, _warnings = load_ruleset(rule_paths, strict=True)
    if not rules:
        raise SatsumaEngineError("Hiç geçerli kural yüklenemedi; tarama yapılamaz.")

    chain_cfg = None
    if getattr(args, "chains", False):
        from .chain import ChainConfig

        chain_cfg = ChainConfig(window_seconds=getattr(args, "chain_window", 1800))
    engine = Engine(rules, suppressions=suppression_list, include_disabled=args.include_disabled, chains=chain_cfg)
    events_path = Path(args.events) if args.events else DEFAULT_EVENTS
    if not events_path.exists():
        raise ConfigurationError(
            f"Olay dosyası bulunamadı: {events_path}. Örnek: `satsuma scan --events samples/events.jsonl`"
        )
    result = engine.scan_file(events_path)
    return result, engine


def cmd_scan(args: argparse.Namespace) -> int:
    result, engine = _run_scan(args)
    findings = sort_findings(record.finding for record in result.reported)

    if not args.quiet:
        print(f"Satsuma Engine {__version__} — tarama")
        print(summarize_text(result))
        if findings:
            print(f"\nBulgular ({len(findings)}):")
            for finding in findings[: args.limit]:
                print("  " + describe_finding_line(finding))
            if len(findings) > args.limit:
                print(f"  … {len(findings) - args.limit} bulgu daha (--limit ile artırılabilir)")

    formats = [f.strip() for f in (args.format or "json,sarif,html").split(",") if f.strip()]
    if args.stdout:
        payload = build_sarif_report(result) if args.stdout == "sarif" else build_json_report(result)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir and formats:
        written = write_all_reports(result, out_dir)
        if not args.quiet:
            print("\nRaporlar:")
            for name, path in written.items():
                print(f"  {name:<6} {path}")

    if args.fail_on:
        threshold = args.fail_on
        if any(_severity_at_least(str(f.get("severity")), threshold) for f in findings):
            if not args.quiet:
                print(f"\nEşik aşıldı: `{threshold}` veya üzeri bulgu var.")
            return 1
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Uçtan uca doğrulama: kural şeması, tarama, bulgu şeması, bastırma tutarlılığı."""
    from .findings import validate_finding

    print(f"Satsuma Engine {__version__} — uçtan uca doğrulama")
    print(f"Zaman: {iso()}")

    result, engine = _run_scan(args)
    findings = sort_findings(record.finding for record in result.reported)
    ok = True

    print("\n[1/5] Kural doğrulaması")
    print(f"  yüklenen kural: {result.stats.rules_loaded} (etkin {result.stats.rules_enabled})")
    print(f"  kural seti hash: {result.stats.ruleset_hash}")
    print(f"  devre dışı kural: {len(engine.disabled_rules)}")

    print("\n[2/5] Tarama")
    print(f"  olay: {result.stats.events_scanned} (eşleşen {result.stats.events_matched})")
    print(f"  ham tespit: {result.stats.raw_detections}")
    print(f"  tekil bulgu: {result.stats.unique_findings} · dedup ile birleşen: {result.stats.merged_events}")
    print(f"  bastırılan: {result.stats.suppressed_findings}")

    print("\n[3/5] Bulgu şeması doğrulaması")
    schema_issues: list[Issue] = []
    for record in result.findings:
        schema_issues.extend(validate_finding(record.finding))
    if schema_issues:
        ok = False
        _print_issues(schema_issues[:20], "Şema hataları")
        print(f"  toplam {len(schema_issues)} şema hatası")
    else:
        print(f"  {len(result.findings)} bulgu `findings/v1` şemasına uygun")

    print("\n[4/5] Bastırma tutarlılığı")
    if result.suppressions:
        summary = result.suppressions.summary()
        print(f"  kaynak: {summary['source'] or '—'} · kayıt: {summary['entries']} · etkin: {summary['active']}")
        if summary["hits"]:
            print("  isabet: " + ", ".join(f"{k}={v}" for k, v in summary["hits"].items()))
        reference_issues = result.suppressions.check_rule_references({rule.id for rule in result.rules})
        if reference_issues:
            _print_issues(reference_issues, "Bastırma uyarıları")
    else:
        print("  bastırma listesi yok (tüm bulgular raporlanır)")

    print("\n[5/5] Rapor çıktıları")
    out_dir = Path(args.out_dir) if args.out_dir else PROJECT_ROOT / "out"
    written = write_all_reports(result, out_dir)
    for name, path in written.items():
        print(f"  {name:<6} {path}")

    print("\nKapsam")
    coverage = engine.coverage(record.finding for record in result.findings)
    print(f"  tespit üreten kural: {coverage['fired_rules']} · hiç tetiklenmeyen: {coverage['silent_rules']}")

    print("\nÖzet")
    for line in summarize_text(result).splitlines():
        print("  " + line)
    if findings:
        top = findings[0]
        print(f"  en yüksek skor: {top.get('finding_id')} / {top.get('rule_id')} "
              f"(skor {top.get('score')}, öncelik {priority_of(top)})")

    print(f"\nSONUÇ: {'BAŞARILI' if ok else 'BAŞARISIZ'}")
    return 0 if ok else 2


# ---------------------------------------------------------------------------
# Ayrıştırıcı
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="satsuma",
        description="Satsuma Engine — şema tabanlı tespit kural motoru ve bulgu hattı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Örnekler:\n"
            "  satsuma rules validate rules/\n"
            "  satsuma rules list rules/ --format csv\n"
            "  satsuma scan --events samples/events.jsonl --out-dir out --format html,json,sarif\n"
            "  satsuma verify --events samples/events.jsonl\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{ENGINE_NAME} {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    rules = subparsers.add_parser("rules", help="kural yazma, doğrulama ve listeleme")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)

    validate = rules_sub.add_parser("validate", help="kuralları şema ve anlam denetiminden geçir")
    validate.add_argument("paths", nargs="*", help="kural dosyası/dizini (varsayılan: ./rules)")
    validate.add_argument("--format", choices=["text", "json"], default="text")
    validate.add_argument("--suppression", help="bastırma dosyası yolu")
    validate.add_argument("--strict", action="store_true", help="uyarıları da hata say")
    validate.set_defaults(func=cmd_rules_validate)

    listing = rules_sub.add_parser("list", help="kural envanterini listele")
    listing.add_argument("paths", nargs="*", help="kural dosyası/dizini (varsayılan: ./rules)")
    listing.add_argument("--format", choices=["table", "json", "csv"], default="table")
    listing.add_argument("--severity", choices=SEVERITY_CHOICES)
    listing.add_argument("--category")
    listing.add_argument("--tag")
    listing.add_argument("--enabled-only", action="store_true")
    listing.add_argument("--aggregation-only", action="store_true")
    listing.set_defaults(func=cmd_rules_list)

    schema = rules_sub.add_parser("schema", help="sözleşme şemasını yazdır")
    schema.add_argument("--kind", action="append", choices=sorted(SCHEMA_FILES), help="şema türü (birden fazla verilebilir)")
    schema.add_argument("--out", help="şemayı dosyaya yaz")
    schema.set_defaults(func=cmd_rules_schema)

    scan = subparsers.add_parser("scan", help="JSONL olaylar üzerinde tarama çalıştır")
    scan.add_argument("--rules", action="append", help="kural dizini/dosyası (birden fazla verilebilir)")
    scan.add_argument("--events", help="JSONL olay dosyası")
    scan.add_argument("--suppression", help="bastırma/allowlist dosyası")
    scan.add_argument("--out-dir", help="rapor çıktı dizini")
    scan.add_argument("--format", default="json,sarif,html", help="üretilecek rapor biçimleri (json,sarif,html)")
    scan.add_argument("--stdout", choices=["json", "sarif"], help="raporu ekrana yaz")
    scan.add_argument("--limit", type=int, default=25, help="terminalde gösterilecek bulgu sayısı")
    scan.add_argument("--fail-on", choices=SEVERITY_CHOICES, help="bu önem ve üzeri bulgu varsa çıkış kodu 1")
    scan.add_argument("--include-disabled", action="store_true", help="devre dışı kuralları da değerlendir")
    scan.add_argument("--chains", action="store_true", help="aynı güçlü süreç kimliğindeki tespitleri zincir bulgusuna yükselt")
    scan.add_argument("--chain-window", type=int, default=1800, help="zincir zaman penceresi (saniye)")
    scan.add_argument("--quiet", action="store_true")
    scan.set_defaults(func=cmd_scan)

    verify = subparsers.add_parser("verify", help="uçtan uca doğrulama (bulgular şemaya karşı denetlenir)")
    verify.add_argument("--rules", action="append", help="kural dizini/dosyası")
    verify.add_argument("--events", help="JSONL olay dosyası")
    verify.add_argument("--suppression", help="bastırma/allowlist dosyası")
    verify.add_argument("--out-dir", help="rapor çıktı dizini")
    verify.add_argument("--include-disabled", action="store_true")
    verify.add_argument("--chains", action="store_true")
    verify.add_argument("--chain-window", type=int, default=1800)
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RuleValidationError as exc:
        print(exc.render(), file=sys.stderr)
        return exc.exit_code
    except SatsumaEngineError as exc:
        print(f"HATA: {exc.message}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover
        print("\nİptal edildi.", file=sys.stderr)
        return 130
