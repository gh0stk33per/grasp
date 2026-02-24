"""SENTINEL analysis engine.

Orchestrates: load corpus inventory -> parse BIN files -> run analyzers -> report.

Usage:
    python3 sentinel/engine.py \\
        --data-dir  sentinel/data/ \\
        --analyzers gps_spoof \\
        [--fingerprint 239e0f32] \\
        [--files 00000019.BIN 00000020.BIN] \\
        [--output-dir sentinel/data/reports/] \\
        [--quiet]

Output:
    stdout                                    -- human-readable report per file
    <output-dir>/<analyzer>/results.json      -- machine-readable full results
    <output-dir>/<analyzer>/summary.json      -- aggregated counts and stats
"""

import argparse
import json
import pathlib
import sys
import time

from sentinel.core.parser import parse_file
from sentinel.analyzers.base import AnalysisResult, Verdict


# ---------------------------------------------------------------------------
# Analyzer registry -- add new analyzers here as they are built
# ---------------------------------------------------------------------------

def _load_analyzer(name: str):
    if name == "gps_spoof":
        from sentinel.analyzers.gps_spoof import GPSSpoofAnalyzer
        return GPSSpoofAnalyzer()
    raise ValueError(f"Unknown analyzer: '{name}'. Available: gps_spoof")


# ---------------------------------------------------------------------------
# Corpus inventory loader
# ---------------------------------------------------------------------------

def _load_inventory(data_dir: pathlib.Path) -> list[dict]:
    inv_path = data_dir / "corpus_inventory.json"
    if not inv_path.exists():
        print(f"ERROR: corpus_inventory.json not found in {data_dir}")
        print("       Run corpus_scan.py first.")
        sys.exit(1)
    with inv_path.open(encoding='utf-8') as fh:
        return json.load(fh)


def _select_files(
    inventory: list[dict],
    data_dir: pathlib.Path,
    fingerprint: str | None,
    explicit_files: list[str] | None,
) -> list[pathlib.Path]:
    """Apply --fingerprint and --files filters to the inventory."""
    selected = inventory

    if fingerprint:
        selected = [
            r for r in selected
            if r.get('parameter_fingerprint') == fingerprint
        ]
        if not selected:
            print(f"ERROR: No files found with fingerprint '{fingerprint}'")
            sys.exit(1)

    if explicit_files:
        names    = set(explicit_files)
        selected = [r for r in selected if r['file'] in names]
        if not selected:
            print(f"ERROR: None of the specified files found in inventory")
            sys.exit(1)

    paths = []
    for r in selected:
        p = data_dir / r['file']
        if p.exists():
            paths.append(p)
        else:
            print(f"  WARN: {r['file']} in inventory but not found on disk -- skipping")

    return paths


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def _build_summary(results: list[AnalysisResult], analyzer_name: str) -> dict:
    from collections import Counter
    verdict_counts = Counter(r.verdict.value for r in results)
    confidence_vals = [r.confidence for r in results if r.confidence > 0]
    avg_conf = (
        sum(confidence_vals) / len(confidence_vals)
        if confidence_vals else 0.0
    )

    # Check-level breakdown
    check_verdicts: dict[str, Counter] = {}
    for r in results:
        for f in r.findings:
            if f.check not in check_verdicts:
                check_verdicts[f.check] = Counter()
            check_verdicts[f.check][f.verdict.value] += 1

    alert_files = [
        r.filepath.name for r in results
        if r.verdict == Verdict.ALERT
    ]
    suspicious_files = [
        r.filepath.name for r in results
        if r.verdict == Verdict.SUSPICIOUS
    ]

    return {
        'analyzer':       analyzer_name,
        'total_files':    len(results),
        'verdict_counts': dict(verdict_counts),
        'avg_confidence': round(avg_conf, 3),
        'alert_files':    alert_files,
        'suspicious_files': suspicious_files,
        'check_breakdown': {
            check: dict(counts)
            for check, counts in check_verdicts.items()
        },
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='SENTINEL analysis engine'
    )
    parser.add_argument('--data-dir',    required=True,
                        help='Directory containing .BIN files and corpus_inventory.json')
    parser.add_argument('--analyzers',   required=True, nargs='+',
                        help='Analyzers to run (e.g. gps_spoof)')
    parser.add_argument('--fingerprint', default=None,
                        help='Limit to files matching this config fingerprint')
    parser.add_argument('--files',       default=None, nargs='+',
                        help='Limit to specific filenames')
    parser.add_argument('--output-dir',  default=None,
                        help='Output directory for JSON reports (default: <data-dir>/reports/)')
    parser.add_argument('--quiet',       action='store_true',
                        help='Suppress per-file human-readable output')
    args = parser.parse_args()

    data_dir   = pathlib.Path(args.data_dir)
    output_dir = pathlib.Path(args.output_dir) if args.output_dir else data_dir / 'reports'

    inventory  = _load_inventory(data_dir)
    bin_files  = _select_files(
        inventory, data_dir,
        args.fingerprint,
        args.files,
    )

    print(f"SENTINEL Engine")
    print(f"  Data dir   : {data_dir}")
    print(f"  Files      : {len(bin_files)}")
    print(f"  Analyzers  : {', '.join(args.analyzers)}")
    if args.fingerprint:
        print(f"  Fingerprint: {args.fingerprint}")
    print()

    analyzers = [_load_analyzer(name) for name in args.analyzers]

    for analyzer in analyzers:
        print(f"Running {analyzer.NAME} v{analyzer.VERSION}")
        print(f"{'='*64}")

        results: list[AnalysisResult] = []
        t_start = time.monotonic()

        for i, filepath in enumerate(bin_files, 1):
            size_kb = filepath.stat().st_size // 1024
            print(f"  [{i:02d}/{len(bin_files)}] {filepath.name} ({size_kb} KB) ... ",
                  end='', flush=True)

            try:
                pr     = parse_file(filepath)
                result = analyzer.analyze(pr)
            except Exception as exc:
                print(f"ERROR: {exc}")
                continue

            results.append(result)
            print(result.verdict.value)

            if not args.quiet:
                print(analyzer.explain(result))

        elapsed = time.monotonic() - t_start
        print(f"\nCompleted {len(results)} files in {elapsed:.1f}s")

        # -- Write JSON output ----------------------------------------
        out_dir = output_dir / analyzer.NAME
        out_dir.mkdir(parents=True, exist_ok=True)

        results_path = out_dir / 'results.json'
        summary_path = out_dir / 'summary.json'

        results_data = [r.to_dict() for r in results]
        summary_data = _build_summary(results, analyzer.NAME)

        results_path.write_text(
            json.dumps(results_data, indent=2), encoding='utf-8'
        )
        summary_path.write_text(
            json.dumps(summary_data, indent=2), encoding='utf-8'
        )

        print(f"Written: {results_path}")
        print(f"Written: {summary_path}")
        print()

        # -- Print summary table --------------------------------------
        print("SUMMARY")
        print(f"  {'VERDICT':<14} COUNT")
        for v, count in sorted(summary_data['verdict_counts'].items()):
            print(f"  {v:<14} {count}")
        print()
        print("  CHECK BREAKDOWN")
        for check, counts in summary_data['check_breakdown'].items():
            parts = '  '.join(f"{v}:{n}" for v, n in sorted(counts.items()))
            print(f"    {check:<28} {parts}")
        print()
        if summary_data['alert_files']:
            print(f"  ALERT files ({len(summary_data['alert_files'])}):")
            for f in summary_data['alert_files']:
                print(f"    {f}")
        if summary_data['suspicious_files']:
            print(f"  SUSPICIOUS files ({len(summary_data['suspicious_files'])}):")
            for f in summary_data['suspicious_files']:
                print(f"    {f}")
        print()


if __name__ == '__main__':
    main()