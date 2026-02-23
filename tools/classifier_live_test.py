"""Live classifier validation against real Wazuh-ES telemetry.

Pulls a live sample, runs the full discovery pipeline with the
per-source classifier active, and prints a classification report.
Output is written to /data/classifier_runs/ for regression comparison.

Observation only -- no corrections stored, no model changes.

Usage (inside container):
    python3 tools/classifier_live_test.py
    python3 tools/classifier_live_test.py --sample 2000
    python3 tools/classifier_live_test.py --sample 500 --show-all

Run logs:
    /data/classifier_runs/run_<timestamp>_<source>.txt
"""

from __future__ import annotations

import argparse
import asyncio
import io
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from grasp.adapters.index_poller import IndexPollerAdapter
from grasp.classifier.random_forest import SourceClassifier
from grasp.classifier.training import BootstrapData
from grasp.config import settings
from grasp.discovery.clustering import cluster_fields, register_classifier
from grasp.discovery.features import collect_field_values, extract_features

SOURCE_ID = "wazuh"

RUNS_DIR = Path(os.environ.get("GRASP_CLASSIFIER_RUNS_PATH", "/data/classifier_runs"))

KNOWN_LABELS: dict[str, str] = {
    "agent.ip": "entity",
    "data.srcip": "entity",
    "data.dstip": "entity",
    "@timestamp": "temporal",
    "syscheck.md5_after": "entity",
    "syscheck.md5_before": "entity",
    "syscheck.sha1_after": "entity",
    "syscheck.sha1_before": "entity",
    "syscheck.sha256_after": "entity",
    "syscheck.sha256_before": "entity",
    "rule.level": "metric",
    "data.win.system.eventID": "metric",
    "rule.groups": "enum",
    "decoder.name": "enum",
    "full_log": "text",
    "data.win.system.message": "text",
    "agent.name": "entity",
    "predecoder.hostname": "entity",
}


def _run_label(source_id: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"run_{ts}_{source_id}"


def _write_run(label: str, content: str) -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = RUNS_DIR / f"{label}.txt"
    path.write_text(content, encoding="utf-8")
    return path


def _adapter_config() -> dict:
    return {
        "endpoint": os.environ.get("GRASP_SOURCE_1_ENDPOINT", ""),
        "auth_user": os.environ.get("GRASP_SOURCE_1_AUTH_USER", ""),
        "auth_password": os.environ.get("GRASP_SOURCE_1_AUTH_PASSWORD", ""),
        "ca_cert": os.environ.get("GRASP_SOURCE_1_CA_CERT", ""),
        "tls_verify": os.environ.get("GRASP_SOURCE_1_TLS_VERIFY", "true").lower() == "true",
        "index_pattern": os.environ.get("GRASP_SOURCE_1_INDEX_PATTERN", "wazuh-alerts-4.x-*"),
        "batch_size": 500,
    }


def _load_or_train_classifier() -> SourceClassifier:
    clf = SourceClassifier(source_id=SOURCE_ID)
    if not clf.load():
        clf.train(BootstrapData.for_source(SOURCE_ID))
    return clf


def _verdict(predicted: str, field_path: str) -> str:
    for pattern, expected in KNOWN_LABELS.items():
        if field_path == pattern or field_path.startswith(pattern + "."):
            if predicted == expected:
                return "CORRECT"
            return f"WRONG (expected {expected})"
    return "unknown"


def _print_report(
    results,
    show_all: bool,
    log,
    sample_lookup: dict[str, list[str]],
) -> None:
    by_class: dict[str, list] = {}
    heuristic_count = 0
    classifier_count = 0
    flagged_count = 0
    correct = 0
    wrong = 0
    checked = 0

    for r in results:
        cls = r.field_class.value
        by_class.setdefault(cls, []).append(r)

    log("\n" + "=" * 72)
    log(f"{'FIELD':<50} {'CLASS':<10} {'CONF':>6}  {'DECIDED BY':<12} {'CHECK'}")
    log("=" * 72)

    for cls in ["entity", "temporal", "metric", "enum", "text", "unknown"]:
        fields = by_class.get(cls, [])
        if not fields:
            continue
        log(f"\n-- {cls.upper()} ({len(fields)} fields) --")
        for r in sorted(fields, key=lambda x: x.field_path):
            decided = "classifier" if r.confidence != 0.5 else "heuristic"
            flagged = (
                r.confidence < settings.classifier_confidence_threshold
                and r.confidence != 0.5
            )
            verdict = _verdict(r.field_class.value, r.field_path)

            if decided == "classifier":
                classifier_count += 1
            else:
                heuristic_count += 1
            if flagged:
                flagged_count += 1
            if verdict == "CORRECT":
                correct += 1
                checked += 1
            elif verdict.startswith("WRONG"):
                wrong += 1
                checked += 1

            flag_str = " [flagged]" if flagged else ""

            if show_all or verdict.startswith("WRONG") or flagged:
                log(
                    f"  {r.field_path:<48} {cls:<10} {r.confidence:>6.3f}"
                    f"  {decided:<12} {verdict}{flag_str}"
                )
                samples = sample_lookup.get(r.field_path, [])
                if samples:
                    preview = " | ".join(str(s)[:40] for s in samples[:5])
                    log(f"    samples: {preview}")

    log("\n" + "=" * 72)
    log(f"Total fields      : {len(results)}")
    log(f"Classifier decided: {classifier_count}")
    log(f"Heuristic decided : {heuristic_count}")
    log(f"Flagged for review: {flagged_count}")
    if checked:
        log(f"Ground truth check: {correct}/{checked} correct ({100*correct//checked}%)")
    log("=" * 72)


async def run(sample_size: int, show_all: bool) -> None:
    label = _run_label(SOURCE_ID)
    buf = io.StringIO()

    def log(msg: str = "") -> None:
        print(msg)
        buf.write(msg + "\n")

    log("GRASP Classifier Live Test")
    log(f"Run     : {label}")
    log(f"Source  : {SOURCE_ID}")
    log(f"Sample  : {sample_size}")
    log(f"Date    : {datetime.now(timezone.utc).isoformat()}")
    log()

    clf = _load_or_train_classifier()
    register_classifier(SOURCE_ID, clf)
    log(f"[classifier] status={clf.stats()['model_status']}  samples={clf.stats()['training_samples']}")

    adapter = IndexPollerAdapter(source_id=SOURCE_ID, config=_adapter_config())
    state = await adapter.connect()
    log(f"[adapter]    state={state.value}  indices={len(adapter.available_indices)}")

    if state.value != "connected":
        log("[error] adapter failed to connect -- aborting")
        await adapter.disconnect()
        return

    log(f"[adapter]    sampling {sample_size} events...")
    batch = await adapter.sample(n=sample_size)
    log(f"[adapter]    received {len(batch.events)} events")

    if not batch.events:
        log("[error] no events returned -- aborting")
        await adapter.disconnect()
        return

    payloads = [e.payload for e in batch.events]
    field_values = collect_field_values(payloads)
    log(f"[discovery]  {len(field_values)} unique field paths")

    min_values = int(os.environ.get("GRASP_DISCOVERY_MIN_FIELD_VALUES", "10"))
    features = []
    for path, vals in field_values.items():
        non_null = [v for v in vals if v is not None]
        if len(non_null) >= min_values:
            features.append(extract_features(path, vals))

    log(f"[discovery]  {len(features)} fields with >= {min_values} values")

    # Build sample value lookup before clustering
    sample_lookup: dict[str, list[str]] = {
        f.field_path: f.sample_values for f in features
    }

    output = cluster_fields(features, source_id=SOURCE_ID)

    _print_report(output.results, show_all=show_all, log=log, sample_lookup=sample_lookup)

    run_path = _write_run(label, buf.getvalue())
    print(f"\n[run log]    saved to {run_path}")

    await adapter.disconnect()


async def _safe_run(sample_size: int, show_all: bool) -> None:
    try:
        await run(sample_size, show_all)
    except Exception as exc:
        print(f"[error] {exc}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live classifier validation")
    parser.add_argument(
        "--sample", type=int, default=1000,
        help="Number of events to sample (default: 1000)",
    )
    parser.add_argument(
        "--show-all", action="store_true",
        help="Show all fields, not just wrong/flagged",
    )
    args = parser.parse_args()
    asyncio.run(_safe_run(sample_size=args.sample, show_all=args.show_all))