"""Retraining CLI for per-source GRASP classifiers.

Loads bootstrap ground truth + human corrections from FeedbackStore,
enforces the minimum corrections floor, retrains the SourceClassifier,
and persists the updated model.

Usage:
    python3 -m grasp.classifier.retrain --source wazuh
    python3 -m grasp.classifier.retrain --source wazuh --dry-run
    python3 -m grasp.classifier.retrain --source wazuh --force

Flags:
    --source   Required. Source ID to retrain (e.g. 'wazuh', 'suricata').
    --dry-run  Check floor and report record counts without retraining.
    --force    Bypass the minimum corrections floor. Use with caution --
               small correction sets cause overfitting in RandomForest.

Exit codes:
    0  Success (or dry-run floor met).
    1  Floor not met (without --force).
    2  Bootstrap unavailable for source.
    3  sklearn / joblib unavailable.
    4  Unexpected error.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging: structured to stdout so Docker log drivers capture it cleanly.
# No file handler here -- the container runtime owns log routing.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("grasp.classifier.retrain")


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 -m grasp.classifier.retrain",
        description="Retrain a GRASP per-source classifier.",
    )
    p.add_argument(
        "--source",
        required=True,
        metavar="SOURCE_ID",
        help="Source identifier to retrain (e.g. wazuh, suricata).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Report counts and floor status without retraining.",
    )
    p.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Bypass minimum corrections floor. Risk of overfitting.",
    )
    return p


def _corrections_to_training_records(
    corrections: list[dict],
    source_id: str,
) -> list:
    """Convert FeedbackStore correction dicts to TrainingRecord instances.

    Corrections lack raw feature vectors -- they carry a feature_vector_id
    but not the vector itself. We rebuild the vector by re-running
    extract_features() against stored sample values from the samples store.
    If no sample is found for a correction, it is skipped with a warning.

    The samples store is a JSONL file at GRASP_SAMPLES_BASE_PATH/features_{source_id}.jsonl.
    Each line is a JSON object produced by clustering.py when it logs field features:
        {"field_path": "...", "vector": [...], "samples": [...], ...}
    """
    from grasp.classifier.base import TrainingRecord
    from grasp.config import settings

    samples_path = (
        Path(settings.samples_base_path) / f"features_{source_id}.jsonl"
    )

    # Build field_path -> vector map from samples store
    vector_map: dict[str, list[float]] = {}
    if samples_path.exists():
        with samples_path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    fp = rec.get("field_path")
                    vec = rec.get("vector")
                    if fp and vec:
                        vector_map[fp] = vec
                except json.JSONDecodeError:
                    logger.warning(
                        "Skipping malformed JSON in samples store line %d", lineno,
                    )
    else:
        logger.warning(
            "Samples store not found at %s -- corrections will be rebuilt "
            "from field_path names only (reduced accuracy)",
            samples_path,
        )

    records: list[TrainingRecord] = []
    skipped = 0
    for corr in corrections:
        fp = corr.get("field_path", "")
        label = corr.get("correct_label", "")
        if not fp or not label:
            skipped += 1
            continue

        if fp in vector_map:
            vec = vector_map[fp]
        else:
            # Fall back: generate a fresh vector from the field path alone.
            # This is weaker than a live vector but better than discarding.
            from grasp.discovery.features import extract_features
            feat = extract_features(fp, [])
            vec = feat.vector
            logger.debug(
                "No cached vector for '%s' -- rebuilt from field path", fp,
            )

        records.append(TrainingRecord(
            feature_vector=vec,
            label=label,
            source_id=source_id,
            field_path=fp,
        ))

    if skipped:
        logger.warning(
            "%d correction records skipped (missing field_path or label)", skipped,
        )

    return records


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns exit code."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    source_id: str = args.source
    dry_run: bool = args.dry_run
    force: bool = args.force

    logger.info(
        "retrain start source=%s dry_run=%s force=%s",
        source_id, dry_run, force,
    )

    # ------------------------------------------------------------------
    # 1. Verify sklearn is available before doing any work
    # ------------------------------------------------------------------
    try:
        import sklearn  # noqa: F401
        import joblib   # noqa: F401
    except ImportError:
        logger.error("scikit-learn / joblib not available -- cannot retrain")
        return 3

    # ------------------------------------------------------------------
    # 2. Load bootstrap records
    # ------------------------------------------------------------------
    from grasp.classifier.training import BootstrapData

    bootstrap = BootstrapData.for_source(source_id)
    if not bootstrap:
        logger.error(
            "No bootstrap data registered for source '%s'. "
            "Register a bootstrap function in training.py _REGISTRY.",
            source_id,
        )
        return 2

    logger.info(
        "Bootstrap records loaded: %d for source=%s",
        len(bootstrap), source_id,
    )

    # ------------------------------------------------------------------
    # 3. Load corrections from FeedbackStore
    # ------------------------------------------------------------------
    from grasp.classifier.feedback import FeedbackStore

    store = FeedbackStore(source_id)
    raw_corrections = store.load()
    correction_count = len(raw_corrections)

    logger.info(
        "Corrections loaded: %d for source=%s",
        correction_count, source_id,
    )

    if raw_corrections:
        label_dist = store.count_by_label()
        logger.info("Correction label distribution: %s", label_dist)

    # ------------------------------------------------------------------
    # 4. Enforce minimum corrections floor
    # ------------------------------------------------------------------
    from grasp.config import settings

    min_floor = settings.classifier_min_corrections
    floor_met = correction_count >= min_floor

    if dry_run:
        status = "MET" if floor_met else "NOT MET"
        logger.info(
            "DRY RUN: source=%s bootstrap=%d corrections=%d floor=%d status=%s",
            source_id, len(bootstrap), correction_count, min_floor, status,
        )
        if not floor_met:
            logger.info(
                "Need %d more corrections before retraining is meaningful.",
                min_floor - correction_count,
            )
        return 0

    if not floor_met and not force:
        logger.error(
            "Floor not met: %d corrections < %d required. "
            "Add more corrections or use --force to bypass.",
            correction_count, min_floor,
        )
        return 1

    if not floor_met and force:
        logger.warning(
            "Floor bypassed via --force: %d corrections < %d required. "
            "RandomForest may overfit on this correction set.",
            correction_count, min_floor,
        )

    # ------------------------------------------------------------------
    # 5. Convert corrections to TrainingRecords and combine with bootstrap
    # ------------------------------------------------------------------
    correction_records = _corrections_to_training_records(
        raw_corrections, source_id,
    )

    all_records = bootstrap + correction_records

    logger.info(
        "Combined training set: %d records (%d bootstrap + %d corrections) "
        "for source=%s",
        len(all_records), len(bootstrap), len(correction_records), source_id,
    )

    # ------------------------------------------------------------------
    # 6. Load existing model (or cold start) and retrain
    # ------------------------------------------------------------------
    from grasp.classifier.random_forest import SourceClassifier

    clf = SourceClassifier(source_id=source_id)
    loaded = clf.load()
    if not loaded:
        logger.info(
            "No persisted model for source=%s -- training from bootstrap first",
            source_id,
        )
        clf.train(bootstrap)

    # retrain() enforces the floor internally; --force bypasses it above
    # by temporarily inflating the correction count signal via all_records.
    # We monkey-patch _n_train to 0 so retrain()'s internal floor calc
    # sees all records as corrections when --force is active.
    if force and not floor_met:
        # bypass: call train() directly instead of retrain() so the
        # corrections floor check is skipped and stats are accurate
        clf.train(all_records)
        # manually set correction count so stats reflect reality
        clf._n_corrections = len(correction_records)
        clf._n_train = len(all_records)
        clf._model_status = "trained"
        clf.persist()
    else:
        clf.retrain(all_records)

    final_stats = clf.stats()
    logger.info("Retrain complete: %s", final_stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())