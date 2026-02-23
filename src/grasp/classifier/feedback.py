"""Per-source feedback store for classifier corrections.

Corrections are appended to a JSONL file scoped to each source_id.
Each record captures the original prediction, the human-supplied
correct label, and the feature vector ID so the same field sampled
twice produces a deterministic, verifiable record.

File path: {GRASP_FEEDBACK_BASE_PATH}/corrections_{source_id}.jsonl

Schema (one JSON object per line):
{
    "source_id":          str,
    "field_path":         str,
    "feature_vector_id":  str,   -- sha256(source_id:field_path:vector)[:16]
    "correct_label":      str,   -- FieldClass value
    "type_hint":          str|null,
    "original_label":     str,
    "original_confidence": float,
    "timestamp":          str    -- ISO 8601 UTC
}
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from grasp.config import settings

logger = logging.getLogger("grasp.classifier.feedback")

# Required keys for schema validation
_REQUIRED_KEYS = frozenset({
    "source_id",
    "field_path",
    "feature_vector_id",
    "correct_label",
    "original_label",
    "original_confidence",
    "timestamp",
})

# Valid FieldClass string values
_VALID_LABELS = frozenset({
    "entity",
    "temporal",
    "metric",
    "enum",
    "text",
    "unknown",
})


def _vector_id(source_id: str, field_path: str, vector: list[float]) -> str:
    """Deterministic 16-char ID for a (source, field, vector) triple.

    sha256(source_id:field_path:repr(vector))[:16]
    Same field sampled twice with identical values produces the same ID.
    """
    raw = f"{source_id}:{field_path}:{repr(vector)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _corrections_path(source_id: str) -> Path:
    base = Path(settings.feedback_base_path)
    base.mkdir(parents=True, exist_ok=True)
    return base / f"corrections_{source_id}.jsonl"


class FeedbackStore:
    """Append-only store for human classifier corrections.

    One instance per source_id. Thread safety is not guaranteed --
    concurrent writers to the same source_id should be avoided.
    """

    def __init__(self, source_id: str) -> None:
        self.source_id = source_id
        self._path = _corrections_path(source_id)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def append(
        self,
        field_path: str,
        feature_vector: list[float],
        correct_label: str,
        original_label: str,
        original_confidence: float,
        type_hint: Optional[str] = None,
    ) -> dict:
        """Append a correction record and return it.

        Args:
            field_path:          Dot-notation field path.
            feature_vector:      27-dim vector from FieldFeatures.vector.
            correct_label:       Human-supplied correct FieldClass value.
            original_label:      Label the model predicted.
            original_confidence: Model confidence at time of prediction.
            type_hint:           Optional format hint (e.g. 'ipv4').

        Returns:
            The written record as a dict.

        Raises:
            ValueError: If correct_label is not a valid FieldClass value.
        """
        if correct_label not in _VALID_LABELS:
            raise ValueError(
                f"Invalid label '{correct_label}'. "
                f"Must be one of: {sorted(_VALID_LABELS)}"
            )

        record = {
            "source_id": self.source_id,
            "field_path": field_path,
            "feature_vector_id": _vector_id(
                self.source_id, field_path, feature_vector
            ),
            "correct_label": correct_label,
            "type_hint": type_hint,
            "original_label": original_label,
            "original_confidence": round(original_confidence, 4),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

        logger.info(
            "Correction appended source=%s field=%s label=%s fvid=%s",
            self.source_id,
            field_path,
            correct_label,
            record["feature_vector_id"],
        )
        return record

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def load(self) -> list[dict]:
        """Load all valid correction records for this source.

        Malformed or schema-invalid lines are skipped with a warning.

        Returns:
            List of correction dicts, oldest first.
        """
        if not self._path.exists():
            return []

        records: list[dict] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning(
                        "Skipping malformed JSON at %s line %d",
                        self._path, lineno,
                    )
                    continue

                missing = _REQUIRED_KEYS - rec.keys()
                if missing:
                    logger.warning(
                        "Skipping record at %s line %d -- missing keys: %s",
                        self._path, lineno, missing,
                    )
                    continue

                records.append(rec)

        return records

    def count(self) -> int:
        """Total number of valid correction records for this source."""
        return len(self.load())

    def count_by_label(self) -> dict[str, int]:
        """Count corrections grouped by correct_label.

        Returns:
            Dict mapping label -> count, e.g. {'entity': 5, 'temporal': 2}
        """
        counts: dict[str, int] = {}
        for rec in self.load():
            lbl = rec.get("correct_label", "unknown")
            counts[lbl] = counts.get(lbl, 0) + 1
        return counts

    def flagged(self) -> list[dict]:
        """Return all records that were flagged for review at prediction time.

        Flagged records have no 'original_label' set to a confident value --
        they were logged from the samples store where original_confidence
        was below GRASP_CLASSIFIER_CONFIDENCE_THRESHOLD.
        """
        return [
            r for r in self.load()
            if r.get("original_confidence", 1.0)
            < settings.classifier_confidence_threshold
        ]

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate_record(record: dict) -> tuple[bool, list[str]]:
        """Validate a correction record dict against the schema.

        Args:
            record: Dict to validate.

        Returns:
            (is_valid, list_of_error_strings)
        """
        errors: list[str] = []

        missing = _REQUIRED_KEYS - record.keys()
        if missing:
            errors.append(f"Missing required keys: {sorted(missing)}")

        label = record.get("correct_label", "")
        if label not in _VALID_LABELS:
            errors.append(
                f"Invalid correct_label '{label}'. "
                f"Valid values: {sorted(_VALID_LABELS)}"
            )

        conf = record.get("original_confidence")
        if conf is not None and not (0.0 <= float(conf) <= 1.0):
            errors.append(
                f"original_confidence {conf} out of range [0.0, 1.0]"
            )

        return (len(errors) == 0, errors)