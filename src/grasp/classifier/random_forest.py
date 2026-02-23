"""RandomForest implementation of AbstractClassifier.

Per-source field classifier backed by scikit-learn RandomForestClassifier.
One instance per source_id. Models are persisted to GRASP_MODEL_BASE_PATH
and loaded on startup. Cold start returns None -- heuristic fallback applies.

Retraining is on-demand only. Call retrain() after corrections accumulate
above GRASP_CLASSIFIER_MIN_CORRECTIONS.

File paths:
    model:   {GRASP_MODEL_BASE_PATH}/classifier_{source_id}.joblib
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from grasp.classifier.base import (
    AbstractClassifier,
    ClassifierResult,
    TrainingRecord,
)
from grasp.config import settings
from grasp.discovery.clustering import FieldClass
from grasp.discovery.features import FEATURE_DIM, FieldFeatures

logger = logging.getLogger("grasp.classifier.random_forest")

# Lazy imports -- joblib and sklearn only needed when a model is used
try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.error(
        "scikit-learn or joblib not available -- SourceClassifier disabled"
    )


def _model_path(source_id: str) -> Path:
    base = Path(settings.model_base_path)
    base.mkdir(parents=True, exist_ok=True)
    return base / f"classifier_{source_id}.joblib"


class SourceClassifier(AbstractClassifier):
    """Per-source RandomForest field classifier.

    State:
        _clf:           Trained RandomForestClassifier or None.
        _encoder:       LabelEncoder mapping FieldClass strings to ints.
        _n_train:       Number of records used in last train/retrain.
        _n_corrections: Correction records seen at last retrain.
        _model_status:  'cold_start' | 'bootstrapping' | 'trained'
    """

    def __init__(self, source_id: str) -> None:
        super().__init__(source_id)
        self._clf: Optional[RandomForestClassifier] = None
        self._encoder: Optional[LabelEncoder] = None
        self._n_train: int = 0
        self._n_corrections: int = 0
        self._model_status: str = "cold_start"
        self._threshold: float = settings.classifier_confidence_threshold
        self._min_corrections: int = settings.classifier_min_corrections

    # ------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------

    def train(self, records: list[TrainingRecord]) -> None:
        """Train from a full set of labelled records (bootstrap).

        Replaces any existing model. Sets status to 'bootstrapping'
        since bootstrap data alone does not constitute a trained model
        in the operational sense -- corrections are needed to reach
        'trained' status.

        Args:
            records: Labelled TrainingRecord list. No-op if empty.
        """
        if not records:
            logger.warning(
                "source=%s train() called with empty records -- no-op",
                self.source_id,
            )
            return

        if not _SKLEARN_AVAILABLE:
            logger.error("sklearn unavailable -- cannot train")
            return

        X, y = self._build_matrices(records)
        self._encoder = LabelEncoder()
        y_enc = self._encoder.fit_transform(y)

        self._clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._clf.fit(X, y_enc)
        self._n_train = len(records)
        self._n_corrections = 0
        self._model_status = "bootstrapping"

        logger.info(
            "source=%s train complete: %d records, classes=%s",
            self.source_id, len(records),
            list(self._encoder.classes_),
        )
        self.persist()

    def retrain(self, records: list[TrainingRecord]) -> None:
        """Retrain incorporating correction records.

        Enforces GRASP_CLASSIFIER_MIN_CORRECTIONS. Count of correction
        records is inferred as records beyond the bootstrap set size.
        Caller is responsible for passing combined bootstrap + correction
        records.

        Args:
            records: Combined bootstrap + correction TrainingRecord list.
        """
        if not _SKLEARN_AVAILABLE:
            logger.error("sklearn unavailable -- cannot retrain")
            return

        correction_count = max(0, len(records) - self._n_train)
        if correction_count < self._min_corrections:
            logger.warning(
                "source=%s retrain skipped: %d corrections below floor %d",
                self.source_id, correction_count, self._min_corrections,
            )
            return

        X, y = self._build_matrices(records)

        # Refit encoder to handle any new labels in corrections
        self._encoder = LabelEncoder()
        y_enc = self._encoder.fit_transform(y)

        self._clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._clf.fit(X, y_enc)
        self._n_corrections = correction_count
        self._n_train = len(records)
        self._model_status = "trained"

        logger.info(
            "source=%s retrain complete: %d records (%d corrections), classes=%s",
            self.source_id, len(records), correction_count,
            list(self._encoder.classes_),
        )
        self.persist()

    # ------------------------------------------------------------------
    # Predict
    # ------------------------------------------------------------------

    def predict(self, feat: FieldFeatures) -> Optional[ClassifierResult]:
        """Classify a single field.

        Returns None on cold start. Below confidence threshold, returns
        a result flagged for analyst review -- the heuristic fallback
        is the caller's responsibility when None is returned.

        Args:
            feat: FieldFeatures from extract_features().

        Returns:
            ClassifierResult or None on cold start.
        """
        if self._clf is None or self._encoder is None:
            return None

        if len(feat.vector) != FEATURE_DIM:
            logger.warning(
                "source=%s predict: vector dim %d != %d -- skipping",
                self.source_id, len(feat.vector), FEATURE_DIM,
            )
            return None

        X = [feat.vector]
        proba = self._clf.predict_proba(X)[0]
        top_idx = int(proba.argmax())
        confidence = float(proba[top_idx])
        label_str = self._encoder.inverse_transform([top_idx])[0]

        try:
            fc = FieldClass(label_str)
        except ValueError:
            logger.warning(
                "source=%s unknown predicted label '%s' -- defaulting UNKNOWN",
                self.source_id, label_str,
            )
            fc = FieldClass.UNKNOWN

        is_entity = fc == FieldClass.ENTITY
        flagged = confidence < self._threshold

        if flagged:
            logger.debug(
                "source=%s field=%s confidence=%.3f below threshold=%.2f -- flagged",
                self.source_id, feat.field_path, confidence, self._threshold,
            )

        return ClassifierResult(
            field_class=fc,
            is_entity=is_entity,
            confidence=confidence,
            model_status=self._model_status,
            flagged=flagged,
        )

    # ------------------------------------------------------------------
    # Persist / Load
    # ------------------------------------------------------------------

    def persist(self) -> None:
        """Persist model and encoder to disk."""
        if self._clf is None or self._encoder is None:
            return

        path = _model_path(self.source_id)
        payload = {
            "clf": self._clf,
            "encoder": self._encoder,
            "n_train": self._n_train,
            "n_corrections": self._n_corrections,
            "model_status": self._model_status,
        }
        joblib.dump(payload, path)
        logger.info("source=%s model persisted to %s", self.source_id, path)

    def load(self) -> bool:
        """Load persisted model from disk.

        Returns:
            True if loaded, False on cold start.
        """
        path = _model_path(self.source_id)
        if not path.exists():
            logger.info(
                "source=%s no persisted model at %s -- cold start",
                self.source_id, path,
            )
            return False

        try:
            payload = joblib.load(path)
            self._clf = payload["clf"]
            self._encoder = payload["encoder"]
            self._n_train = payload.get("n_train", 0)
            self._n_corrections = payload.get("n_corrections", 0)
            self._model_status = payload.get("model_status", "bootstrapping")
            logger.info(
                "source=%s model loaded from %s status=%s",
                self.source_id, path, self._model_status,
            )
            return True
        except Exception as exc:
            logger.error(
                "source=%s failed to load model from %s: %s",
                self.source_id, path, exc,
            )
            return False

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, object]:
        """Operational statistics for health checks and API endpoints."""
        classes = (
            list(self._encoder.classes_)
            if self._encoder is not None
            else []
        )
        return {
            "source_id": self.source_id,
            "model_status": self._model_status,
            "training_samples": self._n_train,
            "correction_count": self._n_corrections,
            "feature_dim": FEATURE_DIM,
            "confidence_threshold": self._threshold,
            "min_corrections": self._min_corrections,
            "classes": classes,
            "model_path": str(_model_path(self.source_id)),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _build_matrices(
        records: list[TrainingRecord],
    ) -> tuple[list[list[float]], list[str]]:
        """Split records into feature matrix X and label vector y."""
        X = [r.feature_vector for r in records]
        y = [r.label for r in records]
        return X, y