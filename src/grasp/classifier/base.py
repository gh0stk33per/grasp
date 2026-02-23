"""Abstract classifier interface.

Defines the contract all classifier implementations must satisfy.
This boundary allows algorithm swap (RandomForest -> XGBoost -> neural)
without touching the discovery pipeline or feedback machinery.

Implementations:
    random_forest.py -- SourceClassifier (RandomForest, current default)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from grasp.discovery.features import FieldFeatures

if TYPE_CHECKING:
    from grasp.discovery.clustering import FieldClass


@dataclass(frozen=True)
class ClassifierResult:
    """Output of a single field classification.

    Attributes:
        field_class:  Predicted FieldClass label.
        is_entity:    True if this field should produce graph nodes.
        confidence:   Model confidence in [0.0, 1.0].
        model_status: 'trained' | 'bootstrapping' | 'cold_start'
        flagged:      True when confidence < threshold -- review candidate.
    """
    field_class: "FieldClass"
    is_entity: bool
    confidence: float
    model_status: str
    flagged: bool


@dataclass(frozen=True)
class TrainingRecord:
    """A single labelled example for classifier training or retraining.

    Attributes:
        feature_vector: 27-dim float list from FieldFeatures.vector.
        label:          Correct FieldClass string value (e.g. 'entity').
        source_id:      Source this record belongs to.
        field_path:     Dot-notation path for diagnostics only.
    """
    feature_vector: list[float]
    label: str
    source_id: str
    field_path: str


class AbstractClassifier(ABC):
    """Contract for all per-source field classifiers.

    Each instance is scoped to a single source_id. Implementations
    are responsible for their own persistence, cold-start behaviour,
    and confidence thresholding.

    Lifecycle:
        1. Instantiate with source_id.
        2. Call train() with bootstrap records to initialise model.
        3. Call predict() per field during discovery.
        4. Call retrain() after corrections accumulate.
        5. Call stats() for operational visibility.
    """

    def __init__(self, source_id: str) -> None:
        self.source_id = source_id

    @abstractmethod
    def train(self, records: list[TrainingRecord]) -> None:
        """Train or replace the model from a full set of labelled records.

        Called once on bootstrap. Replaces any existing persisted model.

        Args:
            records: Labelled training records. Must be non-empty.
        """

    @abstractmethod
    def retrain(self, records: list[TrainingRecord]) -> None:
        """Retrain the model incorporating new correction records.

        Called on-demand after corrections accumulate. Implementations
        must enforce GRASP_CLASSIFIER_MIN_CORRECTIONS before accepting.

        Args:
            records: Combined bootstrap + correction records.
        """

    @abstractmethod
    def predict(self, feat: FieldFeatures) -> Optional[ClassifierResult]:
        """Classify a single field.

        Returns None on cold start (no trained model). The caller
        must fall back to heuristic classification when None is returned.

        Args:
            feat: Feature vector for the field to classify.

        Returns:
            ClassifierResult if a model is loaded, None otherwise.
        """

    @abstractmethod
    def persist(self) -> None:
        """Persist the current model to GRASP_MODEL_BASE_PATH.

        File path: {model_base_path}/classifier_{source_id}.joblib
        No-op if no model is loaded.
        """

    @abstractmethod
    def load(self) -> bool:
        """Load a persisted model from GRASP_MODEL_BASE_PATH.

        Returns:
            True if a model was found and loaded, False on cold start.
        """

    @abstractmethod
    def stats(self) -> dict[str, object]:
        """Return operational statistics for health and API endpoints.

        Required keys:
            source_id        (str)
            model_status     (str)  'trained' | 'bootstrapping' | 'cold_start'
            training_samples (int)
            correction_count (int)
            feature_dim      (int)
            confidence_threshold (float)
            min_corrections  (int)
        """