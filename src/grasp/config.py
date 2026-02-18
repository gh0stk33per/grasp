"""GRASP configuration via environment variables. Zero hardcoding."""

import os


class Settings:
    """All configuration sourced from environment. No defaults that matter."""

    def __init__(self):
        # Core
        self.version = "0.1.0"
        self.log_level = os.environ.get("GRASP_LOG_LEVEL", "info")
        self.api_port = int(os.environ.get("GRASP_API_PORT", "8443"))

        # Graph Database
        self.graph_db_uri = os.environ.get("GRASP_GRAPH_DB_URI", "bolt://grasp-neo4j:7687")
        self.graph_db_user = os.environ.get("GRASP_GRAPH_DB_USER", "neo4j")
        self.graph_db_password = os.environ.get("GRASP_GRAPH_DB_PASSWORD", "")

        # Graph Lifecycle
        self.graph_hot_retention_hours = int(
            os.environ.get("GRASP_GRAPH_HOT_RETENTION_HOURS", "24")
        )
        self.graph_warm_retention_days = int(
            os.environ.get("GRASP_GRAPH_WARM_RETENTION_DAYS", "30")
        )

        # Intelligence Engine
        self.baseline_min_events = int(
            os.environ.get("GRASP_BASELINE_MIN_EVENTS", "10000")
        )
        self.anomaly_threshold = float(
            os.environ.get("GRASP_ANOMALY_THRESHOLD", "0.85")
        )
        self.attack_chain_min_confidence = float(
            os.environ.get("GRASP_ATTACK_CHAIN_MIN_CONFIDENCE", "0.70")
        )


settings = Settings()
