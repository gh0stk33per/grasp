"""GRASP configuration via environment variables. Zero hardcoding.

Source definitions are discovered dynamically from GRASP_SOURCE_N_*
environment variables. Adding a new source requires only adding
variables to .env -- no code changes.
"""

import os
import re
import logging

logger = logging.getLogger("grasp.config")


class SourceConfig:
    """Configuration for a single data source, parsed from environment."""

    def __init__(self, source_id: str, raw: dict[str, str]):
        self.source_id = source_id
        self.source_type = raw.get("type", "")
        self.endpoint = raw.get("endpoint", "")
        self.auth_user = raw.get("auth_user", "")
        self.auth_password = raw.get("auth_password", "")
        self.ca_cert = raw.get("ca_cert", "")
        self.tls_verify = raw.get("tls_verify", "true").lower() == "true"
        self.index_pattern = raw.get("index_pattern", "*")
        self.path = raw.get("path", "")
        self.format = raw.get("format", "jsonl")
        self.port = raw.get("port", "")
        self.protocol = raw.get("protocol", "udp")
        self.poll_interval = int(raw.get("poll_interval", "5"))
        self.batch_size = int(raw.get("batch_size", "500"))

    def to_adapter_config(self) -> dict[str, object]:
        """Convert to the dict format adapters expect."""
        return {
            "endpoint": self.endpoint,
            "auth_user": self.auth_user,
            "auth_password": self.auth_password,
            "ca_cert": self.ca_cert,
            "tls_verify": self.tls_verify,
            "index_pattern": self.index_pattern,
            "path": self.path,
            "format": self.format,
            "port": self.port,
            "protocol": self.protocol,
            "poll_interval": self.poll_interval,
            "batch_size": self.batch_size,
        }


class Settings:
    """All configuration sourced from environment. No defaults that matter."""

    def __init__(self):
        # Core
        self.version = "0.1.0"
        self.log_level = os.environ.get("GRASP_LOG_LEVEL", "info")
        self.api_port = int(os.environ.get("GRASP_API_PORT", "8443"))

        # Graph Database
        self.graph_db_uri = os.environ.get(
            "GRASP_GRAPH_DB_URI", "bolt://grasp-neo4j:7687"
        )
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

        # Discovery Engine
        self.discovery_min_field_values = int(
            os.environ.get("GRASP_DISCOVERY_MIN_FIELD_VALUES", "10")
        )
        self.discovery_sample_size = int(
            os.environ.get("GRASP_DISCOVERY_SAMPLE_SIZE", "1000")
        )

        # Sources (discovered dynamically)
        self.sources = self._discover_sources()

    def _discover_sources(self) -> list[SourceConfig]:
        """Discover source definitions from GRASP_SOURCE_N_* variables.

        Scans environment for numbered source patterns and builds
        SourceConfig objects. Sources must have at least a TYPE defined.
        """
        # Find all source numbers defined in environment
        source_numbers: set[str] = set()
        pattern = re.compile(r"^GRASP_SOURCE_(\d+)_(.+)$")

        for key in os.environ:
            match = pattern.match(key)
            if match:
                source_numbers.add(match.group(1))

        sources: list[SourceConfig] = []
        for num in sorted(source_numbers):
            prefix = f"GRASP_SOURCE_{num}_"
            raw: dict[str, str] = {}

            for key, val in os.environ.items():
                if key.startswith(prefix):
                    # Strip prefix and lowercase the suffix
                    param = key[len(prefix):].lower()
                    raw[param] = val

            if "type" not in raw:
                logger.warning(
                    "Source %s has no TYPE defined, skipping", num
                )
                continue

            source_id = f"source_{num}"
            sources.append(SourceConfig(source_id, raw))
            logger.info(
                "Discovered source [%s]: type=%s endpoint=%s",
                source_id, raw.get("type", ""), raw.get("endpoint", ""),
            )

        return sources


settings = Settings()