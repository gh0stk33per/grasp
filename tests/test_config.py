"""Verify GRASP configuration loads from environment."""

import os


def test_settings_load():
    """Settings should initialize without error."""
    os.environ["GRASP_GRAPH_DB_PASSWORD"] = "test"
    from grasp.config import Settings
    s = Settings()
    assert s.version == "0.1.0"
    assert s.log_level == "info"
    assert s.anomaly_threshold == 0.85
