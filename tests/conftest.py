"""Pytest configuration for GRASP test suite."""

import os

# Ensure test environment variables are set before any imports
os.environ.setdefault("GRASP_GRAPH_DB_PASSWORD", "test")
os.environ.setdefault("GRASP_LOG_LEVEL", "warning")