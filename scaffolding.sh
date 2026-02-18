#!/bin/bash
# GRASP Project Scaffolding
# Run from ~/GRASP (your git repo root)
# Creates directory structure, initial files, and Docker setup

set -e
cd ~/GRASP

# ============================================================
# Directory Structure
# ============================================================

# Core application package
mkdir -p src/grasp/{discovery,adapters,graph,intelligence,api/routers,api/models,models,utils}

# Docker
mkdir -p docker/grasp

# Configuration
mkdir -p config

# Tests mirroring source structure
mkdir -p tests/{discovery,adapters,graph,intelligence,api}

# Docs (already exists from architecture docs)
mkdir -p docs/{architecture,development}

# ============================================================
# Python Package Init Files
# ============================================================

# Root package
cat > src/grasp/__init__.py << 'EOF'
"""
GRASP - Graph-based Reconnaissance, Analysis, and Security Posture

A standalone, plug-and-play security intelligence sidecar that
transforms raw security telemetry into a living graph of relationships.
"""

__version__ = "0.1.0"
EOF

# Sub-packages
for pkg in discovery adapters graph intelligence models utils; do
    touch src/grasp/${pkg}/__init__.py
done

touch src/grasp/api/__init__.py
touch src/grasp/api/routers/__init__.py
touch src/grasp/api/models/__init__.py

# ============================================================
# Application Entrypoint
# ============================================================

cat > src/grasp/main.py << 'EOF'
"""GRASP application entrypoint."""

import logging
from grasp.config import settings

logger = logging.getLogger(__name__)


def main():
    """Start the GRASP engine."""
    logger.info(
        "GRASP v%s starting - Graph-based Reconnaissance, Analysis, and Security Posture",
        settings.version,
    )
    logger.info("Log level: %s", settings.log_level)
    logger.info("API port: %s", settings.api_port)
    logger.info("Graph DB: %s", settings.graph_db_uri)


if __name__ == "__main__":
    main()
EOF

# ============================================================
# Configuration (Environment Variable Management)
# ============================================================

cat > src/grasp/config.py << 'EOF'
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
EOF

# ============================================================
# Structured Logging
# ============================================================

cat > src/grasp/utils/logging.py << 'EOF'
"""Structured JSON logging for all GRASP components."""

import logging
import json
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Emit logs as structured JSON."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def configure_logging(level="info"):
    """Configure structured logging for the GRASP engine."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger("grasp")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(handler)
    root.propagate = False
    return root
EOF

# ============================================================
# Requirements
# ============================================================

cat > requirements.txt << 'EOF'
# GRASP Dependencies
# Core API
fastapi==0.115.6
uvicorn[standard]==0.34.0

# Graph Database
neo4j==5.27.0

# ML / Discovery Engine
scikit-learn==1.6.1
hdbscan==0.8.40
scipy==1.15.1
numpy==2.2.2
pandas==2.2.3
networkx==3.4.2

# Search Index Client
elasticsearch[async]==8.17.0

# Data Validation
pydantic==2.10.5
pydantic-settings==2.7.1

# Utilities
python-dotenv==1.0.1
EOF

# ============================================================
# Dockerfile (Multi-stage, hardened)
# ============================================================

cat > docker/grasp/Dockerfile << 'DOCKERFILE'
# GRASP Engine - Multi-stage Production Build
# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Production image
FROM python:3.12-slim AS production

# Create non-root user
RUN groupadd -r grasp && useradd -r -g grasp -d /app -s /sbin/nologin grasp

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Application code
WORKDIR /app
COPY src/ ./src/

# Ownership
RUN chown -R grasp:grasp /app

USER grasp

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "grasp.main"]
DOCKERFILE

# ============================================================
# docker-compose.yml
# ============================================================

cat > docker-compose.yml << 'COMPOSEFILE'
# GRASP - Graph-based Reconnaissance, Analysis, and Security Posture
# Single-command deployment: docker compose up -d

services:
  grasp-engine:
    build:
      context: .
      dockerfile: docker/grasp/Dockerfile
    container_name: grasp-engine
    env_file: .env
    volumes:
      # Development: mount source for live editing
      - ./src:/app/src:ro
    networks:
      - grasp-net
    depends_on:
      grasp-neo4j:
        condition: service_healthy
    restart: unless-stopped

  grasp-neo4j:
    image: neo4j:5.15-community
    container_name: grasp-neo4j
    environment:
      - NEO4J_AUTH=${GRASP_GRAPH_DB_USER}/${GRASP_GRAPH_DB_PASSWORD}
      - NEO4J_PLUGINS=["apoc"]
      - NEO4J_apoc_export_file_enabled=true
      - NEO4J_apoc_import_file_enabled=true
      - NEO4J_apoc_import_file_use__neo4j__config=true
    volumes:
      - grasp-neo4j-data:/data
    ports:
      - "7474:7474"
      - "7687:7687"
    networks:
      - grasp-net
    healthcheck:
      test: ["CMD", "neo4j", "status"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  grasp-neo4j-data:
    driver: local

networks:
  grasp-net:
    driver: bridge
COMPOSEFILE

# ============================================================
# Environment File
# ============================================================

cat > .env << 'ENVFILE'
# ============================================================
# GRASP Configuration - All settings via environment variables
# ============================================================

# Core
GRASP_LOG_LEVEL=info
GRASP_API_PORT=8443

# Graph Database
GRASP_GRAPH_DB_URI=bolt://grasp-neo4j:7687
GRASP_GRAPH_DB_USER=neo4j
GRASP_GRAPH_DB_PASSWORD=changeme_grasp_2026

# Graph Lifecycle
GRASP_GRAPH_HOT_RETENTION_HOURS=24
GRASP_GRAPH_WARM_RETENTION_DAYS=30

# Intelligence Engine
GRASP_BASELINE_MIN_EVENTS=10000
GRASP_ANOMALY_THRESHOLD=0.85
GRASP_ATTACK_CHAIN_MIN_CONFIDENCE=0.70
ENVFILE

# ============================================================
# .gitignore
# ============================================================

cat > .gitignore << 'GITIGNORE'
# Environment and secrets
.env

# Python
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
*.egg
.eggs/

# Virtual environments
venv/
.venv/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Docker volumes
data/

# ML model artifacts
models/*.pkl
models/*.joblib

# Logs
*.log

# Test
.pytest_cache/
.coverage
htmlcov/
GITIGNORE

# ============================================================
# .env.example (safe to commit - no real secrets)
# ============================================================

cat > .env.example << 'ENVEXAMPLE'
# ============================================================
# GRASP Configuration Template
# Copy to .env and update values before deployment
# ============================================================

# Core
GRASP_LOG_LEVEL=info
GRASP_API_PORT=8443

# Graph Database
GRASP_GRAPH_DB_URI=bolt://grasp-neo4j:7687
GRASP_GRAPH_DB_USER=neo4j
GRASP_GRAPH_DB_PASSWORD=<your_secure_password>

# Graph Lifecycle
GRASP_GRAPH_HOT_RETENTION_HOURS=24
GRASP_GRAPH_WARM_RETENTION_DAYS=30

# Intelligence Engine
GRASP_BASELINE_MIN_EVENTS=10000
GRASP_ANOMALY_THRESHOLD=0.85
GRASP_ATTACK_CHAIN_MIN_CONFIDENCE=0.70

# Sources (add as needed)
# GRASP_SOURCE_1_TYPE=search_index
# GRASP_SOURCE_1_ENDPOINT=https://<host>:<port>
# GRASP_SOURCE_1_AUTH_USER=<user>
# GRASP_SOURCE_1_AUTH_PASSWORD=<secret>
# GRASP_SOURCE_1_TLS_VERIFY=false

# GRASP_SOURCE_2_TYPE=file
# GRASP_SOURCE_2_PATH=/data/events/events.json
# GRASP_SOURCE_2_FORMAT=jsonl

# GRASP_SOURCE_3_TYPE=syslog
# GRASP_SOURCE_3_PORT=5514
# GRASP_SOURCE_3_PROTOCOL=udp
ENVEXAMPLE

# ============================================================
# Test placeholder
# ============================================================

cat > tests/__init__.py << 'EOF'
EOF

cat > tests/test_config.py << 'EOF'
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
EOF

# ============================================================
# Summary
# ============================================================

echo ""
echo "=== GRASP Scaffolding Complete ==="
echo ""
echo "Project structure:"
find . -type f | grep -v '.git/' | grep -v '__pycache__' | sort
echo ""
echo "Next steps:"
echo "  1. Update .env with your Neo4j password"
echo "  2. docker compose build"
echo "  3. docker compose up -d"
echo "  4. docker compose logs grasp-engine"
echo ""