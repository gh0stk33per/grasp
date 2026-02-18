# GRASP - Session 001 Summary

**Date**: 2026-02-18
**Duration**: Extended session (architecture + scaffolding)
**Status**: Complete

---

## Session Narrative

This session began as an open brainstorm on next-generation SOC capabilities and evolved into the birth of GRASP -- a standalone, source-agnostic security intelligence sidecar.

The conversation progressed through several key inflection points:

1. **Initial brainstorm** on autonomous defense engines, human-AI command modes, threat intelligence engines, and continuous adversarial simulation
2. **Honest assessment** of what's achievable vs aspirational -- grounded the vision in practical architecture
3. **Recognition** that the conventional Wazuh/Suricata/Elasticsearch stack isn't boring because of the tools, but because of how everyone uses them
4. **Key insight**: Graph-based correlation as a first-class architectural decision is genuinely novel in the open-source SOC space
5. **Validation research** confirmed BloodHound, GraphKer, and Cartography use Neo4j in security, but none as a real-time operational correlation engine inside a SOC pipeline
6. **Decision** to build GRASP as an independent sidecar, not a SOCOS module -- maximizing portability and adoption
7. **Darktrace comparison** revealed philosophical alignment (unsupervised self-learning AI) but fundamental architectural differences (graph-first, sidecar, open-source, native signal preservation)
8. **Critical architectural decision**: Discovery engine and ML engine are the same component -- ML-native from birth, not bolted on later
9. **Scaffolding deployed**: Project structure, Docker containers, FastAPI with auto-reload, Neo4j with APOC, structured logging -- all operational

---

## Key Architectural Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Project identity | Standalone sidecar | Maximizes portability; SOCOS is one consumer, not the parent |
| Naming | GRASP (Graph-based Reconnaissance, Analysis, and Security Posture) | Captures the "grasping full picture from fragments" concept |
| Source references | All vendor/product references removed from architecture docs | Prevents design bias toward any specific tool |
| Adapter philosophy | Transport + Discovery only, no transformation | Native signal preservation; normalization destroys ML features |
| Field classification | Unsupervised ML (HDBSCAN clustering), not regex ladders | Scales across unknown source types without source-specific rules |
| API framework | FastAPI REST first, Strawberry GraphQL in Phase 2 | Avoids premature complexity; REST sufficient for initial interface |
| Unikernels | Deferred | Python ecosystem incompatibility; Docker provides sufficient isolation |
| Development runtime | Docker containers, not VM system Python | Same environment in dev and production from day one |
| Auto-reload | Uvicorn --reload with source volume mount | Edit on VM, container picks up changes immediately |
| Graph database | Neo4j 5.15-community with APOC plugins | Cypher maturity, graph algorithms, proven at scale |
| Core language | Python 3.12 | ML ecosystem, Neo4j driver, FastAPI compatibility |

---

## Documents Created

### Architecture Documents
- **docs/architecture/Vision_Arch_Doc.md** -- GRASP Vision Architecture Document v1.0 (what GRASP is and why)
- **docs/development/Tech_Approach.md** -- GRASP Technical Approach Document v1.0 (how we build it)

### Project Files
- **docker/grasp/Dockerfile** -- Multi-stage production build (python:3.12-slim, non-root user)
- **docker-compose.yml** -- GRASP engine + Neo4j with health checks
- **requirements.txt** -- All Python dependencies pinned
- **src/grasp/__init__.py** -- Package definition with version
- **src/grasp/main.py** -- FastAPI application with structured startup logging
- **src/grasp/config.py** -- Environment variable management (zero hardcode)
- **src/grasp/utils/logging.py** -- JSON structured logging
- **scaffolding.sh** -- One-shot project structure generator
- **.env** -- Configuration (gitignored)
- **.env.example** -- Template (committed)
- **.gitignore** -- Standard Python/Docker/IDE ignores
- **tests/test_config.py** -- Initial configuration test

---

## Infrastructure State

### Running Containers
```
grasp-engine    (python:3.12-slim / FastAPI + uvicorn --reload)
grasp-neo4j     (neo4j:5.15-community + APOC)
```

### Network
```
grasp-net (bridge)
  grasp-engine  -> port 8443 exposed
  grasp-neo4j   -> ports 7474, 7687 exposed
```

### Validated Endpoints
```
GET http://localhost:8443/health  -> {"status":"ok","version":"0.1.0"}
Neo4j Browser: http://localhost:7474
Neo4j Bolt: bolt://localhost:7687
```

### Git
```
Remote: github.com/gh0stk33per/grasp (private)
Auth: PAT (classic) with credential.helper store
Branch: main
Last commit: "Scaffolding: project structure, Docker, FastAPI, Neo4j, structured logging"
```

---

## Next Session Objectives

### Primary Goal: Discovery Engine + Adapter Foundation (Phase 1 + Phase 2)

Build the adapter abstraction and discovery engine together so GRASP can connect to a live data source, sample events, extract field features, cluster fields, and produce a Source Profile -- validated end-to-end against real security telemetry.

**Deliverables:**

1. **Source Profile data model** (`src/grasp/models/source_profile.py`)
   - Pydantic model defining the Source Profile structure
   - Field inventory, type classifications, confidence scores
   - Co-occurrence relationship maps
   - Profile versioning and revision tracking

2. **Abstract adapter interface** (`src/grasp/adapters/base.py`)
   - Common interface: connect, sample, stream, health, disconnect
   - Async-native design
   - Transport-agnostic contract that all adapters implement

3. **Index Poller adapter** (`src/grasp/adapters/index_poller.py`)
   - Connect to Elasticsearch-compatible search index API
   - Discover available indices via API introspection
   - Sample N events using search queries
   - Return raw JSON events with no transformation
   - TLS and authentication support

4. **JSON event flattener** (`src/grasp/discovery/` utility)
   - Takes arbitrarily nested JSON and produces flat field paths with value arrays
   - Example: `{"data": {"srcip": "1.2.3.4"}}` becomes `{"data.srcip": ["1.2.3.4"]}`
   - Handles arrays, nested objects, null values gracefully

5. **Field feature extractor** (`src/grasp/discovery/features.py`)
   - Takes a list of raw values from a single JSON field
   - Computes feature vector: string length stats, character distribution, entropy, format consistency, separator analysis, cardinality, numeric properties
   - Pure computation -- no ML, no heuristics
   - Unit tests validating correct features for known value types (IPs, timestamps, hashes, hostnames)

6. **Field clusterer** (`src/grasp/discovery/clustering.py`)
   - Takes feature vectors from all fields across a sample batch
   - Runs HDBSCAN clustering
   - Outputs cluster assignments with confidence scores
   - Cluster labeling with semantic meaning where identifiable
   - Unknown clusters tagged as discovered-type-N, not discarded

7. **Co-occurrence analyzer** (`src/grasp/discovery/relationships.py`)
   - Mutual information between entity-typed fields within events
   - Identifies candidate relationships from co-occurrence patterns

8. **Source Profile assembler** (`src/grasp/discovery/profile.py`)
   - Combines all outputs into a versioned Source Profile
   - Persists and supports incremental updates

### End-to-End Validation Target

9. **Live validation pipeline:**
   - Index Poller connects to live Elasticsearch instance (test bed)
   - Samples 500 events from security alert index
   - Discovery engine processes sample through full pipeline
   - Source Profile produced with entity types and relationships identified
   - Profile correctly distinguishes IPs, timestamps, hashes, hostnames, and categories

### Secondary Goal: File Watcher Adapter (if time permits)

10. **File Watcher adapter** (`src/grasp/adapters/file_watcher.py`)
    - Connect to JSON-per-line log file on disk
    - Sample first N lines
    - Validate discovery engine produces comparable Source Profile from a different source type

### Success Criteria for Next Session

- Abstract adapter interface defined and Index Poller implements it
- Index Poller successfully connects to live Elasticsearch and retrieves events
- Feature extractor correctly distinguishes entity types based on value features alone
- HDBSCAN clustering groups similar field types together
- Source Profile model is defined and can serialize/deserialize
- Full end-to-end pipeline: adapter connects -> samples -> discovery runs -> Source Profile produced
- All new code has corresponding unit tests
- Code committed and pushed to remote

---

## Open Questions for Next Session

1. **Sample size for discovery**: Architecture doc says 1000 events default. Is that enough for HDBSCAN to produce stable clusters? May need experimentation.
2. **Nested field handling**: How deep do we flatten? Security events can be deeply nested. Need a practical limit.
3. **Mixed-type fields**: Some fields contain different types across events (sometimes IP, sometimes hostname). How does the feature extractor handle this? The clustering should naturally handle it (noisy cluster), but we need to verify.
4. **Performance baseline**: How fast does feature extraction need to be for the bootstrap flow? If sampling 1000 events, extraction should complete in seconds, not minutes.
5. **Index discovery**: Should the Index Poller auto-detect which indices contain security data, or does the user specify the index pattern in .env? Trade-off between zero-config and precision.
6. **TLS verification**: Test bed uses self-signed certs. Adapter needs configurable TLS verification (GRASP_SOURCE_N_TLS_VERIFY).

---

*GRASP Session 001: From brainstorm to running containers in one session.*