# GRASP - Graph-based Reconnaissance, Analysis, and Security Posture

## Vision Architecture Document v2.0

**Classification**: Internal - Architecture Vision
**Status**: Draft
**Date**: 2026-02-23
**Author**: Doc + Claude (Co-Architects)
**Supersedes**: Vision Architecture Document v1.0 (2026-02-17)

---

## Revision History

| Version | Date | Change Summary |
|---------|------|----------------|
| 1.0 | 2026-02-17 | Initial document. Security-focused framing. Single domain. |
| 2.0 | 2026-02-23 | Expanded to domain-agnostic Intelligent Data Attribution platform. Introduced Domain Pack architecture. Per-source model decision. UAV validated as second domain. Security reframed as first customer, not the product. |

---

## 1. Executive Summary

GRASP is a standalone, plug-and-play data intelligence sidecar that transforms raw structured telemetry from any source into a living graph of entities, relationships, and behavioral patterns -- enabling AI-driven anomaly detection, attribution, and situational awareness across any domain.

The core capability is **Intelligent Data Attribution**: given an unknown stream of structured data, GRASP autonomously answers what the things in that data are, what those things do to each other, what normal behavior looks like for this specific environment, what is anomalous, and what that anomaly means -- without being told what the data is, without a schema, without field names that carry semantic meaning, and without any source-specific configuration.

GRASP does not replace any component in an existing stack. It consumes standard outputs from systems already deployed, adds graph-based intelligence, and provides insights that flat, document-oriented processing fundamentally cannot deliver.

### 1.1 Design Philosophy

**Self-learning intelligence, open-source accessibility, sidecar portability.**

- Self-learning: Unsupervised models discover structure and learn behavioral baselines autonomously from the data itself
- Zero-configuration: Point GRASP at a data source, it figures out the rest
- Signal fidelity: Native event formats are preserved -- normalization destroys information the ML engine needs
- Graph-first: Relationships between entities are the primary analytical lens, not individual events
- Domain-agnostic: No assumption about what domain, industry, or vendor produced the telemetry
- Source-agnostic: Works with any structured data without source-specific customization
- Air-gap native: Designed to operate with zero external connectivity -- local data, local models, local intelligence

### 1.2 What GRASP Is NOT

- NOT a SIEM -- it has no log storage, no dashboards, no compliance reporting
- NOT a module within any other platform -- it is a fully independent project
- NOT dependent on any specific vendor, tool, or domain
- NOT a normalized event pipeline -- it deliberately avoids flattening data into common schemas
- NOT a replacement for any existing investment -- it makes everything already deployed smarter
- NOT cloud-dependent -- it runs fully air-gapped by design, not as an afterthought

---

## 2. Problem Statement

### 2.1 The Universal Data Attribution Problem

Every domain that produces operational telemetry runs some variation of the same pattern: collect data, store it, write queries or rules against known fields, generate alerts or reports. The tools differ across industries but the architectural approach is identical -- flat, document-oriented processing against a known schema.

This approach has two fundamental limitations.

**It cannot see relationships.** When a multi-stage event unfolds -- an attack chain, a mechanical failure cascade, a fraud sequence, an adversarial UAV maneuver -- a flat system sees N separate events at different severity levels, possibly in different data stores, possibly separated by time. A graph sees those events connected through the entities involved. The path is the detection.

**It requires prior knowledge.** Flat processing assumes you already know what your data means before you can ask questions of it. Schema definitions, field mappings, named queries -- all of it requires a human to have understood the data first. In practice this means new data sources take months to integrate, legacy data remains dark, and acquired systems stay siloed indefinitely.

GRASP inverts both limitations. It understands the data first, autonomously, then lets you ask questions.

### 2.2 Why This Has Not Been Solved in Open Source

Graph databases are used in specific domains today, but narrowly and statically:

- **BloodHound**: Graph-based Active Directory attack path analysis -- offline, single-domain, pentesting-focused
- **GraphKer**: Graph-based MITRE CVE/CWE/CAPEC knowledge graphs -- static reference data, not operational
- **Cartography**: Graph-based cloud infrastructure auditing -- inventory snapshots, not real-time correlation

No open-source project uses a graph database as a real-time operational intelligence engine that autonomously discovers schema, builds behavioral baselines, and detects anomalies -- across any domain, without source-specific configuration.

### 2.3 The Commercial Benchmark

The commercial market validates the core philosophy. Products valued in the billions use unsupervised self-learning AI that models an environment without signatures or rules. However, these commercial offerings are:

- Proprietary and closed-source
- Domain-specific -- built for one vertical and not transferable
- Monolithic -- requiring their own sensors and data collection infrastructure
- Expensive -- six-figure enterprise deployments
- Not graph-native -- typically using Bayesian models and clustering, with graph techniques added as supplementary analysis
- Cloud-dependent -- cannot operate in air-gapped or contested environments

GRASP brings this class of intelligence to the open-source ecosystem with a fundamentally different architecture: graph-first, domain-agnostic, sidecar deployment, native signal preservation, air-gap native, and zero vendor lock-in.

### 2.4 Validated Domains

GRASP's architecture is validated against two structurally distinct domains:

**Domain 1 -- Security Operations (First Customer)**
Host-based security telemetry, network flow data, endpoint detection alerts. Rich, complex, varied event schemas. Validated through 15 clustering runs against live Wazuh/Elasticsearch data. The security domain motivated the original architecture and provides the ongoing operational test bed.

**Domain 2 -- UAV / Autonomous Systems Telemetry (Second Customer)**
ArduPilot DataFlash binary logs from Pixhawk flight controllers. 183 message types, 1,574 fields per log, multi-stream sensor fusion across IMU, GPS, barometer, RC inputs, motor outputs, vibration, and Extended Kalman Filter state. Validated through binary investigation of 665,095 records across two ground sessions from the same airframe. The UAV domain proves source-agnosticism -- the same discovery engine that classifies security telemetry correctly identifies sensor axes, GPS coordinates, control signals, and flight mode enumerations from raw binary data with no prior schema knowledge.

The structural identity between these two domains is the proof of concept for domain-agnostic Intelligent Data Attribution:

| Dimension | Security | UAV |
|-----------|----------|-----|
| Data source | Alert telemetry | Sensor telemetry |
| Entity types | IPs, hashes, users, hosts | Airframes, waypoints, RF sources |
| Relationships | Attack paths, lateral movement | Sensor correlations, control chains |
| Baseline | Normal network behaviour | Normal flight envelope |
| Anomaly | Intrusion, exfiltration | Spoofing, degradation, adversarial manoeuvre |
| Air-gap | Valuable | Mandatory in contested ops |
| Schema knowledge | Partial | Often proprietary or undocumented |

---

## 3. Architecture Overview

### 3.1 Core Principles

1. **API-First**: Every capability exposed through well-documented APIs
2. **Single Deployable**: One container alongside graph database, deployed via docker-compose
3. **Zero-Hardcode**: All configuration through environment variables
4. **Thin Adapters**: Transport and discovery only -- no transformation
5. **Native Signal Fidelity**: Raw events preserved; relationships extracted, not schemas enforced
6. **Unsupervised Discovery**: Structure, entities, and relationships learned from data, not configured
7. **Incremental Intelligence**: Value from minute one (topology), improving over time (behavioural ML)
8. **Domain-Agnostic Core**: No assumption about what domain, product, or vendor produced the telemetry
9. **Per-Source Learning**: Classification models and behavioural baselines are scoped to each source -- no cross-source contamination
10. **Air-Gap Native**: Zero external connectivity required -- all learning happens locally from local data

### 3.2 Three-Layer Product Architecture

GRASP is structured in three layers. The core never changes. Domain Packs are the extension surface. Adapters are the connectivity surface.

```
+------------------------------------------------------------------+
|  LAYER 3: DOMAIN PACKS                                           |
|                                                                  |
|  +------------------+  +------------------+  +--------------+   |
|  | Security Pack    |  | UAV Pack         |  | Custom Pack  |   |
|  | - TypeHints:     |  | - TypeHints:     |  | (extensible) |   |
|  |   ipv4, hash,    |  |   gps_coord,     |  |              |   |
|  |   fqdn, sid ...  |  |   rf_freq,       |  |              |   |
|  | - Synthetic      |  |   pwm_signal ... |  |              |   |
|  |   training data  |  | - Synthetic      |  |              |   |
|  | - Domain vocab   |  |   training data  |  |              |   |
|  +------------------+  +------------------+  +--------------+   |
+------------------------------------------------------------------+
|  LAYER 2: GRASP CORE (domain-blind)                              |
|                                                                  |
|  Discovery Engine  ->  Graph Engine  ->  Intelligence Engine     |
|  - Feature extract     - Entity nodes    - Layer 1: Structural   |
|  - HDBSCAN cluster     - Relationships   - Layer 2: Behavioural  |
|  - Per-source model    - Lifecycle mgmt  - Layer 3: Semantic     |
|  - Source Profile      - Entity resolve  - Feedback loop         |
+------------------------------------------------------------------+
|  LAYER 1: ADAPTER LAYER                                          |
|                                                                  |
|  Index Poller | File Watcher | DataFlash | Syslog | Kafka | ...  |
|  (Transport + Discovery -- no transformation)                    |
+------------------------------------------------------------------+
```

### 3.3 High-Level Data Flow

```
+-------------------------------------------------------------------+
|                     ANY DATA SOURCE                               |
|  Security telemetry | UAV sensors | Industrial historian | ...    |
+-------+-------------------+-------------------+-------------------+
        |                   |                   |
        v                   v                   v
+-------+-------+   +-------+-------+   +-------+-------+
|   Adapter:    |   |   Adapter:    |   |   Adapter:    |
| Index Poller  |   | DataFlash     |   | File Watcher  |
|  (Transport   |   |  (Transport   |   |  (Transport   |
|  + Discovery) |   |  + Discovery) |   |  + Discovery) |
+-------+-------+   +-------+-------+   +-------+-------+
        |                   |                   |
        +-------------------+-------------------+
                            |
                   +--------v--------+
                   |  Source Profile  |
                   |    Registry     |
                   | (per-source,    |
                   |  versioned)     |
                   +--------+--------+
                            |
                   +--------v--------+
                   |  Discovery      |
                   |  Engine         |
                   | (unsupervised   |
                   |  per-source     |
                   |  ML)            |
                   +--------+--------+
                            |
                   +--------v--------+
                   |  Graph Engine   |
                   |  (Relationship  |
                   |   mapping and   |
                   |   lifecycle)    |
                   +--------+--------+
                            |
                   +--------v--------+
                   |  Graph Database |
                   | (Living Graph)  |
                   +--------+--------+
                            |
              +-------------+-------------+
              |                           |
     +--------v--------+        +--------v--------+
     | Intelligence     |        | API Layer       |
     | Engine           |        | (FastAPI)       |
     | - Structural     |        | - REST (Day 1)  |
     |   analysis       |        | - GraphQL       |
     | - Behavioural    |        |   (Phase 2)     |
     |   baselining     |        | - WebSocket     |
     | - Anomaly        |        |   (Live feed)   |
     |   detection      |        +-----------------+
     | - Semantic       |
     |   enrichment     |
     +------------------+
```

### 3.4 Integration Model

```
+-------------------------------------------+
|      Any Operational Stack                 |
|                                           |
|  +----------+  +-----------+  +--------+  |
|  | Security |  | Autopilot |  | SCADA  |  |
|  | Platform |  | / FC      |  | / ICS  |  |
|  +----+-----+  +-----+-----+  +---+----+  |
|       |              |             |       |
|       v              v             v       |
|  +----+------------------------------+    |
|  |   Storage / Transport Layer        |    |
|  |   (Index, File, Binary, Stream)    |    |
|  +----+------------------------------+    |
|       |                                   |
+-------+-----------------------------------+
        |
        | Standard outputs (no modification required)
        |
+-------v-------------------------------------------+
|       GRASP (Sidecar)                              |
|       Discovers, correlates, attributes, learns    |
|  +----------------+  +------------------------+   |
|  | GRASP Engine   |  | Graph Database         |   |
|  +----------------+  +------------------------+   |
+---------------------------------------------------+

GRASP operates independently of any specific stack or domain.
It consumes standard outputs without modification.
```

---

## 4. Intelligent Data Attribution

### 4.1 The Core Capability

Intelligent Data Attribution is the process by which GRASP autonomously answers five questions about any structured data source, without prior knowledge of what the data represents:

1. **What are the things?** -- Entity discovery: which fields carry identity-bearing values that should become graph nodes
2. **What do they do to each other?** -- Relationship discovery: which entities co-occur, with what frequency, implying what connections
3. **What is normal?** -- Behavioural baseline: what does the statistical distribution of entity behaviour look like over time for this specific source
4. **What is anomalous?** -- Deviation detection: which new events deviate from the established baseline and by how much
5. **What does the anomaly mean?** -- Semantic enrichment: given the graph structure, the domain pack vocabulary, and accumulated feedback, what is the likely interpretation

### 4.2 Per-Source Model Architecture

A foundational decision of v2.0: **no classification model crosses source boundaries.**

Every Source Profile maintains its own:
- Feature-based HDBSCAN clustering (unsupervised, from the data itself)
- Local RandomForest classifier (trained from corrections on this source only)
- Behavioural baseline (statistical profiles scoped to this source's entities)
- Corrections store (`corrections_{source_id}.jsonl`)
- Persisted model (`classifier_{source_id}.joblib`)

This design has four consequences:

**Air-gap compatibility**: A new source in an isolated environment starts with HDBSCAN heuristics and builds its own model from local corrections. No pre-trained model required. No external connectivity required.

**No cross-contamination**: A model trained on security telemetry does not bias classification of UAV sensor data. Each source is epistemically isolated.

**Honest uncertainty**: On first contact with a new source type, the system produces high-uncertainty classifications and flags them for review. This is correct behaviour -- it surfaces what is not yet known rather than confidently guessing.

**Community transfer (optional, future)**: When deployments share the same source type, corrections can be federated without sharing raw data. This is an opt-in network effect, not a hard dependency.

### 4.3 Field Classification Model

Fields are classified by their statistical fingerprint across six source-agnostic roles:

| Class | Role | Basis |
|-------|------|-------|
| ENTITY | Graph node candidate | High cardinality, structured format, identity-bearing values |
| TEMPORAL | Event ordering | Monotonically increasing, timestamp-pattern values |
| METRIC | Numeric measurement | Continuous numeric, bounded range, physical meaning |
| ENUM | Low-cardinality category | Small unique set, repeating discrete values |
| TEXT | Long descriptive content | High length variance, natural language patterns |
| UNKNOWN | Unclassifiable | Does not fit statistical profile of any class |

Classification is based on the 27-dimensional feature vector computed from field values -- character distributions, entropy, cardinality, separator patterns, length statistics, numeric properties. Field names are never used in classification. This is what makes the system domain-agnostic.

TypeHints are optional format annotations applied after classification, sourced from the Domain Pack:

- Security Pack hints: `ipv4`, `ipv6`, `mac`, `hash_md5`, `hash_sha1`, `hash_sha256`, `uuid`, `fqdn`, `url`, `path`, `sid`
- UAV Pack hints: `gps_coord`, `pwm_signal`, `rf_frequency`, `euler_angle`, `quaternion`, `unix_time_us`
- Hints are extensible -- new formats are additions, not changes to classification logic

---

## 5. Adapter Layer

### 5.1 Purpose

Adapters solve exactly two problems: how to connect to a data source (transport contract) and how to deliver raw events to the discovery engine (discovery contract). They do NOT transform, normalize, or enrich data.

### 5.2 Transport Contract

Each transport type implements a common interface:

- **Connect**: Establish connection using provided endpoint and credentials
- **Sample**: Retrieve N events for discovery analysis
- **Stream**: Continuously deliver new events to the engine
- **Health**: Report connection status and throughput metrics

Transport types supported at launch:

| Type | Mechanism | Applicable Sources |
|------|-----------|-------------------|
| Index Poller | Search index scroll/search-after API | Any search-engine-indexed data |
| File Watcher | Filesystem tail on structured log files | Any JSON-per-line or structured log output |
| DataFlash Reader | ArduPilot binary log parser | Pixhawk / ArduPilot flight controller logs |
| Syslog Listener | UDP/TCP syslog receiver | Any network device, firewall, or appliance |

Future transport types:

| Type | Mechanism | Applicable Sources |
|------|-----------|-------------------|
| Message Queue Consumer | Topic/queue subscription | High-volume streaming pipelines (Kafka, NATS) |
| REST Poller | Periodic API polling | Any REST-based event or telemetry API |
| Webhook Receiver | HTTP POST listener | Alert forwarding, automation platforms |
| OPC-UA Client | Industrial protocol | SCADA historians, industrial sensors |

### 5.3 Discovery Contract

When an adapter connects and samples data, the discovery engine analyzes the raw events to produce a Source Profile. Discovery is performed through value-based feature analysis, not field name interpretation.

### 5.4 What Adapters Explicitly Do NOT Do

- No field renaming or mapping
- No schema enforcement
- No data type coercion
- No enrichment or augmentation
- No filtering or deduplication
- No normalization to a common event format

---

## 6. Graph Engine

### 6.1 Purpose

The graph engine takes raw events and Source Profiles and builds a living graph in the graph database. It is responsible for entity resolution, relationship creation, and graph lifecycle management.

### 6.2 Dynamic Schema

GRASP builds its schema organically from what the discovery engine finds. There are no predefined node labels or relationship types.

**Node Creation Logic:**

For each event, the graph engine examines the Source Profile to identify ENTITY-class fields. Each entity value becomes a node (or merges with an existing node). Nodes carry the entity value as primary identifier, first-seen and last-seen timestamps, source attribution, the full raw event payload, and discovery confidence score.

**Relationship Creation Logic:**

Co-occurring ENTITY fields within the same event produce edges. Relationships carry the timestamp of the establishing event, event count (incremented on repeated observation), source attribution, and the raw event payload.

**Cross-domain relationship examples:**

| Domain | Entity A | Entity B | Relationship |
|--------|----------|----------|--------------|
| Security | Source IP | Destination IP | COMMUNICATES_WITH |
| Security | Identity | Asset | AUTHENTICATED_TO |
| Security | Hash | Filename | OBSERVED_ON |
| UAV | IMU axis X | IMU axis Y | CO_VARIES_WITH |
| UAV | Motor output | Vibration | DRIVES |
| UAV | GPS position | Barometric altitude | CROSS_VALIDATES |

### 6.3 Entity Resolution

The same real-world entity may appear differently across sources. The graph engine merges nodes based on entity value matching -- this is why entity extraction is value-based, not field-name-based. Advanced entity resolution across sources is a Phase 2 intelligence problem.

### 6.4 Graph Lifecycle Management

- **Hot tier**: Last 24 hours -- full detail, all relationships, all event payloads
- **Warm tier**: 1-30 days -- aggregated relationships, entity nodes retained
- **Cold tier**: 30+ days -- entity nodes only, statistical summaries
- **Pruning**: Configurable retention policies per tier

---

## 7. Intelligence Engine

### 7.1 Layered Intelligence Model

The intelligence engine operates in three layers, each building on the previous. All three layers are domain-agnostic -- the same algorithms that detect lateral movement in a security graph detect anomalous sensor correlation in a UAV graph.

### 7.2 Layer 1: Structural Analysis (Immediate Value)

Available within minutes of first data ingestion.

- **PageRank**: Identify the most connected/critical nodes
- **Community Detection**: Find clusters of tightly connected entities
- **Shortest Path**: Calculate paths between any two entities
- **Degree Centrality**: Identify nodes with unusual connection counts

### 7.3 Layer 2: Behavioural Baselining (Hours to Days)

Available after sufficient data accumulation.

- **Temporal Pattern Learning**: Normal behaviour at different times
- **Relationship Frequency Baselining**: Normal communication/interaction rates between entity pairs
- **Graph Topology Stability**: Structural change detection
- **Entity Behavioural Profiles**: Per-entity fingerprints scoped to their source profile

### 7.4 Layer 3: Semantic Enrichment (Evolving)

AI-assisted interpretation loaded from the active Domain Pack:

- Pattern matching against domain-specific frameworks (ATT&CK for security, flight envelope models for UAV)
- Confidence-weighted recommendations
- Human feedback integration -- analyst corrections improve future outputs

### 7.5 Feedback Loop

- Analyst approves, rejects, or modifies intelligence outputs
- Decisions feed back into the per-source classifier and intelligence models
- Feedback is stored in source-scoped JSONL files, never shared across sources without explicit consent
- This is the Human-AI Command Mode -- continuous bidirectional trust calibration

---

## 8. API Layer

### 8.1 Technology Choice

- **Phase 1**: FastAPI (Python) -- REST endpoints with automatic OpenAPI documentation
- **Phase 2**: Strawberry GraphQL added alongside REST for flexible graph queries
- **Phase 3**: WebSocket support for real-time anomaly and intelligence feeds

### 8.2 API Domains

**Source Management**: Register sources, view Source Profiles, monitor adapter health, submit corrections

**Graph Intelligence**: Query entities and relationships, request path analysis, retrieve anomaly scores, get structural analysis

**Domain Packs**: List available packs, activate/deactivate packs, view active TypeHints per source

**System Operations**: Health and readiness, configuration management, graph lifecycle status, model health

---

## 9. Deployment Architecture

### 9.1 Production Deployment

```
docker-compose.yml
+--------------------------------------------------+
|                                                  |
|  +--------------------+  +--------------------+  |
|  |    GRASP Engine    |  |   Graph Database   |  |
|  |  (Python/FastAPI)  |  |                    |  |
|  |                    |  |  - Graph Storage   |  |
|  |  - Discovery       |  |  - Query Engine    |  |
|  |  - Adapters        |  |  - Algorithm       |  |
|  |  - Graph Engine    |  |    Plugins         |  |
|  |  - Intelligence    |  |                    |  |
|  |  - API Layer       |  |                    |  |
|  +----------+----------+  +----------+---------+  |
|             |    Internal Protocol   |            |
|             +------------------------+            |
|                                                  |
+--------------------------------------------------+
```

### 9.2 Air-Gap Deployment

GRASP is designed for air-gapped operation as a first-class deployment mode, not an afterthought. In an air-gapped environment:

- All adapters connect to local sources only
- Per-source models train entirely on local data
- No telemetry, no model updates, no connectivity of any kind leaves the deployment boundary
- Domain Packs are pre-loaded at deployment time
- Corrections accumulate locally and improve local models only

This makes GRASP suitable for defence, critical infrastructure, healthcare, and any environment where data sovereignty is non-negotiable.

### 9.3 Environment Variables

All configuration via .env, zero hardcoding:

```
# GRASP Core
GRASP_LOG_LEVEL=info
GRASP_API_PORT=8443

# Graph Database
GRASP_GRAPH_DB_URI=<protocol>://<host>:<port>
GRASP_GRAPH_DB_USER=<user>
GRASP_GRAPH_DB_PASSWORD=<secret>

# Source: Search Index
GRASP_SOURCE_1_TYPE=search_index
GRASP_SOURCE_1_ENDPOINT=https://<host>:<port>
GRASP_SOURCE_1_AUTH_USER=<user>
GRASP_SOURCE_1_AUTH_PASSWORD=<secret>
GRASP_SOURCE_1_TLS_VERIFY=false

# Source: DataFlash Binary
GRASP_SOURCE_2_TYPE=dataflash
GRASP_SOURCE_2_PATH=/data/mavlink/
GRASP_SOURCE_2_WATCH=true

# Source: File Watcher
GRASP_SOURCE_3_TYPE=file
GRASP_SOURCE_3_PATH=/data/events/events.json
GRASP_SOURCE_3_FORMAT=jsonl

# Per-Source Model Paths
GRASP_MODEL_BASE_PATH=/data/models
GRASP_FEEDBACK_BASE_PATH=/data/feedback

# Classification
GRASP_CLASSIFIER_CONFIDENCE_THRESHOLD=0.6

# Graph Lifecycle
GRASP_GRAPH_HOT_RETENTION_HOURS=24
GRASP_GRAPH_WARM_RETENTION_DAYS=30
GRASP_GRAPH_PRUNE_SCHEDULE=0 2 * * *

# Intelligence Engine
GRASP_BASELINE_MIN_EVENTS=10000
GRASP_ANOMALY_THRESHOLD=0.85
GRASP_ATTACK_CHAIN_MIN_CONFIDENCE=0.70

# Domain Pack
GRASP_DOMAIN_PACK=security
```

---

## 10. Validation Strategy

### 10.1 Validation Principles

GRASP validation must be conducted across structurally distinct domain pairs. Validating within a single domain proves capability but not source-agnosticism. Proving the same discovery engine produces meaningful Source Profiles from both security telemetry and UAV sensor data -- without domain-specific code changes -- is the definitive validation of the core thesis.

### 10.2 Domain 1 Validation: Security Operations

**Discovery Validation:**
- Point GRASP at a search-index-based security telemetry source with zero configuration beyond endpoint
- Measure: Correct entity type identification rate, confidence scores, relationship discovery
- Compare discovered Source Profile against known Wazuh field semantics

**Graph Validation:**
- Run adversary emulation profile against monitored environment
- Measure: Does the graph show the attack chain as connected relationships?
- Quantify: How many manual correlation steps does GRASP eliminate?

**Intelligence Validation:**
- Establish behavioural baselines during normal operation
- Run lateral movement simulation
- Measure: Anomaly detection accuracy, confidence score calibration

### 10.3 Domain 2 Validation: UAV / Autonomous Systems

**Discovery Validation:**
- Point GRASP at ArduPilot DataFlash binary logs with zero UAV-specific configuration
- Measure: Does GRASP correctly classify IMU axes as co-occurring METRIC entities, GPS fields as ENTITY candidates, MODE as ENUM, TimeUS as TEMPORAL?
- Compare discovered Source Profile against known ArduPilot DataFlash schema (183 message types, 1,574 fields)

**Behavioural Baseline Validation:**
- Establish baseline from ground session telemetry (stationary, motors off)
- Introduce controlled perturbation (motor spin-up sequences)
- Measure: Does Layer 2 flag the perturbation as anomalous deviation from ground baseline?

**Cross-Platform Validation:**
- Run identical test sequences on both airframes
- Compare Source Profiles: structurally similar, statistically distinct
- Validate: Per-source model architecture produces independent baselines for physically distinct platforms

**Adversarial Detection (Future):**
- Simulate GPS spoofing signature (discontinuous position jump while IMU-integrated position holds)
- Measure: Does the graph reveal the multi-stream anomaly pattern that no single-stream analysis would detect?

### 10.4 Cross-Domain Proof

The definitive proof of Intelligent Data Attribution: the same GRASP binary, pointed at security telemetry and UAV telemetry in the same deployment, produces two structurally coherent Source Profiles using identical discovery code with no domain-specific branches. Only the Domain Pack differs.

---

## 11. Build Sequence

Ordered by dependency and validation priority:

| Phase | Component | Deliverable | Validates |
|-------|-----------|-------------|-----------|
| 1 | Discovery Engine | Source Profile from raw data | Core GRASP concept |
| 2 | Transport Layer | Index Poller + File Watcher adapters | Data connectivity |
| 3 | DataFlash Adapter | ArduPilot binary log parser | Second domain, binary transport |
| 4 | Graph Engine | Live graph from discovered entities | Entity extraction + relationships |
| 5 | API Layer (REST) | FastAPI endpoints for source mgmt + graph queries | Operational interface |
| 6 | Intelligence Layer 1 | Structural graph analysis (PageRank, communities) | Immediate analytical value |
| 7 | Intelligence Layer 2 | Behavioural baselining + anomaly detection | Self-learning capability |
| 8 | Per-Source Model | RandomForest classifier scoped to source | Trainable classification |
| 9 | Domain Pack: Security | Security TypeHints + synthetic training data | Security domain maturity |
| 10 | Domain Pack: UAV | UAV TypeHints + synthetic training data | UAV domain maturity |
| 11 | Intelligence Layer 3 | Semantic enrichment via Domain Pack | Domain-specific intelligence |
| 12 | Feedback Loop | Analyst corrections improve per-source models | Continuous learning |
| 13 | API Layer (GraphQL) | Flexible graph queries via Strawberry | Advanced consumer interface |
| 14 | Syslog Adapter | Syslog listener for network appliances | Third transport type |

---

## 12. Technology Stack

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Core Language | Python 3.12 | ML ecosystem, graph database drivers, FastAPI compatibility |
| API Framework | FastAPI | Async-native, automatic OpenAPI docs, Python-native |
| GraphQL (Phase 2) | Strawberry | Python-native, FastAPI integration |
| Graph Database | Neo4j 5.x-community | Cypher query language, APOC algorithms, proven at scale |
| ML Framework | scikit-learn | Unsupervised learning (HDBSCAN) + supervised (RandomForest) |
| Graph Algorithms | networkx + APOC | In-memory and database-level graph analysis |
| Search Index Client | elasticsearch-py | Async client for search-index-based sources |
| Binary Parsing | Python struct (stdlib) | Zero-dependency DataFlash binary parsing |
| Deployment | Docker (python:3.12-slim) | Minimal footprint, hardened, production-ready |
| Orchestration | docker-compose | Single-command deployment |
| Configuration | Environment variables (.env) | Zero-hardcode principle |

---

## 13. Security Considerations

### 13.1 GRASP's Own Security Posture

- TLS for all external connections
- PKI certificate management for production deployments
- Non-root container execution
- Read-only filesystem mounts where possible
- No shell in production images
- API authentication required for all endpoints
- Secrets managed via environment variables

### 13.2 Data Handling

- GRASP stores raw event data in the graph database
- No data leaves the deployment boundary
- Per-source corrections and models are stored locally, never transmitted
- Source credentials are stored in environment variables, never in the graph or logs

### 13.3 Air-Gap Security Posture

In air-gapped deployments, GRASP produces zero outbound network traffic by design. There are no update checks, no telemetry callbacks, no model synchronisation endpoints. The system is self-contained from first boot.

---

## 14. Future Considerations

- **Multi-tenant support**: Source Profile and graph namespacing for managed service deployments
- **Distributed deployment**: Engine separation from graph database for scale
- **Advanced entity resolution**: ML-based identity correlation across sources
- **Autonomous response**: Integration with SOAR or equivalent platforms for recommended action execution
- **Federated learning**: Opt-in anonymised correction sharing across GRASP deployments of the same source type
- **Additional Domain Packs**: Industrial (OPC-UA, SCADA), Healthcare (HL7, FHIR), Financial (FIX, SWIFT)
- **Kubernetes deployment**: Helm charts for cloud-native environments
- **High-throughput ingestion**: Purpose-built components in compiled languages for extreme-volume sources
- **SDR Integration**: HackRF / GNU Radio stream adapter for RF environment intelligence in UAV deployments

---

## 15. Success Criteria

GRASP v2.0 is considered successful when:

1. The discovery engine correctly identifies entity types from raw security telemetry with >90% accuracy and zero source-specific configuration
2. The discovery engine correctly identifies entity types from raw ArduPilot DataFlash binary logs with >90% accuracy using the same discovery code, zero UAV-specific configuration in the core, and only the UAV Domain Pack active
3. The graph engine builds a connected topology from multiple sources with correct entity resolution for shared identifiers
4. Per-source behavioural baselines detect controlled anomalies (adversary simulation in security, motor perturbation in UAV) as statistically anomalous with confidence scores above the configured threshold
5. Two physically distinct airframes running identical test sequences produce distinct but structurally similar Source Profiles, validating the per-source model architecture
6. The entire system deploys with a single `docker compose up -d` and requires only source endpoint configuration
7. The system operates fully in an air-gapped environment with zero external connectivity, training exclusively on locally-sourced data

---

## 16. Decision Log

| Decision | Choice | Rationale | Date |
|----------|--------|-----------|------|
| Core language | Python 3.12 | ML ecosystem, graph database drivers, FastAPI | 2026-02-17 |
| API framework | FastAPI (REST first) | Async-native, auto-docs, minimal overhead | 2026-02-17 |
| GraphQL timing | Phase 2, not Phase 1 | Premature complexity; REST sufficient initially | 2026-02-17 |
| Field classification | Unsupervised ML, not regex ladder | Scalability across unknown source types | 2026-02-17 |
| Normalization | Rejected | Destroys features the ML engine needs | 2026-02-17 |
| Unikernels | Deferred | Python ecosystem incompatibility | 2026-02-17 |
| Deployment model | Single container + graph DB | Minimise operational complexity | 2026-02-17 |
| Project identity | Standalone sidecar | Maximise portability and adoption | 2026-02-17 |
| Graph database | Neo4j 5.x-community | Cypher maturity, APOC, proven scale | 2026-02-17 |
| Platform identity | Data intelligence platform, security as first customer | Security framing limits addressable market; Intelligent Data Attribution is the universal capability | 2026-02-23 |
| Per-source models | No classifier crosses source boundaries | Prevents cross-domain bias; enables air-gap operation; produces honest uncertainty on new sources | 2026-02-23 |
| Domain Pack architecture | Core stays domain-blind; domain knowledge lives in packs | Core is universal; packs are the extension and monetisation surface | 2026-02-23 |
| UAV as second domain | ArduPilot DataFlash, Pixhawk hardware | Structurally distinct from security; air-gap mandatory; geopolitically urgent; live hardware available | 2026-02-23 |
| Air-gap as first-class | Designed in, not bolted on | Defence and critical infrastructure are highest-value markets; cloud dependency disqualifies GRASP from them | 2026-02-23 |
| TypeHint extensibility | Hints are domain pack additions, not classification gates | Classification logic stays universal; domain vocabulary is injected, not hardcoded | 2026-02-23 |
| Synthetic training data | Not pre-loaded into core; lives in Domain Packs | Pre-loading creates source bias in the core; packs carry domain-specific bootstrapping | 2026-02-23 |

---

*GRASP: Because intelligence is not about data points. It is about what connects them.*