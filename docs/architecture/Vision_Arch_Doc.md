# GRASP - Graph-based Reconnaissance, Analysis, and Security Posture

## Vision Architecture Document v1.0

**Classification**: Internal - Architecture Vision
**Status**: Draft
**Date**: 2026-02-17
**Author**: Doc + Claude (Co-Architects)

---

## 1. Executive Summary

GRASP is a standalone, plug-and-play security intelligence sidecar that transforms raw security telemetry from any source into a living graph of relationships, enabling AI-driven anomaly detection, attack chain reconstruction, and security posture analysis.

Unlike traditional SIEM correlation engines that operate on flat, normalized event data, GRASP treats relationships as the primary analytical lens. It autonomously discovers data structure, extracts entities, infers relationships, and builds a continuously evolving graph model -- without requiring source-specific configuration, field mappings, or schema definitions.

GRASP does not replace any component in an existing security stack. It consumes standard outputs from tools already deployed, adds graph-based intelligence, and provides insights that flat correlation fundamentally cannot deliver.

### 1.1 Design Philosophy

**Self-learning intelligence, open-source accessibility, sidecar portability.**

- Self-learning: Unsupervised models discover structure and learn behavioral baselines autonomously
- Zero-configuration: Point GRASP at a data source, it figures out the rest
- Signal fidelity: Native event formats are preserved; normalization destroys information the ML engine needs
- Graph-first: Relationships between entities are the primary detection mechanism, not individual events
- Source-agnostic: Works with any security telemetry without source-specific customization
- Product-agnostic: No dependency on any specific vendor, tool, or platform

### 1.2 What GRASP Is NOT

- NOT a SIEM -- it has no log storage, no dashboards, no compliance reporting
- NOT a module within any other platform -- it is a fully independent project
- NOT dependent on any specific security tool or vendor
- NOT a normalized event pipeline -- it deliberately avoids flattening data into common schemas
- NOT a replacement for any existing security investment -- it makes everything already deployed smarter

---

## 2. Problem Statement

### 2.1 The Gap in Current Security Operations

Every SOC runs some variation of the same pattern: collect logs, index them, write correlation rules, generate alerts, triage in a queue. The tools differ across organizations but the architectural approach is identical -- flat, document-oriented event processing.

This approach has a fundamental limitation: **it cannot see relationships.**

When an attacker executes a multi-stage attack -- initial access, credential theft, lateral movement, privilege escalation, data exfiltration -- a traditional SIEM sees five separate alerts at different severity levels, possibly in different indices, possibly minutes or hours apart. An analyst must manually correlate these events by searching for shared indicators across time windows.

In a graph, those five events are connected through the assets and identities involved. The attack path is visible as a structural pattern -- a chain of relationships that emerges naturally from the data. The path IS the detection, not the individual alerts.

### 2.2 Why Nobody Has Solved This in Open Source

Graph databases are used in security tooling today, but narrowly:

- **BloodHound**: Graph-based Active Directory attack path analysis -- offline, single-domain, pentesting-focused
- **GraphKer**: Graph-based MITRE CVE/CWE/CAPEC knowledge graphs -- static reference data, not operational
- **Cartography**: Graph-based cloud infrastructure auditing -- inventory snapshots, not real-time correlation

No open-source project uses a graph database as a **real-time operational correlation engine** inside a security operations pipeline. Every existing project treats graph analysis as an offline tool or static reference database.

### 2.3 The Commercial Benchmark

The commercial market validates the core philosophy. Products valued in the billions use unsupervised self-learning AI that models an environment without signatures or rules. However, these commercial offerings are:

- Proprietary and closed-source
- Monolithic -- requiring their own sensors and data collection infrastructure
- Expensive -- six-figure enterprise deployments
- Not graph-native -- typically using Bayesian models and clustering, with graph techniques added as supplementary analysis

GRASP brings this class of intelligence to the open-source ecosystem with a fundamentally different architecture: graph-first, sidecar deployment, native signal preservation, and zero vendor lock-in.

---

## 3. Architecture Overview

### 3.1 Core Principles

1. **API-First**: Every capability exposed through well-documented APIs
2. **Single Deployable**: One container alongside graph database, deployed via docker-compose
3. **Zero-Hardcode**: All configuration through environment variables
4. **Thin Adapters**: Transport and discovery only -- no transformation
5. **Native Signal Fidelity**: Raw events preserved; relationships extracted, not schemas enforced
6. **Unsupervised Discovery**: Structure, entities, and relationships learned from data, not configured
7. **Incremental Intelligence**: Value from minute one (topology), improving over time (behavioral ML)
8. **Product Agnostic**: No assumption about what tools produce the telemetry

### 3.2 High-Level Architecture

```
+-------------------------------------------------------------------+
|                        DATA SOURCES                                |
|  Any security telemetry: indexed data, raw logs, APIs, syslog     |
+-------+-------------------+-------------------+-------------------+
        |                   |                   |
        v                   v                   v
+-------+-------+   +-------+-------+   +-------+-------+
|   Adapter:    |   |   Adapter:    |   |   Adapter:    |
| Index Poller  |   |  File Watcher |   | Syslog/API    |
|  (Transport   |   |  (Transport   |   |  (Transport   |
|  + Discovery) |   |  + Discovery) |   |  + Discovery) |
+-------+-------+   +-------+-------+   +-------+-------+
        |                   |                   |
        +-------------------+-------------------+
                            |
                   +--------v--------+
                   |  Source Profile  |
                   |    Registry     |
                   | (What GRASP has |
                   |   discovered)   |
                   +--------+--------+
                            |
                   +--------v--------+
                   |  Entity         |
                   |  Extraction     |
                   |  Engine         |
                   | (Pattern-based  |
                   |  recognition)   |
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
     | - Behavioral     |        |   (Phase 2)     |
     |   baselining     |        | - WebSocket     |
     | - Anomaly        |        |   (Live feed)   |
     |   detection      |        +-----------------+
     | - Attack chain   |
     |   reconstruction |
     | - Confidence     |
     |   scoring        |
     +------------------+
```

### 3.3 Integration Model

```
+-------------------------------------------+
|        Any Security Stack                  |
|                                           |
|  +----------+  +-----------+  +--------+  |
|  | EDR/XDR  |  | Network   |  | Threat |  |
|  | Platform |  | Sensors   |  | Intel  |  |
|  +----+-----+  +-----+-----+  +---+----+  |
|       |              |             |       |
|       v              v             v       |
|  +----+------------------------------+    |
|  |   Search/Index Platform            |    |
|  |   or Raw Log Storage               |    |
|  +----+------------------------------+    |
|       |                                   |
+-------+-----------------------------------+
        |
        | Standard outputs (no modification required)
        |
+-------v-----------------------------------+
|       GRASP (Sidecar)                      |
|       Discovers, correlates, learns        |
|  +----------------+  +----------------+   |
|  | GRASP Engine   |  | Graph Database |   |
|  +----------------+  +----------------+   |
+-------------------------------------------+

GRASP operates independently of any specific security stack.
It consumes standard telemetry outputs without modification.
```

---

## 4. Adapter Layer

### 4.1 Purpose

Adapters solve exactly two problems: **how to connect to a data source** (transport contract) and **what the data looks like** (discovery contract). They do NOT transform, normalize, or enrich data.

### 4.2 Transport Contract

The transport contract defines how an adapter retrieves events from a source. Each transport type implements a common interface:

- **Connect**: Establish connection using provided endpoint and credentials
- **Sample**: Retrieve N events for discovery analysis
- **Stream**: Continuously deliver new events to the engine
- **Health**: Report connection status and throughput metrics

Transport types supported at launch:

| Type | Mechanism | Applicable Sources |
|------|-----------|-------------------|
| Index Poller | Search index scroll/search-after API | Any search-engine-indexed security data |
| File Watcher | Filesystem tail on structured log files | Any JSON-per-line or structured log output |
| Syslog Listener | UDP/TCP syslog receiver | Any network device, firewall, or appliance |

Future transport types (post-launch):

| Type | Mechanism | Applicable Sources |
|------|-----------|-------------------|
| Message Queue Consumer | Topic/queue subscription | High-volume streaming pipelines |
| REST Poller | Periodic API polling | Any REST-based threat intel or event API |
| Webhook Receiver | HTTP POST listener | Alert forwarding systems, automation platforms |

### 4.3 Discovery Contract

The discovery contract is the heart of GRASP. When an adapter connects and samples data, the discovery engine analyzes the raw events to produce a **Source Profile** -- a living document of everything GRASP has learned about a data source.

Discovery is performed autonomously through value-based analysis, not field name interpretation:

**Type Inference from Values:**

| Pattern Detected | Entity Classification | Confidence Method |
|------------------|-----------------------|-------------------|
| IPv4/IPv6 regex match | Network Entity (IP) | Regex + validation |
| RFC3339/ISO8601 patterns | Timestamp | Format detection |
| Hex string 32/40/64 chars | Hash (MD5/SHA1/SHA256) | Length + charset |
| Username-shaped strings | Identity Entity | Heuristic + cardinality |
| Hostname/FQDN patterns | Asset Entity | DNS pattern match |
| Low cardinality (< 20 unique) | Category/Severity | Statistical profiling |
| ATT&CK ID pattern (Txxxx) | Technique Reference | Regex match |
| MAC address pattern | Network Interface | Regex + validation |
| Port number range (0-65535) | Service Indicator | Range validation |
| URL/URI pattern | Resource Locator | Format detection |

**Relationship Inference from Co-occurrence:**

When two entity-typed fields appear in the same event, the discovery engine infers a relationship:

- Source IP + Destination IP in same event = network communication relationship
- Username + Hostname in same event = session/authentication relationship
- Hash + Filename in same event = file indicator relationship
- IP + Technique ID in same event = technique-to-asset association

**Source Profile Structure:**

Each discovered source produces a profile containing:

- Source identifier and transport type
- Field inventory with inferred types and confidence scores
- Entity field classifications
- Relationship patterns (co-occurrence maps)
- Cardinality statistics per field
- Sample event fingerprint for drift detection
- Discovery timestamp and revision counter

The Source Profile is not static. It refines continuously as GRASP sees more events, adjusting confidence scores and discovering new patterns.

### 4.4 What Adapters Explicitly Do NOT Do

- No field renaming or mapping
- No schema enforcement
- No data type coercion
- No enrichment or augmentation
- No filtering or deduplication
- No normalization to a common event format

The raw event, exactly as received, is passed through to the graph engine with the Source Profile attached as metadata.

---

## 5. Graph Engine

### 5.1 Purpose

The graph engine takes raw events and Source Profiles and builds a living graph in the graph database. It is responsible for entity resolution, relationship creation, and graph lifecycle management.

### 5.2 Dynamic Schema

Unlike traditional graph applications with predefined node labels and relationship types, GRASP builds its schema organically from what the discovery engine finds.

**Node Creation Logic:**

For each event, the graph engine examines the Source Profile to identify entity fields. Each entity value becomes a node (or merges with an existing node):

- A field classified as "Network Entity (IP)" with value "192.168.1.100" creates or merges an IP node
- A field classified as "Identity Entity" with value "admin" creates or merges an Identity node
- A field classified as "Asset Entity" with value "webserver01" creates or merges an Asset node

Nodes carry:

- The entity value as primary identifier
- First-seen and last-seen timestamps
- Source attribution (which adapter discovered this entity)
- The full raw event payload as a property (preserving native signal fidelity)
- Discovery confidence score

**Relationship Creation Logic:**

Co-occurring entities within the same event produce edges:

- IP-to-IP co-occurrence = COMMUNICATES_WITH
- Identity-to-Asset co-occurrence = AUTHENTICATED_TO / SESSION_ON
- Hash-to-Asset co-occurrence = OBSERVED_ON
- Technique-to-Asset co-occurrence = TECHNIQUE_APPLIED

Relationships carry:

- Timestamp of the event that created them
- Event count (incremented on repeated observations)
- Source attribution
- The raw event payload that established the relationship

### 5.3 Entity Resolution

A critical challenge: the same real-world entity may appear differently across sources. An IP address appearing in host-based alerts is the same entity as the same IP appearing in network flow data. The graph engine merges these based on entity value matching -- this is why entity extraction is value-based, not field-name-based.

Advanced entity resolution (e.g., recognizing that "jsmith" in one source and "john.smith" in another are the same person) is a Phase 2 intelligence problem, not a Phase 1 graph engine problem.

### 5.4 Graph Lifecycle Management

The graph cannot grow unbounded. Lifecycle management includes:

- **Hot tier**: Last 24 hours -- full detail, all relationships, all event payloads
- **Warm tier**: 1-30 days -- aggregated relationships (counts instead of individual events), entity nodes retained
- **Cold tier**: 30+ days -- entity nodes only, statistical summaries, no individual events
- **Pruning**: Configurable retention policies per tier

Tier transitions are handled by background jobs within the graph engine.

---

## 6. Intelligence Engine

### 6.1 Layered Intelligence Model

The intelligence engine operates in three layers, each building on the previous. Layers are designed to deliver value incrementally -- Layer 1 works from day one, Layers 2 and 3 improve over time.

### 6.2 Layer 1: Structural Analysis (Immediate Value)

Available within minutes of first data ingestion.

**Graph Algorithms:**

- **PageRank**: Identify the most connected/critical nodes in the graph -- which assets are central to the most communication paths
- **Community Detection**: Find clusters of tightly connected entities -- natural groupings that may represent network segments, application tiers, or attack clusters
- **Shortest Path**: Calculate paths between any two entities -- critical for attack chain visualization
- **Degree Centrality**: Identify nodes with unusual numbers of connections -- potential indicators of scanning, lateral movement, or C2 beaconing

**Immediate Outputs:**

- Topology map of discovered environment
- Critical asset identification (highest PageRank scores)
- Network segmentation visualization (community clusters)
- Connection anomalies (nodes with degree significantly above peers)

### 6.3 Layer 2: Behavioral Baselining (Hours to Days)

Available after sufficient data accumulation to establish statistical baselines.

**Unsupervised Models:**

- **Temporal Pattern Learning**: What does normal communication look like at different times of day, week, month? Deviation from temporal patterns flags anomalies
- **Relationship Frequency Baselining**: How often does Asset A normally communicate with Asset B? A sudden spike or novel relationship triggers an alert
- **Graph Topology Stability**: How stable is the overall graph structure? New clusters forming, existing clusters fragmenting, or novel bridge nodes appearing all indicate environmental change
- **Entity Behavioral Profiles**: Each entity develops a behavioral fingerprint based on its graph neighborhood -- who it talks to, how often, with what patterns

**Baseline Outputs:**

- Per-entity behavioral profiles with confidence intervals
- Anomaly scores for every new event (deviation from baseline)
- Trend analysis over configurable time windows
- Drift detection when baselines shift significantly

### 6.4 Layer 3: Semantic Enrichment (Evolving)

AI-assisted interpretation of what the unsupervised layers discover.

**Capabilities:**

- **Attack Chain Reconstruction**: When anomalous relationships form a path through multiple assets, correlate with known attack frameworks to classify the potential attack type
- **Technique Mapping**: If source events contain technique identifiers, the intelligence engine maps graph patterns to known tactics and techniques
- **Confidence Scoring**: Every intelligence output carries a confidence score reflecting data quality, baseline maturity, and pattern strength
- **Recommendation Generation**: Based on detected patterns and confidence scores, suggest investigative or response actions

**Feedback Loop:**

- Analyst approves, rejects, or modifies recommendations
- Decisions feed back into the intelligence engine
- Over time, the system learns which recommendations are useful for this specific environment
- This implements a Human-AI Command Mode -- a continuous learning mechanism where the system and analyst calibrate trust bidirectionally

---

## 7. API Layer

### 7.1 Technology Choice

**Phase 1**: FastAPI (Python) providing REST endpoints with automatic OpenAPI documentation.
**Phase 2**: Strawberry GraphQL added alongside REST for flexible graph queries.
**Phase 3**: WebSocket support for real-time anomaly and intelligence feeds.

### 7.2 API Domains

**Source Management:**

- Register a new data source (endpoint + credentials)
- View discovered Source Profiles
- Monitor adapter health and throughput
- Submit discovery corrections (feedback loop)

**Graph Intelligence:**

- Query entities and relationships
- Request attack path analysis between entities
- Retrieve anomaly scores for specific entities or time windows
- Get structural analysis results (PageRank, communities)

**System Operations:**

- Health and readiness endpoints
- Configuration management
- Graph lifecycle status (tier sizes, pruning activity)
- Intelligence engine status (baseline maturity, model health)

---

## 8. Deployment Architecture

### 8.1 Production Deployment

```
docker-compose.yml
+--------------------------------------------------+
|                                                  |
|  +--------------------+  +--------------------+  |
|  |    GRASP Engine     |  |  Graph Database    |  |
|  |  (Python/FastAPI)   |  |                    |  |
|  |                     |  |  - Graph Storage   |  |
|  |  - Discovery Engine |  |  - Query Engine    |  |
|  |  - Adapters         |  |  - Algorithm       |  |
|  |  - Graph Engine     |  |    Plugins         |  |
|  |  - Intelligence     |  |                    |  |
|  |  - API Layer        |  |                    |  |
|  +----------+----------+  +----------+---------+  |
|             |    Internal Protocol   |            |
|             +------------------------+            |
|                                                  |
+--------------------------------------------------+

GRASP Engine Container (hardened):
  - Non-root user
  - Read-only filesystem where possible
  - Dropped capabilities
  - No shell in production image

Graph Database Container:
  - TLS enabled
  - Authentication required
  - Algorithm plugins for graph analysis
```

### 8.2 User Experience

1. User pulls GRASP docker-compose
2. Configures .env with source endpoints and credentials (the ONLY configuration)
3. Runs `docker compose up -d`
4. GRASP connects, discovers, builds graph
5. Within minutes: entity topology visible via API
6. Within hours: behavioral baselines forming, anomaly scores appearing
7. Within days: mature baselines, attack chain detection operational

### 8.3 Environment Variables

All configuration via .env, zero hardcoding:

```
# GRASP Core
GRASP_LOG_LEVEL=info
GRASP_API_PORT=8443

# Graph Database Connection
GRASP_GRAPH_DB_URI=<protocol>://<host>:<port>
GRASP_GRAPH_DB_USER=<user>
GRASP_GRAPH_DB_PASSWORD=<secret>

# Source: Search Index (example)
GRASP_SOURCE_1_TYPE=search_index
GRASP_SOURCE_1_ENDPOINT=https://<host>:<port>
GRASP_SOURCE_1_AUTH_USER=<user>
GRASP_SOURCE_1_AUTH_PASSWORD=<secret>
GRASP_SOURCE_1_TLS_VERIFY=false

# Source: File Watcher (example)
GRASP_SOURCE_2_TYPE=file
GRASP_SOURCE_2_PATH=/data/events/events.json
GRASP_SOURCE_2_FORMAT=jsonl

# Source: Syslog Listener (example)
GRASP_SOURCE_3_TYPE=syslog
GRASP_SOURCE_3_PORT=5514
GRASP_SOURCE_3_PROTOCOL=udp

# Graph Lifecycle
GRASP_GRAPH_HOT_RETENTION_HOURS=24
GRASP_GRAPH_WARM_RETENTION_DAYS=30
GRASP_GRAPH_PRUNE_SCHEDULE=0 2 * * *

# Intelligence Engine
GRASP_BASELINE_MIN_EVENTS=10000
GRASP_ANOMALY_THRESHOLD=0.85
GRASP_ATTACK_CHAIN_MIN_CONFIDENCE=0.70
```

---

## 9. Validation Strategy

### 9.1 Validation Principles

GRASP validation must be conducted against diverse, real-world security telemetry sources representing fundamentally different perspectives:

- **Host-based telemetry**: Security alerts from endpoint detection platforms (analyzed events -- the source has already made a judgment)
- **Network-based telemetry**: Flow data and IDS alerts from network sensors (observed events -- raw traffic metadata and detection)
- **Perimeter telemetry**: Firewall and gateway logs (policy enforcement events -- traffic decisions and session state)

The validation environment must include at least three sources using different transport mechanisms to prove source-agnosticism.

### 9.2 Adversary Simulation

Validation requires controlled adversary simulation using tools that generate known attack patterns mapped to established attack frameworks:

| Simulation Type | Purpose | Validation Target |
|----------------|---------|-------------------|
| ATT&CK-based adversary emulation | Execute known multi-stage attack chains | Attack chain reconstruction accuracy |
| Automated lateral movement simulation | Generate realistic pivot-and-spread behavior | Relationship detection and path analysis |

### 9.3 Validation Methodology

**Phase 1 -- Discovery Validation:**

- Point GRASP at a search-index-based telemetry source with zero configuration beyond endpoint
- Measure: How many entity types correctly identified? What confidence scores?
- Point GRASP at a file-based telemetry source with zero configuration beyond path
- Measure: Same metrics, different source type
- Compare discovered Source Profiles -- are the same real-world entities recognized across sources?

**Phase 2 -- Graph Validation:**

- Run adversary emulation profile against monitored environment
- Measure: Does the graph show the attack chain as connected relationships?
- Compare: Flat alert view in the source platform vs graph view in GRASP for the same attack
- Quantify: How many manual correlation steps does GRASP eliminate?

**Phase 3 -- Intelligence Validation:**

- Establish behavioral baselines during normal operation
- Run lateral movement simulation
- Measure: Does the anomaly detection flag the new relationships?
- Measure: Does attack chain reconstruction correctly classify the simulation?
- Measure: Are confidence scores meaningful (high for real attacks, low for noise)?

---

## 10. Build Sequence

Ordered by dependency and validation priority:

| Phase | Component | Deliverable | Validates |
|-------|-----------|-------------|-----------|
| 1 | Discovery Engine | Source Profile from raw data | Core GRASP concept |
| 2 | Transport Layer | Index Poller + File Watcher adapters | Data connectivity |
| 3 | Graph Engine | Live graph from discovered entities | Entity extraction + relationships |
| 4 | API Layer (REST) | FastAPI endpoints for source mgmt + graph queries | Operational interface |
| 5 | Intelligence Layer 1 | Structural graph analysis (PageRank, communities) | Immediate analytical value |
| 6 | Intelligence Layer 2 | Behavioral baselining + anomaly detection | Self-learning capability |
| 7 | Intelligence Layer 3 | Attack chain reconstruction + technique mapping | Security-specific intelligence |
| 8 | API Layer (GraphQL) | Flexible graph queries via Strawberry | Advanced consumer interface |
| 9 | Feedback Loop | Analyst corrections improve discovery + intelligence | Continuous learning |
| 10 | Syslog Adapter | Syslog listener for network appliances | Third transport type |

---

## 11. Technology Stack

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Core Language | Python 3.12 | ML ecosystem, graph database drivers, FastAPI compatibility |
| API Framework | FastAPI | Async-native, automatic OpenAPI docs, Python-native |
| GraphQL (Phase 2) | Strawberry | Python-native, FastAPI integration |
| Graph Database | Neo4j 5.x-community | Cypher query language, APOC algorithms, proven at scale |
| ML Framework | scikit-learn | Unsupervised learning (clustering, anomaly detection) |
| Graph Algorithms | networkx + APOC | In-memory and database-level graph analysis |
| Search Index Client | elasticsearch-py | Async client for search-index-based sources |
| Deployment | Docker (python:3.12-slim) | Minimal footprint, hardened, production-ready |
| Orchestration | docker-compose | Single-command deployment |
| Configuration | Environment variables (.env) | Zero-hardcode principle |

---

## 12. Security Considerations

### 12.1 GRASP's Own Security Posture

- TLS for all external connections (source systems, graph database, API endpoints)
- PKI certificate management for production deployments
- Non-root container execution
- Read-only filesystem mounts where possible
- No shell in production images
- API authentication required for all endpoints
- Secrets managed via environment variables (future: secrets manager integration)

### 12.2 Data Handling

- GRASP stores raw event data in the graph database -- the same security controls apply as the source systems
- Graph lifecycle management ensures data retention compliance
- No data leaves the deployment boundary -- GRASP is entirely self-contained
- Source credentials are stored in environment variables, never in the graph or logs

### 12.3 Attack Surface

- Single exposed port (API endpoint)
- No inbound connections required for Index Poller or File Watcher adapters
- Syslog adapter requires a listening port (configurable, non-privileged)
- Graph database accessible only within the docker-compose internal network

---

## 13. Future Considerations

Items explicitly deferred from initial build but architecturally accounted for:

- **Multi-tenant support**: Source Profiles and graph namespacing for managed service deployments
- **Distributed deployment**: GRASP engine separation from graph database for scale
- **Advanced entity resolution**: ML-based identity correlation across sources
- **Autonomous response**: Integration with SOAR platforms for recommended action execution
- **Federated learning**: Anonymized intelligence sharing across GRASP deployments
- **Threat intelligence integration**: Real-time threat intel enrichment as a dedicated adapter
- **Kubernetes deployment**: Helm charts for cloud-native environments
- **High-throughput ingestion gateways**: Purpose-built components in compiled languages for extreme-volume edges

---

## 14. Success Criteria

GRASP v1.0 is considered successful when:

1. The discovery engine correctly identifies entity types from raw security telemetry with >90% accuracy and zero source-specific configuration
2. The graph engine builds a connected topology from multiple sources with correct entity resolution for shared identifiers (IPs, hostnames)
3. An adversary simulation produces a visible, connected attack chain in the graph that is not visible through flat SIEM correlation alone
4. Behavioral baselines detect simulated lateral movement as anomalous with confidence scores above the configured threshold
5. The entire system deploys with a single `docker compose up -d` and requires only source endpoint configuration

---

*GRASP: Because security is not about events. It is about relationships.*