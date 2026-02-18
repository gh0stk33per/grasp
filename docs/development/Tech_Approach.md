# GRASP - Technical Approach Document v1.0

## How We Build It

**Classification**: Internal - Technical Approach
**Status**: Draft
**Date**: 2026-02-17
**Author**: Doc + Claude (Co-Architects)
**Companion Document**: GRASP Vision Architecture Document v1.0

---

## 1. Purpose

The Vision Architecture Document defines what GRASP is and why it exists. This document defines how we build it -- the technical approach, design patterns, development methodology, and decision framework that guide every line of code.

This is a living document. As GRASP evolves, approaches that prove wrong will be revised. Approaches that prove right will be reinforced. The goal is intellectual honesty, not perfection.

---

## 2. Development Philosophy

### 2.1 Core Tenets

**Production-grade from day one.** No prototypes that get promoted. No "we'll fix it later." Every component is built to the standard it will run at in production. This does not mean over-engineering -- it means doing the right thing the first time, even if the right thing is simple.

**Function over form.** Working code that proves a concept beats elegant code that doesn't ship. When perfectionism threatens progress, choose pragmatism. When shortcuts threaten quality, choose discipline. The tension between these is where good engineering lives.

**ML-native, not ML-bolted.** Machine learning is not a feature added to GRASP. It is the foundation. The discovery engine, the entity extractor, the relationship modeler, the behavioral baseline, the anomaly detector -- these are all ML problems solved with ML approaches. Classical programming handles transport, storage, and API scaffolding. Intelligence is ML from birth.

**Evolve, don't plan to completion.** GRASP will encounter data formats, edge cases, and architectural challenges we cannot anticipate. The approach must accommodate evolution without requiring rewrites. This means clean interfaces between components, versioned Source Profiles, and the humility to revise decisions when evidence demands it.

### 2.2 Design Constraints

These constraints are non-negotiable and apply to every component:

- **Zero hardcoding**: All configuration through environment variables
- **No source assumptions**: No component may assume knowledge of any specific security product, vendor, or data format
- **Native signal preservation**: Raw event data is never modified, transformed, or normalized by any component
- **Single deployable**: The entire GRASP engine runs as one container alongside the graph database
- **Fail gracefully**: Unknown data, unexpected formats, and classification failures are handled as normal operations, not errors

---

## 3. Component Approach

### 3.1 Discovery Engine

**The Problem:**
Given a batch of raw JSON events from an unknown source, produce a Source Profile that identifies field types, entity classifications, and relationship patterns -- without any prior knowledge of the source.

**The Approach: Feature-Based Unsupervised Classification**

Classical rule-based classification (regex ladders, if/then/else chains) cannot scale to the diversity of security telemetry formats. Instead, the discovery engine treats field classification as a clustering problem.

**Stage 1 -- Field Value Feature Extraction:**

For each unique field path in the sampled events, compute a feature vector from the observed values:

| Feature Category | Specific Features |
|-----------------|-------------------|
| String Metrics | Mean/median/stddev length, min/max length |
| Character Distribution | Ratio of alpha, numeric, hex, punctuation, whitespace |
| Entropy | Shannon entropy of character distribution |
| Format Consistency | Percentage of values matching the most common format pattern |
| Separator Analysis | Most frequent separators (dots, dashes, colons, slashes), separator count distribution |
| Numeric Properties | Parseable as number (%), numeric range, integer vs float ratio |
| Cardinality | Unique values / total values ratio |
| Character Class Patterns | Positional character class sequences (e.g., "NNN.NNN.NNN.NNN" for IPs) |
| Value Length Distribution | Histogram of value lengths (tight = fixed format, wide = variable content) |

This stage is pure computation. No ML, no heuristics. It transforms raw string values into numeric feature vectors suitable for clustering.

**Stage 2 -- Unsupervised Field Clustering:**

Feed all field feature vectors into a density-based clustering algorithm (HDBSCAN preferred):

- Does not require pre-specifying cluster count
- Handles noise (fields that don't fit any cluster)
- Finds arbitrary-shaped clusters (important because feature distributions for IPs, hashes, and timestamps have very different shapes)
- Produces cluster membership with confidence scores

Output: N clusters, each representing a discovered field type. Fields within a cluster share statistical properties.

**Stage 3 -- Cluster Interpretation:**

Apply lightweight heuristics to label discovered clusters with semantic meaning:

- Cluster with fixed-length hex values, high entropy = hash-family (MD5/SHA1/SHA256 distinguished by length)
- Cluster with dot-separated numeric octets in valid ranges = IP address family
- Cluster with ISO/RFC timestamp format consistency = temporal field
- Cluster with low cardinality, short strings = categorical/severity field
- Cluster with FQDN-pattern separators = hostname/domain family
- Cluster with high cardinality, mixed alphanumeric = identifier family (potentially usernames, session IDs)

**Critical design decision:** Clusters that cannot be labeled are tagged as "discovered-type-N" and retained. The system does not discard what it does not understand. Unknown types still participate in co-occurrence analysis and relationship inference. Analyst feedback can label them later.

**Stage 4 -- Co-occurrence and Relationship Inference:**

For all fields classified as entity types (IP, hostname, identity, hash, etc.), compute pairwise mutual information within events:

- High mutual information between two entity fields = strong co-occurrence = candidate relationship
- Temporal mutual information (do these fields change together over time?) strengthens relationship confidence
- Directional analysis where applicable (field A changes first, then field B changes = potential causal relationship)

Output: A relationship map identifying which entity types appear together and how strongly they co-occur.

**Stage 5 -- Source Profile Assembly:**

Combine all outputs into a versioned Source Profile:

- Field inventory with cluster assignments and confidence scores
- Entity classifications with semantic labels (known or discovered-type-N)
- Relationship map with mutual information scores
- Statistical metadata (sample size, timestamp range, throughput estimate)
- Profile version and revision timestamp

The Source Profile is persisted and updated incrementally as GRASP sees more events from the same source.

### 3.2 Transport Layer

**The Problem:**
Connect to diverse data sources using different protocols and deliver raw events to the discovery and graph engines reliably.

**The Approach: Adapter Interface Pattern**

All adapters implement a common abstract interface:

```
Adapter Interface:
    connect(config) -> ConnectionStatus
    sample(n) -> List[RawEvent]
    stream() -> AsyncIterator[RawEvent]
    health() -> AdapterHealth
    disconnect() -> None
```

Each transport type implements this interface differently:

**Index Poller Adapter:**
- Connects to search index APIs (initially Elasticsearch-compatible)
- Discovers available indices via API introspection
- Samples using search queries with size limits
- Streams using search-after or scroll pagination with configurable poll intervals
- Tracks last-seen document for incremental polling

**File Watcher Adapter:**
- Connects by validating file path existence and readability
- Detects file format (JSON-per-line, structured JSON, CSV) from initial sample
- Samples by reading first N lines
- Streams using filesystem watching (inotify on Linux) with tail-follow semantics
- Handles file rotation (detect new file, continue from last position)

**Syslog Listener Adapter:**
- Opens UDP/TCP listener on configured port
- Detects message format from initial messages (RFC3164, RFC5424, raw)
- Parses syslog envelope, extracts payload
- Samples by buffering first N messages
- Streams by yielding messages as they arrive

**Transport Guarantees:**
- At-least-once delivery (duplicate handling is the graph engine's responsibility via entity merge)
- Configurable batch sizes for throughput optimization
- Backpressure signaling when the graph engine falls behind
- Automatic reconnection with exponential backoff

### 3.3 Graph Engine

**The Problem:**
Take raw events and Source Profiles and build a living, queryable graph that represents entities and their relationships.

**The Approach: Source-Profile-Driven Graph Construction**

The graph engine does not contain any knowledge about data formats. It operates entirely from Source Profiles provided by the discovery engine.

**Entity Extraction:**
For each incoming event, the graph engine:
1. Retrieves the Source Profile for the event's source
2. Identifies fields classified as entity types in the profile
3. Extracts entity values from those fields
4. Creates or merges graph nodes using entity value as the primary key

**Merge Strategy:**
- Same entity value from same source = update existing node (increment event count, update last-seen)
- Same entity value from different sources = merge nodes (critical for cross-source correlation)
- Merge preserves all source attributions and maintains per-source statistics

**Relationship Creation:**
For each pair of entity fields with significant mutual information (from the Source Profile's relationship map):
1. Extract both entity values from the event
2. Create or strengthen a relationship edge between the corresponding nodes
3. Attach event timestamp and raw event reference to the edge

**Batch Processing:**
- Events are processed in configurable batches for throughput
- Neo4j UNWIND operations for efficient bulk node/edge creation
- Transaction management with retry logic for transient failures

**Graph Schema Evolution:**
- New entity types discovered by the discovery engine automatically create new node labels
- New relationship patterns automatically create new edge types
- No manual schema migration required
- Schema changes are logged for operational awareness

### 3.4 Intelligence Engine

**The Problem:**
Extract actionable security intelligence from the graph structure using unsupervised methods.

**The Approach: Layered Analysis with Incremental Value**

**Layer 1 -- Structural Analysis (Graph Algorithms):**

Runs on-demand and on schedule against the current graph state:

- PageRank via APOC plugin: Identifies critical nodes (high-traffic assets, central identities)
- Louvain community detection: Discovers natural clusters (network segments, application groups, attack clusters)
- Shortest path computation: Enables attack chain visualization between any two entities
- Degree distribution analysis: Flags statistical outliers (nodes with connections far outside the norm)

Implementation: Cypher queries using APOC procedures, triggered by API requests or scheduled jobs.

**Layer 2 -- Behavioral Baselining (Unsupervised ML):**

Builds and maintains behavioral models per entity:

- **Temporal profiles**: Time-series of connection frequency, event rate, relationship count per entity. Models using rolling statistics (mean, stddev, percentiles) or lightweight models (Isolation Forest for multivariate anomaly detection)
- **Neighborhood profiles**: Feature vectors describing each entity's graph neighborhood (who it connects to, how often, through what relationship types). Changes in neighborhood profile indicate behavioral shifts
- **Graph-level baselines**: Global metrics (total nodes, edges, communities, average degree) tracked over time. Sudden changes in global structure indicate environmental events

Anomaly scoring: Each new event is evaluated against the relevant entity's baseline. Deviation produces an anomaly score (0.0 = perfectly normal, 1.0 = unprecedented). Scores above the configurable threshold generate intelligence outputs.

Implementation: scikit-learn models (Isolation Forest, HDBSCAN for evolving clusters), maintained in memory with periodic persistence.

**Layer 3 -- Semantic Enrichment (AI-Assisted):**

Interprets structural and behavioral findings through security domain knowledge:

- Attack chain reconstruction: When a sequence of anomalous relationships forms a path through multiple entities, attempt to classify the pattern against known attack frameworks
- Technique identification: If source events contain technique identifiers (discovered through normal field classification), map graph patterns to the corresponding tactics
- Confidence-weighted recommendations: Combine structural importance (PageRank), behavioral deviation (anomaly score), and semantic context (technique mapping) into prioritized intelligence outputs

Implementation: Initially rule-based pattern matching against graph structures. Evolves toward trained models as feedback loop provides labeled data.

**Feedback Integration:**

Every intelligence output that reaches an analyst generates a feedback opportunity:
- Confirm (correct detection) = positive training signal
- Reject (false positive) = negative training signal
- Modify (partially correct) = nuanced training signal

Feedback is stored with the original intelligence output and used to:
- Adjust anomaly thresholds per entity type
- Refine cluster labeling confidence in the discovery engine
- Train supervised classifiers that complement the unsupervised baseline (Phase 2+)

### 3.5 API Layer

**The Problem:**
Expose all GRASP capabilities through a well-documented, programmatic interface.

**The Approach: FastAPI with Domain-Separated Routers**

**Router Structure:**

```
/api/v1/
    /sources/           - Source registration, profiles, health
    /graph/             - Entity queries, relationship traversal
    /intelligence/      - Anomaly scores, attack chains, recommendations
    /system/            - Health, config, lifecycle status
```

**Design Principles:**
- Async throughout (FastAPI + async Neo4j driver + async ES client)
- Pydantic models for all request/response schemas
- Automatic OpenAPI documentation (no manual swagger maintenance)
- Versioned API (v1 prefix) for future backward compatibility
- Pagination for all list endpoints
- WebSocket endpoints (Phase 3) for real-time intelligence feeds

**Authentication:**
- API key-based authentication for all endpoints
- Keys managed via environment variables
- Rate limiting per key
- Future: OAuth2/OIDC integration for enterprise deployments

---

## 4. Data Flow

### 4.1 Bootstrap Flow (First Connection)

```
1. GRASP starts, reads source configuration from environment
2. For each configured source:
   a. Adapter connects using provided endpoint/credentials
   b. Adapter samples N events (default: 1000)
   c. Discovery engine extracts features from all fields
   d. Discovery engine clusters fields, labels clusters
   e. Discovery engine computes co-occurrence relationships
   f. Source Profile assembled and persisted
   g. Adapter begins continuous streaming
3. Graph engine starts processing events using Source Profiles
4. Intelligence Layer 1 (structural analysis) runs on first graph snapshot
5. Intelligence Layer 2 (behavioral baselining) begins accumulating data
6. API layer serves Source Profiles and initial graph queries
```

### 4.2 Steady-State Flow (Continuous Operation)

```
1. Adapters stream events continuously
2. Each event is processed against its source's current Source Profile
3. Graph engine extracts entities, creates/merges nodes, creates relationships
4. Source Profile is periodically refreshed (detect schema drift, new field types)
5. Intelligence Layer 2 updates baselines, scores new events
6. Anomalies above threshold trigger intelligence outputs
7. Intelligence outputs available via API (and WebSocket in Phase 3)
8. Analyst feedback refines discovery and intelligence models
```

### 4.3 Source Profile Refresh Flow

```
1. Scheduled refresh (configurable interval, default: 1 hour)
2. Discovery engine re-samples from the source
3. Feature extraction on new sample
4. Compare new clustering results with existing Source Profile
5. If significant drift detected:
   a. Log schema drift event
   b. Update Source Profile with new classifications
   c. Retain previous version for comparison
   d. Notify via API (and WebSocket in Phase 3)
6. If no significant drift:
   a. Update confidence scores (more data = higher confidence)
   b. Increment profile revision counter
```

---

## 5. Error Handling Philosophy

### 5.1 Core Principle

**Unknown is not an error. Unexpected is not a failure.**

GRASP operates on data it has never seen from sources it knows nothing about. The normal operating state includes encountering fields it cannot classify, values it cannot parse, and patterns it does not recognize. These are data points, not exceptions.

### 5.2 Error Categories

**Transient Infrastructure Errors:**
- Source connection failures, graph database timeouts, network interruptions
- Handling: Retry with exponential backoff, circuit breaker pattern, health status degradation
- Never: Lose events silently, crash the engine, corrupt the graph

**Data Anomalies:**
- Malformed JSON, unexpected encodings, empty fields, null values
- Handling: Skip the malformed event, increment a counter, log at debug level
- Never: Stop processing, raise an exception to the user, discard the entire batch

**Classification Uncertainty:**
- Fields that don't cluster cleanly, values that match multiple type patterns, low-confidence entity extraction
- Handling: Assign the best-fit classification with a low confidence score, tag as uncertain, include in graph with uncertainty metadata
- Never: Discard uncertain data, force a classification, default to a hardcoded type

**Graph Conflicts:**
- Entity merge conflicts, relationship type disagreements between sources
- Handling: Preserve both perspectives, tag with source attribution, surface the conflict via API
- Never: Silently overwrite one source's data with another's, choose arbitrarily

### 5.3 Observability

Every component emits structured logs (JSON format) with:
- Component identifier
- Operation being performed
- Outcome (success, retry, skip, degrade)
- Relevant metrics (event count, processing time, confidence score)
- Correlation ID for tracing an event through the entire pipeline

---

## 6. Testing Strategy

### 6.1 Unit Testing

**Discovery Engine:**
- Feature extraction produces correct feature vectors for known value types
- Clustering produces stable clusters for well-separated data
- Cluster labeling assigns correct semantic labels for clear clusters
- Unknown clusters are retained and tagged, not discarded

**Graph Engine:**
- Entity extraction using a Source Profile produces correct nodes
- Node merging correctly handles same-source and cross-source scenarios
- Relationship creation follows co-occurrence map from Source Profile
- Lifecycle management correctly transitions data between tiers

**Adapters:**
- Each adapter type correctly implements the interface contract
- Connection handling survives disconnection and reconnection
- Sampling returns well-formed events
- Streaming delivers events in order with correct backpressure

### 6.2 Integration Testing

- End-to-end flow: raw events in, Source Profile out, graph populated, intelligence generated
- Multi-source flow: two different source types producing events about the same entities are correctly merged in the graph
- Schema drift: source changes format mid-stream, discovery engine detects and adapts
- Graph lifecycle: data correctly transitions through hot/warm/cold tiers

### 6.3 Validation Testing

- Adversary simulation: known attack patterns produce detectable graph structures
- Behavioral baseline: normal operation establishes stable baselines, simulated attacks deviate measurably
- Cross-source correlation: the same real-world event visible in multiple sources creates a single, enriched graph representation
- False positive measurement: what percentage of high-anomaly-score events are actual threats vs noise

### 6.4 Chaos Testing

- Source goes offline mid-stream: GRASP degrades gracefully, reconnects, resumes
- Graph database restarts: engine buffers events, replays on reconnection
- Malformed data injection: engine skips bad events without pipeline disruption
- Volume spike: backpressure mechanisms engage without data loss

---

## 7. Project Structure

```
grasp/
    __init__.py
    main.py                          # Application entrypoint
    config.py                        # Environment variable management

    discovery/
        __init__.py
        features.py                  # Field value feature extraction
        clustering.py                # Unsupervised field clustering
        labeling.py                  # Cluster interpretation and labeling
        relationships.py             # Co-occurrence and mutual information analysis
        profile.py                   # Source Profile data model and persistence

    adapters/
        __init__.py
        base.py                      # Abstract adapter interface
        index_poller.py              # Search index adapter
        file_watcher.py              # File-based adapter
        syslog_listener.py           # Syslog adapter

    graph/
        __init__.py
        engine.py                    # Core graph construction logic
        entities.py                  # Entity extraction and node management
        relationships.py             # Relationship creation and edge management
        lifecycle.py                 # Hot/warm/cold tier management
        driver.py                    # Graph database connection management

    intelligence/
        __init__.py
        structural.py                # Layer 1: Graph algorithms
        behavioral.py                # Layer 2: Baselining and anomaly detection
        semantic.py                  # Layer 3: Attack chain and technique mapping
        scoring.py                   # Confidence score computation
        feedback.py                  # Analyst feedback processing

    api/
        __init__.py
        app.py                       # FastAPI application factory
        routers/
            sources.py               # Source management endpoints
            graph.py                 # Graph query endpoints
            intelligence.py          # Intelligence output endpoints
            system.py                # Health and operations endpoints
        models/
            requests.py              # Pydantic request models
            responses.py             # Pydantic response models

    models/
        __init__.py
        events.py                    # Raw event wrapper
        source_profile.py            # Source Profile Pydantic model
        entities.py                  # Entity classification models
        intelligence.py              # Intelligence output models

    utils/
        __init__.py
        logging.py                   # Structured logging configuration
        metrics.py                   # Internal metrics collection
        crypto.py                    # TLS and credential management
```

---

## 8. Deployment Approach

### 8.1 Container Strategy

**GRASP Engine Image:**
- Base: python:3.12-slim
- Non-root user (grasp:grasp)
- Read-only root filesystem
- Writable tmpdir for runtime state
- No shell, no package manager in production build
- Multi-stage Dockerfile: build stage installs dependencies, production stage copies only what's needed

**Graph Database Image:**
- Official vendor image with algorithm plugins pre-installed
- TLS enabled via mounted certificates
- Authentication enforced
- Accessible only within docker-compose internal network

### 8.2 Configuration Strategy

All configuration through a single .env file:
- Source definitions (type, endpoint, credentials)
- Graph database connection
- API settings (port, TLS, authentication)
- Intelligence thresholds
- Lifecycle policies
- Log levels

No configuration files, no YAML, no JSON configs. Environment variables only. This aligns with twelve-factor app principles and ensures every deployment parameter is visible in one place.

### 8.3 Persistence Strategy

**Graph Database Volume:**
- Named Docker volume for graph data
- Survives container restarts and upgrades
- Backup via database-native tools

**GRASP State:**
- Source Profiles persisted to graph database (they are graph metadata)
- ML model state persisted to a dedicated volume
- No critical state in the container filesystem
- Full cold-start capability: if state is lost, GRASP re-discovers and re-learns from live sources

---

## 9. Evolution Strategy

### 9.1 How GRASP Grows

GRASP is designed to evolve along three axes:

**Source Diversity:**
Each new adapter type extends GRASP's reach. The adapter interface is the stable contract -- new adapters implement it without changes to the discovery engine, graph engine, or intelligence layer. The discovery engine automatically handles new data formats through unsupervised classification.

**Intelligence Depth:**
Layer 1 (structural) is immediate. Layer 2 (behavioral) matures over hours and days. Layer 3 (semantic) improves continuously through feedback. Each layer operates independently -- a failure or regression in Layer 3 does not affect Layers 1 and 2.

**Deployment Scale:**
Phase 1 is single-container deployment. Future phases may separate the engine from the graph database, introduce message queues between adapters and the engine, or distribute intelligence computation. The component boundaries in the project structure are designed to support this decomposition without architectural changes.

### 9.2 What We Will Learn

Some decisions in this document are hypotheses, not certainties:

- **HDBSCAN for field clustering**: May need alternative algorithms for certain data distributions. The clustering component is isolated and swappable.
- **Mutual information for relationship inference**: May need supplementary methods (temporal correlation, conditional probability). The relationship component is isolated and extensible.
- **Anomaly thresholds**: The right threshold will vary by deployment. The feedback loop is designed to calibrate this automatically, but initial defaults may need significant tuning.
- **Graph lifecycle tiers**: The 24h/30d boundaries are starting points. Real-world graph growth rates will determine optimal retention policies.

Each hypothesis will be validated against real data during the build process. When evidence contradicts an assumption, the approach document will be revised.

### 9.3 What We Will NOT Change

Some decisions are foundational and will not be revisited:

- Native signal preservation (no normalization)
- Unsupervised discovery as the primary classification mechanism
- Graph-first correlation architecture
- Source-agnostic design (no vendor-specific code outside adapters)
- Zero-hardcode configuration principle
- Production-grade quality standard from day one

---

## 10. Decision Log

A record of significant technical decisions and their rationale.

| Decision | Choice | Rationale | Date |
|----------|--------|-----------|------|
| Core language | Python 3.12 | ML ecosystem, graph database drivers, FastAPI | 2026-02-17 |
| API framework | FastAPI (REST first) | Async-native, auto-docs, minimal overhead | 2026-02-17 |
| GraphQL timing | Phase 2, not Phase 1 | Premature complexity; REST sufficient for initial interface | 2026-02-17 |
| Field classification | Unsupervised ML, not regex ladder | Scalability across unknown source types | 2026-02-17 |
| Normalization | Rejected | Destroys features the ML engine needs for classification | 2026-02-17 |
| Unikernels | Deferred | Python ecosystem incompatibility; Docker provides sufficient isolation | 2026-02-17 |
| Deployment model | Single container + graph DB | Minimize operational complexity for initial adoption | 2026-02-17 |
| Project identity | Standalone sidecar, not platform module | Maximize portability and adoption potential | 2026-02-17 |
| Graph database | Neo4j 5.x-community | Cypher maturity, APOC algorithms, proven scale | 2026-02-17 |

---

*This document evolves with GRASP. Revision history tracks what changed and why.*