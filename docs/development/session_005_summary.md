# GRASP - Session 005 Summary

**Date**: 2026-02-23
**Duration**: Extended session (architecture evolution + UAV data investigation)
**Status**: Complete

---

## Session Narrative

This session began with a review of the trainable classifier design from Session 004 and evolved into a fundamental re-examination of what GRASP is and what it should become. The session produced the Vision Architecture Document v2.0, a validated UAV data investigation, and a fully specified design for the per-source classifier engine to be built in Session 006.

The conversation progressed through several key inflection points:

1. **Classifier design review** -- the RandomForest trainable classifier design was examined against the Vision Architecture Document v1.0, revealing a core tension: training on Wazuh corrections would embed source-specific bias into a system designed to be source-agnostic

2. **The blindfold question** -- the critical insight that today's Wazuh-ES data is tomorrow's Kafka stream, CSV, database, or MAVLink binary, and in an air-gapped environment. A global classifier violates the source-agnostic principle through the back door

3. **Platform identity shift** -- recognition that GRASP is not a security tool with good engineering. It is a domain-agnostic Intelligent Data Attribution platform that security was the first customer of. The security framing limits the addressable market unnecessarily

4. **UAV domain validation** -- two hexa-quad copters with Pixhawk flight controllers, HackRF SDR, and 194MB of DataFlash binary logs were identified as the second validation domain. The geopolitical urgency of UAV adversarial detection (GPS spoofing, RF jamming) was assessed as a commercially and strategically pressing problem

5. **Binary data investigation** -- a pure standard-library Python investigation script was written and run against two ArduPilot DataFlash `.BIN` files (00000028.BIN, 00000029.BIN). Both files were parsed successfully: 183 message types, 1,574 fields, 665,095 total records, zero parse errors. Both sessions confirmed as ground sessions with no GPS fix, motors tested but no flight

6. **Vision Architecture Document v2.0** -- the vision doc was rewritten to reflect the platform identity, domain-agnostic framing, per-source model architecture, Domain Pack concept, and UAV as the second validated domain

7. **Per-source classifier architecture** -- the classifier engine was fully designed as a separate `src/grasp/classifier/` package (Option B), with storage strategy, volume design, and the five-checkpoint build plan agreed

8. **Source validation sequence** -- Wazuh-ES → Suricata eve.json → Fortinet syslog → MAVLink DataFlash. Each source tests a different transport type and format before the domain jump to UAV

---

## Key Decisions Made This Session

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Platform identity | Intelligent Data Attribution platform | Security framing limits addressable market; same engine applies universally |
| Classifier scope | Per-source, not global | Global classifier smuggles source bias; per-source is epistemically honest |
| Cross-source contamination | Explicitly prohibited | Wazuh corrections must never influence MAVLink classification |
| Air-gap posture | First-class, not afterthought | Defence and critical infrastructure are highest-value markets; cloud dependency disqualifies |
| Classifier package | Option B -- separate `src/grasp/classifier/` package | Cleaner boundary; independently testable; Domain Pack extensible |
| Storage granularity | Feature vectors, not raw events | 27 floats per field vs kilobytes per event; source not required at retrain time |
| Volume strategy | Three separate volumes -- models, feedback, samples | Different backup priority and retention policy per concern |
| Correction record | References feature vector ID, not inline vector | Decouples corrections from raw data; enables offline retraining |
| Bootstrap data | Lives in Domain Packs, not in core | Core stays domain-blind; packs carry domain-specific knowledge |
| Source ID (PoC) | Plain string, caller-supplied | Operational complexity deferred; engine logic is the priority |
| Source validation sequence | Wazuh → Suricata → Fortinet → MAVLink | Tests transport and format variety before domain jump |
| registry.py | Deferred | Not needed until multi-source enumeration is required |
| Vision doc version | v2.0 | Scope change is fundamental, not incremental |

---

## Artefacts Produced This Session

| Artefact | Path | Status |
|----------|------|--------|
| DataFlash investigation script | `tools/mavlink/investigate.py` | Complete, validated |
| DataFlash investigation report | `tools/mavlink/investigation_report.txt` | Complete -- 665,095 records analysed |
| Vision Architecture Document v2.0 | `docs/architecture/Vision_Arch_Doc.md` | Complete -- replace v1.0 |
| Session summary | `docs/development/session_005_summary.md` | This document |

---

## UAV Data Investigation Findings

### Files Investigated
| File | Size | Records | Message Types | Fields Defined |
|------|------|---------|---------------|----------------|
| 00000028.BIN | 15,113,188 bytes | 370,015 | 59 | 1,574 |
| 00000029.BIN | 12,100,230 bytes | 295,080 | 60 | 1,574 |

### Session Characteristics
- Firmware: ArduCopter V4.6.3 (92b0cd78) -- same build on both files
- Both sessions: ground only, no flight, no GPS fix (Status=1, NSats=0, HDop=99.99)
- Motor activity: MOTB.ThrOut range 0.0--0.33, consistent with motor testing
- Flight mode: STABILIZE (Mode=0) throughout both sessions
- One difference: 00000029.BIN contains 3 ERR records absent from 00000028.BIN

### Pre-Analysis: What GRASP Should Classify Correctly (No Changes)
| Field(s) | Expected Class | Basis |
|----------|---------------|-------|
| TimeUS (all messages) | TEMPORAL | uint64, monotonically increasing, 500 unique |
| GyrX, GyrY, GyrZ | METRIC | float32, 500 unique, bounded symmetric range |
| AccX, AccY, AccZ | METRIC | float32, 500 unique, gravity-centred range |
| BARO pressure/altitude | METRIC | float32, continuous, bounded |
| MODE.Mode | ENUM | 1 unique value throughout |
| GPS.Status, GPS.NSats | ENUM | 1--2 unique values |
| MSG.Message | TEXT | char[64], natural language content |
| PARM.Name | ENTITY | char[16], 500 unique structured identifiers |

### Pre-Analysis: Where GRASP Will Struggle (Gap = Domain Pack Requirement)
| Field(s) | Likely Classification | Correct Classification | Gap |
|----------|----------------------|----------------------|-----|
| GPS.Lat, GPS.Lng | METRIC | ENTITY with hint=gps_coord | No GPS coordinate TypeHint in Security Pack |
| GPS.GWk | ENUM | TEMPORAL context | GPS week is time, not category |
| RCIN/RCOU channels | METRIC | METRIC (correct) but causal relationship missed | Control signal semantics not discoverable from values alone |
| VIBE.VibeX/Y/Z + RCOU | Independent METRIC | Co-occurrence relationship: DRIVES | Vibration-throttle causality is a Domain Pack relationship hint |
| PARM.Value | UNKNOWN or METRIC | Mixed (by design) | Spans 8 orders of magnitude -- classifier will be uncertain |

These gaps define the UAV Domain Pack specification. They are not core engine failures -- they are domain knowledge that belongs in the pack layer.

---

## Classifier Engine Design (Session 006 Build Target)

### Package Structure
```
src/grasp/classifier/
    __init__.py
    base.py              -- AbstractClassifier interface
    random_forest.py     -- SourceClassifier (RandomForest implementation)
    feedback.py          -- FeedbackStore (per-source JSONL corrections)
    training.py          -- BootstrapData (synthetic examples via extract_features())
```

### Volume Structure
```
/data/
    models/              -- GRASP_MODEL_BASE_PATH
        classifier_wazuh.joblib
        classifier_suricata.joblib
        classifier_mavlink.joblib
    feedback/            -- GRASP_FEEDBACK_BASE_PATH
        corrections_wazuh.jsonl
        corrections_suricata.jsonl
        corrections_mavlink.jsonl
    samples/             -- GRASP_SAMPLES_BASE_PATH
        features_wazuh.jsonl
        features_suricata.jsonl
        features_mavlink.jsonl
```

### Correction Record Schema
```json
{
    "source_id": "wazuh",
    "field_path": "agent.ip",
    "feature_vector_id": "wazuh_abc123",
    "correct_label": "entity",
    "type_hint": "ipv4",
    "original_label": "unknown",
    "original_confidence": 0.41,
    "timestamp": "2026-02-23T10:00:00Z"
}
```

### Integration Point in clustering.py
```python
classifier = SourceClassifier(source_id=source_id)
result = classifier.predict(feat)
if result is None:
    # cold start or below confidence threshold -- heuristic fallback
    fc, is_entity = _classify_from_features(feat)
    confidence = 0.5
else:
    fc, is_entity, confidence = result
```

The heuristic is a permanent fallback, not a temporary scaffold.

### Source Validation Sequence
| Order | Source ID | Transport | Format | Purpose |
|-------|-----------|-----------|--------|---------|
| 1 | wazuh | ES Index Poller | JSON | Baseline -- 15 runs of ground truth available |
| 2 | suricata | File Watcher | JSONL (eve.json) | Different transport, network vs host events |
| 3 | fortinet | Syslog Listener | key=value | Different transport, different format entirely |
| 4 | mavlink | DataFlash Reader | Binary | Different domain -- proves domain isolation |

### Wazuh Bootstrap Ground Truth (from runs 9--15)
| Field Pattern | Correct Label | Type Hint |
|---------------|--------------|-----------|
| agent.ip, data.srcip, data.dstip | ENTITY | ipv4 |
| @timestamp, data.win.system.systemTime | TEMPORAL | -- |
| syscheck.md5_after, syscheck.md5_before | ENTITY | hash_md5 |
| syscheck.sha1_after, syscheck.sha1_before | ENTITY | hash_sha1 |
| syscheck.sha256_after, syscheck.sha256_before | ENTITY | hash_sha256 |
| rule.level, data.win.system.eventID | METRIC | -- |
| rule.groups.*, decoder.name | ENUM | -- |
| full_log, data.win.system.message | TEXT | -- |
| rule.mitre_techniques.* | ENTITY | -- |
| agent.name, predecoder.hostname | ENTITY | fqdn |

---

## Build Sequence for Session 006

Five checkpoints, one artifact per checkpoint, Go/No-Go between each:

| Checkpoint | File | Validates |
|------------|------|-----------|
| 1 | `src/grasp/classifier/base.py` | Abstract interface -- the algorithm swap boundary |
| 2 | `src/grasp/classifier/feedback.py` | FeedbackStore -- append, load, count, validate schema |
| 3 | `src/grasp/classifier/training.py` | BootstrapData -- calls real extract_features(), Wazuh domain first |
| 4 | `src/grasp/classifier/random_forest.py` | SourceClassifier -- train, predict, persist, cold-start fallback |
| 5 | `src/grasp/discovery/clustering.py` patch | Integration -- classifier replaces direct heuristic call with fallback |

### Testing Strategy
Each checkpoint includes a paired test in `tests/classifier/`:

| Test File | Covers |
|-----------|--------|
| `test_base.py` | Interface contract -- all implementations satisfy abstract methods |
| `test_feedback.py` | Append correction, load corrections, count by label, reject invalid schema |
| `test_training.py` | Bootstrap produces valid feature vectors, correct labels, calls real extract_features |
| `test_random_forest.py` | Cold start returns None, trains from bootstrap, predict returns (class, bool, float), persists and loads, retrains on corrections |
| `test_clustering_integration.py` | Classifier result used when confident, heuristic used when cold, confidence threshold respected |

Backend validation before any API work:
```bash
# After Checkpoint 4 -- run directly, no API needed
python3 -c "
from grasp.classifier.random_forest import SourceClassifier
from grasp.classifier.training import BootstrapData

clf = SourceClassifier(source_id='wazuh')
clf.train(BootstrapData.for_source('wazuh'))
print(clf.stats())
"
```

---

## Open Questions for Session 006

1. **Minimum corrections before retraining is meaningful** -- what is the floor? 10 corrections? 50? Below this floor the RF will overfit to noise. Needs a configurable `GRASP_CLASSIFIER_MIN_CORRECTIONS` env var with a sensible default.

2. **Feature vector ID generation** -- the correction record references a `feature_vector_id`. How is this ID generated? Hash of (source_id + field_path + feature_vector)? Needs to be deterministic so the same field sampled twice produces the same ID.

3. **Confidence threshold behaviour** -- below `GRASP_CLASSIFIER_CONFIDENCE_THRESHOLD` (default 0.6), the classifier returns None and the heuristic takes over. Should low-confidence predictions still be logged to the samples store so an analyst can review them? Likely yes -- they are the highest-value correction candidates.

4. **Retraining trigger** -- on-demand only for PoC (explicit API call or CLI). Periodic scheduler deferred. Confirm this is acceptable for Session 006 scope.

5. **Suricata eve.json availability** -- is the file live (being written by a running Suricata instance) or static (a captured file)? Determines whether the File Watcher adapter needs live-tail or single-pass read for initial validation.

---

## Infrastructure State at Session End

### GRASP Repository
```
Branch: main
New files this session:
  tools/mavlink/investigate.py          (complete)
  tools/mavlink/investigation_report.txt (complete, gitignored with .BIN files)
Pending commit:
  docs/architecture/Vision_Arch_Doc.md  (v2.0 -- replace v1.0)
  docs/development/session_005_summary.md (this file)
```

### Suggested Commit Message
```
docs: Vision Architecture Document v2.0 + Session 005 summary

Expand GRASP from security-focused tool to domain-agnostic Intelligent
Data Attribution platform. Key changes:

- Platform identity: security is first customer, not the product
- Per-source model architecture: no classifier crosses source boundaries
- Domain Pack concept: core stays domain-blind, packs carry domain knowledge
- UAV validated as second domain: ArduPilot DataFlash investigation complete
- Air-gap as first-class deployment mode
- Three-layer architecture: Adapter / Core / Domain Pack
- Classifier engine design complete: ready to build in Session 006

Artefacts: Vision_Arch_Doc.md v2.0, investigate.py, investigation_report.txt
```

### DataFlash Files
```
tools/mavlink/00000028.BIN   15,113,188 bytes  (gitignored)
tools/mavlink/00000029.BIN   12,100,230 bytes  (gitignored)
tools/mavlink/investigation_report.txt         (gitignored with .BIN)
```

Note: Consider adding `investigation_report.txt` to git tracking separately
from the .BIN files -- it is a derived artefact with no sensitive content
and has value as session documentation.

---

*Session 005: From a security classifier to a platform that thinks in relationships across any domain.*