# GRASP - Session 006 Summary

**Date**: 2026-02-23
**Duration**: Extended session (classifier engine build + live validation)
**Status**: Complete

---

## Session Narrative

This session built the per-source trainable classifier engine designed in Session 005 and validated it against live Wazuh-ES telemetry. The session progressed through five incremental checkpoints, each validated inside the Docker container before proceeding. Two infrastructure issues were encountered and resolved along the way.

The session progressed through several key inflection points:

1. **Open questions resolved** -- five design questions left open at the end of Session 005 were answered before any code was written: minimum corrections floor (10), feature vector ID strategy (sha256 hash), low-confidence logging (yes, flagged for review), retraining trigger (on-demand CLI only), and Suricata source (eve.json raw, no filtering)

2. **CP1: Abstract interface** -- `src/grasp/classifier/base.py` and `__init__.py` created. `AbstractClassifier`, `ClassifierResult`, and `TrainingRecord` dataclasses defined. Five new config properties added to `config.py` and `.env`

3. **CP2: FeedbackStore** -- `src/grasp/classifier/feedback.py` built. Volume permission issue surfaced: named Docker volumes mount as root-owned, blocking the non-root `grasp` user. Fixed by pre-creating `/data` subdirectories with correct ownership in the Dockerfile before the `USER grasp` switch

4. **CP3: BootstrapData** -- `src/grasp/classifier/training.py` built. Wazuh ground truth from runs 9-15 encoded as real `extract_features()` calls against curated sample values. No synthetic vectors

5. **CP4: SourceClassifier** -- `src/grasp/classifier/random_forest.py` built. Cold start returns None, bootstrap sets status to `bootstrapping`, retrain enforces the corrections floor, persist/load via joblib confirmed deterministic

6. **CP5: clustering.py integration** -- circular import discovered between `clustering.py` and `random_forest.py`. Resolved by moving the `SourceClassifier` import inside `load_classifier()` function body rather than at module level. `_classify_from_features` renamed to `_heuristic_classify` to align with test expectations

7. **Live validation** -- `tools/classifier_live_test.py` written, connecting the full pipeline: IndexPollerAdapter → collect_field_values → extract_features → cluster_fields with classifier active → classification report. Run logs persisted to `/data/classifier_runs/` via the named volume

8. **First live run result** -- 84% ground truth accuracy on first run from bootstrap alone. 25/195 fields decided by classifier, 170 by heuristic. All 25 classifier decisions correct. 3 heuristic errors identified

---

## Key Decisions Made This Session

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Min corrections floor | 10 | Below 10, RandomForest memorises rather than generalises |
| Feature vector ID | `sha256(source_id:field_path:vector)[:16]` | Deterministic, verifiable, same field sampled twice produces same ID |
| Low-confidence logging | Yes, `flagged_for_review: true` | Highest-value correction candidates should be surfaced to analyst |
| Retraining trigger | On-demand CLI only for PoC | No scheduler complexity in Session 006 scope |
| Suricata source | `eve.json` raw, no pre-filtering | Source-agnostic principle -- classifier handles all event types |
| Volume ownership | Pre-create `/data` dirs in Dockerfile before `USER grasp` | Named volumes inherit directory ownership set at image build time |
| Circular import fix | Local import inside `load_classifier()` | Breaks the cycle without restructuring the package |
| Run log location | `/data/classifier_runs/` | Named volume is writable by grasp user; bind-mounted `tools/` is not |
| `tools/` mount | Read-write bind mount | Scripts and run outputs need to persist back to host |

---

## Artefacts Produced This Session

| Artefact | Path | Status |
|----------|------|--------|
| Abstract classifier interface | `src/grasp/classifier/base.py` | Complete |
| Package marker | `src/grasp/classifier/__init__.py` | Complete |
| Feedback store | `src/grasp/classifier/feedback.py` | Complete |
| Bootstrap training data | `src/grasp/classifier/training.py` | Complete -- Wazuh ground truth |
| RandomForest classifier | `src/grasp/classifier/random_forest.py` | Complete |
| clustering.py patch | `src/grasp/discovery/clustering.py` | Complete -- classifier integrated |
| Live validation script | `tools/classifier_live_test.py` | Complete |
| Dockerfile update | `docker/grasp/Dockerfile` | `/data` subdirs with correct ownership |
| docker-compose update | `docker-compose.yml` | `grasp-data` volume + `tools/` mount |
| Config update | `src/grasp/config.py` + `.env` | 5 new classifier env vars |

---

## Live Run 1 Results (run_20260223_090144_wazuh)

```
Sample        : 1000 events
Fields found  : 359 unique paths
Fields scored : 195 (>= 10 non-null values)
Classifier    : 25 fields decided (all correct)
Heuristic     : 170 fields decided
Flagged       : 0
Ground truth  : 16/19 correct (84%)
```

### Correctly Classified (classifier)
`agent.ip`, `syscheck.md5_after/before`, `syscheck.sha1_after/before`,
`syscheck.sha256_after/before`, `@timestamp`, `rule.level`,
`data.win.system.eventID`, `decoder.name`

### Heuristic Errors (3 fields -- correction candidates)

| Field | Predicted | Expected | Root Cause |
|-------|-----------|----------|------------|
| `full_log` | entity | text | Long strings score high on entity heuristic |
| `agent.name` | enum | entity | Low-cardinality hostnames mis-routed to enum |
| `predecoder.hostname` | enum | entity | Same as agent.name -- few unique values in 1000-event sample |

### Additional Observations from Sample Evidence

`syscheck.gid_after` / `syscheck.uid_after` → UNKNOWN (correct behaviour)
```
samples: 103 | 900 | 988 | S-1-5-18 | 111
```
Mixed Linux UIDs (integers) and Windows SIDs (strings) in the same field.
Classifier correctly abstains. These are entity candidates but statistically
ambiguous -- correction needed to add them.

`data.win.system.providerGuid` → enum (should be entity)
```
samples: {0d4fdc09-8c27-494a-bda0-505e4fd8adae} | {fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}
```
UUIDs with low cardinality in this sample routed to enum. Type hint regex
would catch these as UUIDs if classifier were activating. Correction candidate.

`agent.name` / `predecoder.hostname` → enum (small lab limitation)
```
samples: wazuh-aio | dvwa | AD | metasploitable3 | openvas-agent  (5 unique)
samples: dvwasrv | openvas | wazuh-aio  (3 unique)
```
Low cardinality is a lab environment artefact -- only 5 machines. Bootstrap
correction is correct but behaviour will vary by deployment size. Worth noting
in ground truth table.

---

## Infrastructure State at Session End

### GRASP Repository
```
Branch: main
New files this session:
  src/grasp/classifier/__init__.py
  src/grasp/classifier/base.py
  src/grasp/classifier/feedback.py
  src/grasp/classifier/training.py
  src/grasp/classifier/random_forest.py
  tools/classifier_live_test.py
Modified files:
  src/grasp/discovery/clustering.py   (classifier integration + rename)
  src/grasp/config.py                 (5 new classifier properties)
  docker/grasp/Dockerfile             (/data subdirs + ownership)
  docker-compose.yml                  (grasp-data volume + tools mount)
  .env                                (5 new classifier vars)
Run logs (gitignored via /data/):
  /data/classifier_runs/run_20260223_090144_wazuh.txt
```

### Suggested Commit Message
```
feat: per-source trainable classifier engine (Session 006)

Add src/grasp/classifier/ package:
- base.py: AbstractClassifier interface + ClassifierResult + TrainingRecord
- feedback.py: FeedbackStore -- per-source JSONL corrections with schema validation
- training.py: BootstrapData -- Wazuh ground truth from runs 9-15 via real extract_features()
- random_forest.py: SourceClassifier -- train, predict, persist, cold-start, retrain floor

Patch src/grasp/discovery/clustering.py:
- Rename _classify_from_features to _heuristic_classify (test alignment)
- Add source_id parameter to cluster_fields()
- Integrate per-source classifier with permanent heuristic fallback
- Add load_classifier() and register_classifier() cache helpers
- Fix circular import: SourceClassifier import moved inside load_classifier()

Infrastructure:
- Dockerfile: create /data subdirs with grasp ownership before USER switch
- docker-compose.yml: mount grasp-data named volume at /data + tools bind mount
- .env + config.py: five new classifier env vars

Tools:
- classifier_live_test.py: live validation script with regression run logging

Live validation: 84% ground truth accuracy from bootstrap alone.
No classifier crosses source boundaries.
```

---

## Open Questions for Session 007

1. **Sample values in run report** -- confirmed working in run_20260223_095449. Each field displays up to 5 sample values providing evidence for every classification decision

2. **Bootstrap expansion** -- `full_log`, `agent.name`, and `predecoder.hostname` are confirmed heuristic errors. Add them to `training.py` bootstrap ground truth and re-run to confirm improvement

3. **Heuristic coverage gap** -- 170/195 fields decided by heuristic. Many are classifiable (`data.win.eventdata.*`, `syscheck.*`, `rule.*` patterns). Expanding bootstrap to cover these families will push classifier coverage significantly higher

4. **Retraining CLI** -- `python3 -m grasp.classifier.retrain --source wazuh` was agreed in Session 005 but not built. Needed before corrections can be applied operationally

5. **`data.win.system.systemTime`** -- appeared as `temporal` with heuristic (conf=0.500) in the live run. Was in the bootstrap ground truth table but not appearing as a classifier decision. Investigate why the classifier did not activate on this field

---

## Build Sequence for Session 007

| Priority | Task | Purpose |
|----------|------|---------|
| 1 | Fix sample values display in run report | Complete the live validation tool |
| 2 | Add 3 corrections to bootstrap + re-run | Confirm 100% ground truth on known fields |
| 3 | Expand bootstrap coverage for `data.win.*` and `syscheck.*` | Push classifier coverage above 50% |
| 4 | Build retraining CLI | Enable operational corrections workflow |
| 5 | Run against Suricata eve.json | Second source validation -- proves source isolation |

---

*Session 006: Bootstrap accuracy 84%. Classifier activating. Heuristic gaps mapped. Ready to improve.*