# SENTINEL — Session 001 Start Brief

**Date**: 2026-02-24
**Objective**: Corpus characterisation -- all 60 DataFlash BIN files
**Status**: Ready to build

---

## Context for Claude

You are starting Session 001 of SENTINEL, a new sub-project inside the GRASP repository at `grasp/sentinel/`. SENTINEL is a sensor integrity and threat detection engine for autonomous vehicles (UAV/UWV) running on constrained hardware (Raspberry Pi 5 sidecar target).

Read `tools/mavlink/investigate.py` from project knowledge before writing any code. That script is the proven DataFlash binary parser that seeds this session's work. Do not rewrite it -- extend it.

---

## What SENTINEL Is

An onboard threat detection engine that answers one question continuously:

> Is what my sensors are telling me consistent with reality, and if not, is the inconsistency natural or adversarial?

It learns normal from a vehicle's own DataFlash telemetry history (offline, ground pipeline). It detects deviations from that baseline in real time (onboard, vehicle pipeline). No external connectivity. No cloud. No human in the loop during operation.

Full architecture: `sentinel/docs/architecture/SENTINEL_Vision_Architecture_v1.0.md`

---

## What the Corpus Is

- 60 ArduPilot DataFlash `.BIN` files
- Single hexa-quad copter, ArduPilot firmware
- File sizes range from 313 KB to 14,759 KB
- Sessions are known to include: ground-only motor testing, failed arming attempts, GPS errors, compass warnings
- Two files already investigated in GRASP Session 005: `00000028.BIN` (370,015 records, 183 msg types) and `00000029.BIN` (295,080 records, 183 msg types) -- both ground sessions, no GPS fix, motors tested
- All files are on the development machine at `grasp/sentinel/data/*.BIN`
- Multiple parameter configurations possible across the 60 files -- vehicle was tested at different times with different settings

---

## Session 001 Objective

Build `sentinel/tools/corpus_scan.py` -- a corpus characterisation tool that runs against all 60 BIN files in a single pass and produces a structured inventory.

This is the foundation of everything downstream. No baseline model, no detector, no attack signatures can be built without knowing what is in the corpus.

---

## What corpus_scan.py Must Produce

### Per-file structured output (JSON)

```json
{
  "file": "00000028.BIN",
  "size_bytes": 15113188,
  "duration_seconds": 847.3,
  "session_type": "ground",
  "firmware_version": "ArduCopter V4.6.3",
  "gps_state": {
    "fix_acquired": false,
    "nsats_max": 0,
    "hdop_min": 99.99,
    "position_changes": 0
  },
  "arming_events": {
    "count": 2,
    "successful": 2,
    "failed": 0
  },
  "message_types_present": ["IMU", "ATT", "GPS", "BARO", "MAG", "RCIN", "MOTB", "PARM", "ERR", "..."],
  "logging_frequencies": {
    "IMU": 50.2,
    "ATT": 10.1,
    "GPS": 2.0,
    "BARO": 25.0,
    "MAG": 25.0,
    "RCIN": 25.0,
    "MOTB": 25.0
  },
  "parameter_fingerprint": "a3f8c2d1",
  "safety_critical_params": {
    "ARMING_CHECK": 1.0,
    "FS_THR_ENABLE": 1.0,
    "FENCE_ENABLE": 0.0,
    "EKF_TYPE": 3.0
  },
  "anomaly_indicators": {
    "err_count": 0,
    "err_codes": [],
    "gps_glitches": 0,
    "compass_warnings": 0,
    "voltage_alerts": 0,
    "ekf_warnings": 0,
    "arming_failures": 0
  },
  "motor_activity": {
    "max_throttle_out": 0.33,
    "motor_test_detected": true
  },
  "usability_verdict": "clean_baseline",
  "verdict_reasons": []
}
```

### Usability verdicts

| Verdict | Meaning |
|---------|---------|
| `clean_baseline` | No anomaly indicators, GPS state as expected, arming successful -- suitable for baseline training |
| `contains_deviations` | Has ERR messages, GPS glitches, compass warnings or other anomaly indicators -- valuable as labelled deviation data |
| `review` | Ambiguous -- flagged for human review before use |
| `exclude` | Corrupt, zero records, or unreadable |

### Summary table (stdout + summary.json)

```
FILE                SIZE_KB  DURATION_S  TYPE     GPS_FIX  ARMINGS  ERRORS  VERDICT
00000028.BIN        14759    847         ground   no       2        0       clean_baseline
00000029.BIN        11816    712         ground   no       1        3       contains_deviations
00000037.BIN        313      45          ground   no       0        0       review
...

CORPUS SUMMARY
Total files       : 60
Clean baseline    : N
Contains deviations: N
Review            : N
Exclude           : N

Config fingerprints: N distinct configurations
  fingerprint a3f8c2d1: N files
  fingerprint 7b2e9f4a: N files

Logging frequencies (median across clean_baseline files):
  IMU  : XX.X Hz
  ATT  : XX.X Hz
  GPS  : X.X  Hz
  BARO : XX.X Hz
  MAG  : XX.X Hz
  RCIN : XX.X Hz
  MOTB : XX.X Hz
```

---

## How to Measure Logging Frequency

Every DataFlash message that carries sensor data has a `TimeUS` field (microseconds since boot, uint64). Frequency for a message type is measured from the actual data:

```python
# Collect all TimeUS values for a message type across the file
timestamps = [t for t in timeus_values]  # in microseconds
if len(timestamps) > 1:
    intervals = [timestamps[i+1] - timestamps[i] 
                 for i in range(len(timestamps)-1)
                 if timestamps[i+1] > timestamps[i]]
    if intervals:
        median_interval_us = sorted(intervals)[len(intervals)//2]
        frequency_hz = 1_000_000 / median_interval_us
```

Use median, not mean. GPS glitches and logging gaps create outlier intervals that corrupt a mean calculation. Median is robust.

---

## How to Detect Session Type

**Ground session**: GPS Status <= 1 throughout (no fix), altitude change < 2m, flight mode is STABILIZE or LOITER without sustained altitude hold.

**Flight session**: GPS fix acquired (Status >= 3) with NSats > 4, OR sustained altitude change > 5m from BARO, OR flight mode transitions to AUTO/GUIDED/LOITER with altitude hold.

**Unknown**: Does not meet either criterion clearly.

---

## How to Extract Parameter Fingerprint

Safety-critical parameters are those in this set:

```python
SAFETY_CRITICAL_PARAMS = {
    "ARMING_CHECK", "FS_THR_ENABLE", "FS_THR_VALUE",
    "FS_GCS_ENABLE", "FENCE_ENABLE", "FENCE_ACTION",
    "EKF_TYPE", "AHRS_EKF_TYPE",
    "MOT_SPIN_ARM", "MOT_SPIN_MIN",
    "COMPASS_USE", "COMPASS_AUTODEC",
    "GPS_TYPE", "GPS_GNSS_MODE",
    "BARO_PRIMARY", "INS_USE",
}
```

Extract these from PARM messages at the start of each session. Hash the sorted key=value pairs:

```python
import hashlib
param_str = "|".join(f"{k}={v:.4f}" 
                     for k, v in sorted(params.items()) 
                     if k in SAFETY_CRITICAL_PARAMS)
fingerprint = hashlib.sha256(param_str.encode()).hexdigest()[:8]
```

---

## How to Detect Anomaly Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| ERR messages | Any ERR record present -- log SubSys and ECode values |
| GPS glitch | GPS.Status drops from >= 3 to <= 1 after initial fix acquisition |
| Compass warning | ERR record with SubSys=6 (compass) OR XKF4.SS bit 2 set |
| Voltage alert | POWR.Vcc drops below 4.5V OR ERR SubSys=3 |
| EKF warning | XKF4.FS > 0 OR ERR SubSys=8 |
| Arming failure | ERR SubSys=10 (arming) with ECode > 0 |

---

## Session 001 Rules

- Pure Python standard library only -- no numpy, no pandas, no external dependencies
- Single script: `sentinel/tools/corpus_scan.py`
- Runs as: `python3 sentinel/tools/corpus_scan.py --data-dir sentinel/data/`
- Output files written to `sentinel/data/` -- `corpus_inventory.json` (per-file detail) and `corpus_summary.json` (aggregated)
- One artifact, one checkpoint
- Do not start building the baseline model until corpus_scan.py has run against all 60 files and the inventory is reviewed

---

## Relationship to GRASP

SENTINEL is at `grasp/sentinel/`. It may import from `grasp/src/grasp/` if useful but the deployed vehicle pipeline artifact must have zero GRASP dependencies. During the ground pipeline phase (corpus characterisation, baseline model construction) GRASP tools are available and encouraged.

The DataFlash binary parser in `investigate.py` is the proven seed. `corpus_scan.py` extends it -- do not rewrite the binary parsing layer.

---

## Key Questions Session 001 Answers

By the end of Session 001 the following must be known from data, not assumed:

1. How many of the 60 files are clean baseline candidates?
2. How many contain existing anomaly indicators (pre-labelled deviation data)?
3. What are the actual logging frequencies for primary sensor message types?
4. How many distinct vehicle configurations exist in the corpus?
5. What is the typical session duration?
6. Are any files corrupt or unreadable?

These answers drive every downstream design decision.

---

*Session 001: Know your data before you model it.*