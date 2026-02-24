# SENTINEL
## Sensor Integrity Engine for Navigation and Telemetry In Lightweight deployments

### Vision Architecture Document v1.0

**Classification**:  **CONFIDENTIAL**:Internal - Architecture Vision
**Status**: Active
**Date**: 2026-02-24
**Author**: Doc
**Location**: `GRASP/sentinel/docs/architecture/SENTINEL_Vision_Architecture_v1.0.md`

---

## Revision History

| Version | Date | Change Summary |
|---------|------|----------------|
| 1.0 | 2026-02-24 | Initial document. Pivot from GRASP generic platform to focused autonomous vehicle threat detection engine. |

---

## 1. Executive Summary

SENTINEL is an onboard threat detection and sensor integrity engine for autonomous vehicles operating in contested, communications-denied, and adversarially complex environments. Its primary targets are Unmanned Aerial Vehicles (UAV) and Unmanned Underwater Vehicles (UWV).

SENTINEL answers one question continuously during vehicle operation:

> **Is what my sensors are telling me consistent with reality, and if not, is the inconsistency natural or adversarial?**

This is a sensor fusion integrity problem. It is unsolved in the open-source domain. SENTINEL solves it by learning what normal looks like for a specific vehicle from its own telemetry history, then detecting deviations from that baseline in real time -- without external connectivity, without cloud infrastructure, and without a human in the loop.

SENTINEL runs as a sidecar on a companion computer (Raspberry Pi 5 reference target). It consumes raw sensor telemetry from the vehicle's flight controller via MAVLink or DataFlash. It produces an integrity verdict and anomaly classification that the vehicle's autopilot or operator can act on.

---

## 2. The Problem

### 2.1 The Threat Surface

Autonomous vehicles operating in contested environments face adversarial attacks that target their sensor stack rather than their network stack. These attacks are fundamentally different from classical cybersecurity threats:

- They exploit physics, not software vulnerabilities
- They are invisible to conventional intrusion detection systems
- They can be mounted without direct access to the vehicle
- Their effects manifest as plausible but false sensor readings

**Pre-flight attacks** are particularly dangerous because they corrupt the navigation reference before takeoff, causing the vehicle to operate on false assumptions for the entire mission.

**In-flight attacks** require faster detection -- a GPS spoofing attack on a UAV moving at 20 m/s that goes undetected for five seconds results in 100 metres of false navigation.

### 2.2 Known Attack Vectors

| Attack | Target Sensor | DataFlash Signature |
|--------|--------------|---------------------|
| GPS spoofing | GPS | Position jumps, HDop/NSats inconsistency, position vs baro altitude disagreement |
| GPS jamming | GPS | Fix loss (Status drop), NSats=0, sudden HDop spike |
| Compass tampering | MAG | Raw magnetometer values inconsistent with calibration offsets |
| Parameter injection | PARM | Safety-critical parameter values deviating from known-good baseline |
| RC signal injection | RCIN | Unexpected channel values during known-idle periods |
| ESC firmware compromise | MOTB | Motor output curves deviating from learned throttle-response profile |
| IMU spoofing | IMU | Accelerometer/gyro readings inconsistent with attitude estimate |
| Barometer manipulation | BARO | Altitude inconsistent with GPS altitude and climb rate |
| Sensor replay | Any | Implausibly clean or repetitive sensor values |

### 2.3 Why Existing Solutions Fail

Existing flight controller safety systems (Arming Checks, EKF health monitoring, failsafes) detect hardware failures and gross signal loss. They are not designed to detect plausible but false sensor readings -- which is exactly what adversarial attacks produce.

Conventional cybersecurity tools (IDS, SIEM, anomaly detectors) operate on network traffic and discrete events. Sensor fusion integrity requires reasoning about continuous multi-dimensional time series across physically coupled sensors. These are different problem domains.

There is no production-grade, open-source, onboard threat detection system for autonomous vehicles that addresses the sensor fusion integrity problem.

SENTINEL fills that gap.

### 2.4 The UWV Extension

Underwater vehicles face the same problem in a more constrained form. GPS is unavailable at depth. Navigation relies entirely on IMU, DVL (Doppler Velocity Log), pressure sensors, and acoustic positioning. The attack surface shifts accordingly but the detection architecture is identical: learn normal, detect deviation, classify cause.

The same SENTINEL engine, with a different sensor ontology, applies to UWV without architectural changes.

---

## 3. Design Philosophy

### 3.1 Core Principles

**Vehicle-specific baseline.** Normal is learned from this vehicle's own telemetry history. A parameter that is nominal on one vehicle may be anomalous on another. There is no universal normal.

**Cross-sensor consistency as the primary signal.** A single sensor reading in isolation is hard to classify as anomalous. The same reading in context -- inconsistent with what three other physically coupled sensors are saying -- is a strong anomaly signal. SENTINEL's primary detection mechanism is cross-sensor consistency checking, not single-sensor threshold monitoring.

**Adversarial plausibility as the detection target.** Attacks are designed to look plausible. A GPS spoof that produces clearly impossible coordinates will be rejected by the flight controller's existing checks. The dangerous spoof produces coordinates that look real but are false. SENTINEL is specifically designed to detect the plausible-but-false case.

**Air-gap native.** Zero external connectivity required at any point during operation. All learning happens offline on ground hardware. The onboard inference artifact is self-contained. No threat feeds, no cloud calls, no update dependencies during flight.

**Constrained-first design.** Every design decision is evaluated against the target platform constraints: Raspberry Pi 5, ~4GB RAM, quad-core Cortex-A76. If it does not fit there, it does not ship.

**Pre-flight as a first-class threat surface.** Attacks do not require the vehicle to be airborne. GPS spoofing during calibration, parameter injection during configuration, compass tampering during initialisation -- these are high-value attack windows that occur before any in-flight protection is active. SENTINEL detects them.

### 3.2 What SENTINEL Is Not

SENTINEL is not a flight controller. It does not command the vehicle.

SENTINEL is not a network intrusion detection system. It does not inspect network packets.

SENTINEL is not a rule engine. It does not fire alerts based on threshold violations. It learns normal and detects deviations from it.

SENTINEL is not dependent on GRASP infrastructure. It uses GRASP's discovery engine during the offline training phase but the deployed artifact has no GRASP dependency.

---

## 4. Architecture

### 4.1 Two-Phase Design

SENTINEL operates in two distinct phases with different compute environments.

```
+------------------------------------------------------------------+
|  PHASE 1: GROUND PIPELINE  (development machine / server)        |
|                                                                   |
|  DataFlash .BIN corpus                                           |
|         |                                                         |
|         v                                                         |
|  Corpus Characterisation                                         |
|  - Session classification (ground/flight/unknown)                |
|  - Frequency envelope measurement (actual Hz per message type)   |
|  - Parameter fingerprinting (config identity)                    |
|  - Anomaly pre-screening (existing deviations catalogued)        |
|  - Usability verdict per file                                    |
|         |                                                         |
|         v                                                         |
|  Baseline Model Construction                                     |
|  - Normal statistical envelope per message type                  |
|  - Cross-sensor correlation baseline                             |
|  - Arming sequence state machine                                 |
|  - Parameter reference set per config fingerprint               |
|         |                                                         |
|         v                                                         |
|  Attack Signature Library                                        |
|  - Known attack patterns (ATT&CK for ICS + literature)          |
|  - Synthesised attack injections into clean BIN files            |
|  - Detection validation against injected files                   |
|         |                                                         |
|         v                                                         |
|  Model Distillation                                              |
|  - Heavy offline model -> compact onboard artifact               |
|  - vehicle_profile.bin (self-contained, deployable)              |
+------------------------------------------------------------------+
                              |
                              | Deploy
                              v
+------------------------------------------------------------------+
|  PHASE 2: VEHICLE PIPELINE  (Raspberry Pi 5 sidecar)            |
|                                                                   |
|  Live MAVLink / DataFlash stream                                 |
|         |                                                         |
|         v                                                         |
|  Telemetry Ingestion                                             |
|  - MAVLink serial listener                                       |
|  - Message type routing                                          |
|  - Frequency-aware time alignment                                |
|         |                                                         |
|         v                                                         |
|  Lightweight Inference Engine                                    |
|  - Loads vehicle_profile.bin at boot                             |
|  - Runs at sensor rate (not event rate)                          |
|         |                                                         |
|         v                                                         |
|  Cross-Sensor Consistency Checker                               |
|  - Multi-sensor fusion integrity                                 |
|  - Physically impossible combination detection                   |
|  - Temporal consistency validation                               |
|         |                                                         |
|         v                                                         |
|  Anomaly Scorer                                                  |
|  - Deviation from learned baseline                               |
|  - Confidence-weighted anomaly score                             |
|         |                                                         |
|         v                                                         |
|  Attack Classifier                                               |
|  - Pattern matching against attack signature library             |
|  - Named attack classification where signature matches           |
|  - Unknown anomaly flagging where no signature matches           |
|         |                                                         |
|         v                                                         |
|  Response Layer                                                  |
|  - Integrity verdict: NOMINAL / DEGRADED / COMPROMISED           |
|  - Alert to ground station via MAVLink STATUS_TEXT               |
|  - Structured log for post-mission forensic analysis             |
|  - (Future) Autopilot countermeasure trigger                     |
+------------------------------------------------------------------+
```

### 4.2 Sensor Ontology

SENTINEL's attack detection is grounded in the physical relationships between sensors. These relationships are facts about physics, not learned assumptions.

**GPS / Barometer / IMU consistency triangle**

These three sensors are physically coupled. They must agree within known tolerances. Disagreement is always anomalous.

```
GPS altitude  ~=  Barometric altitude  (within ~5m in stable conditions)
GPS velocity  ~=  IMU integrated velocity  (within drift tolerance)
GPS position change rate  ~=  IMU acceleration integral
```

**Compass / EKF consistency**

The Extended Kalman Filter fuses compass, GPS, and IMU. EKF health metrics (XKF messages) are derived from this fusion. Compass tampering manifests as EKF innovation spikes before the flight controller raises a compass health warning.

**Motor / IMU consistency**

Motor commands (RCOU/MOTB) produce predictable attitude changes (ATT/IMU). A vehicle that receives motor commands but does not respond with expected attitude changes indicates either mechanical failure or motor output spoofing.

**RCIN / Mission consistency**

During autonomous missions, RCIN channels should reflect stick positions. Unexpected RCIN values during a known-autonomous phase indicate RC injection.

### 4.3 Frequency Architecture

Different message types log at different rates. The inference engine must handle this correctly.

| Message Group | Typical Rate | Role in Detection |
|---|---|---|
| IMU (accelerometer/gyro) | 50-400 Hz | Fastest ground truth -- attitude and motion |
| ATT (attitude estimate) | 10-50 Hz | EKF output -- derived state |
| MOTB/RCOU (motor output) | 10-25 Hz | Command state |
| BARO (barometric) | 10-25 Hz | Altitude ground truth |
| MAG (magnetometer) | 10-25 Hz | Heading ground truth |
| RCIN (RC input) | 10-25 Hz | Operator/autopilot intent |
| GPS (position fix) | 1-5 Hz | Absolute position -- slowest |
| PARM (parameters) | Once at boot | Configuration state |
| ERR (error events) | On event | Flight controller diagnostics |

Cross-sensor consistency checks operate in windows aligned to the slowest sensor in each comparison pair. GPS/BARO comparison windows at GPS rate (1-5 Hz). IMU/ATT comparison at ATT rate (10-50 Hz).

### 4.4 Vehicle Profile

The vehicle profile is the compiled output of the ground pipeline. It is a single self-contained artifact deployed to the Pi 5.

Contents:

```
vehicle_profile.bin
    vehicle_id:         str    -- unique vehicle identifier
    firmware_version:   str    -- ArduPilot version this profile was trained on
    config_fingerprint: str    -- hash of safety-critical parameter set
    baseline_envelopes: dict   -- per-message-type statistical envelopes
    consistency_rules:  list   -- cross-sensor relationship rules with tolerances
    arming_sequence:    dict   -- expected state machine for pre-flight
    parameter_baseline: dict   -- known-good values for safety-critical parameters
    attack_signatures:  list   -- compact pattern representations
    trained_at:         str    -- ISO timestamp
    training_files:     int    -- number of clean sessions in training corpus
```

### 4.5 Relationship to GRASP

SENTINEL lives inside the GRASP repository at `grasp/sentinel/` and uses GRASP's discovery engine during the ground pipeline phase. Specifically:

- GRASP's DataFlash binary parser (`tools/mavlink/investigate.py`) is the seed for the corpus characterisation tool
- GRASP's field classification engine identifies sensor roles from statistical behaviour without prior schema knowledge
- GRASP's co-occurrence analysis identifies cross-sensor correlations that form the consistency rules

The deployed vehicle pipeline artifact has zero GRASP dependency. It is self-contained Python that runs on the Pi 5 with no external libraries beyond numpy and a compact anomaly scorer.

---

## 5. Validation Strategy

### 5.1 The Inflection Point Gate

SENTINEL does not port to the Pi 5 until three conditions are simultaneously true:

1. **Corpus characterised** -- all BIN files inventoried, clean baseline files identified, frequency envelopes measured
2. **Detector validated** -- synthesised attack injections caught with acceptable detection rate and false positive rate on development hardware
3. **Model compact** -- inference artifact fits within Pi 5 compute and memory budget without optimisation

### 5.2 Validation Phases

**Phase 1 -- Corpus characterisation** (development machine)

All 60 BIN files scanned. Structured inventory produced. Clean baseline files identified. Deviation files catalogued. Frequency envelopes measured from actual TimeUS timestamps.

**Phase 2 -- Baseline model construction** (development machine)

Statistical envelopes learned from clean sessions. Cross-sensor correlation baselines computed. Arming sequence state machine extracted. Parameter reference set per config fingerprint.

**Phase 3 -- Attack synthesis and detection validation** (development machine)

Five known pre-flight attack patterns synthesised by injecting anomalous values into copies of clean BIN files. Detector run against injected files. Detection rate, false positive rate, and detection latency measured and reported.

**Phase 4 -- Pi 5 port** (Raspberry Pi 5)

Inference engine deployed to Pi 5. Connected to live MAVLink stream during pre-flight. Detector response observed against real pre-flight sensor data.

**Phase 5 -- Real pre-flight validation** (Raspberry Pi 5 + vehicle)

Normal pre-flight session with detector running live. False positives from real-world noise identified and used to refine model. Production-ready baseline model produced.

### 5.3 First Five Attack Signatures (Phase 3 targets)

| Attack | Injection Method | Detection Mechanism |
|--------|-----------------|---------------------|
| GPS position spoof | Inject implausible Lat/Lng into GPS messages | GPS/BARO altitude divergence + position jump rate |
| GPS fix spoof | Inject NSats>4 with HDop inconsistency | NSats/HDop/Status relationship violation |
| Parameter injection | Modify ARMING_CHECK or FS_THR_ENABLE in PARM | Parameter value deviates from config fingerprint baseline |
| Compass offset tamper | Inject COMPASS_OFS inconsistent with MAG raw | MAG raw vs calibration offset consistency rule |
| RC injection | Inject RCIN values during known-idle motor test | RCIN activity during zero-throttle ground idle |

---

## 6. Repository Structure

```
grasp/
    sentinel/
        docs/
            architecture/
                SENTINEL_Vision_Architecture_v1.0.md  -- this document
            development/
                session_001_summary.md                -- corpus characterisation
        tools/
            corpus_scan.py      -- extended from GRASP investigate.py
        src/
            sentinel/
                baseline/       -- baseline model construction
                detector/       -- anomaly detection engine
                classifier/     -- attack signature matching
                response/       -- alert and logging layer
                vehicle/        -- vehicle profile read/write
        data/
            *.BIN               -- DataFlash files (gitignored)
            corpus_inventory.json   -- output of corpus_scan.py
        models/
            vehicle_profile.bin -- compiled onboard artifact (gitignored)
        tests/
            corpus/
            baseline/
            detector/
```

---

## 7. Technology Constraints

### 7.1 Ground Pipeline (no constraints)

Python 3.12, scikit-learn, numpy, scipy. Full GRASP toolchain available. Runs on thunderbolt VM or any development machine.

### 7.2 Vehicle Pipeline (Pi 5 constrained)

| Constraint | Budget | Rationale |
|---|---|---|
| RAM | < 256 MB | Leave headroom for OS and MAVLink stack |
| CPU | < 25% single core | One core reserved for MAVLink comms |
| Inference latency | < 500ms per cycle | Faster than any meaningful attack window |
| Startup time | < 10s | Must be active before arming sequence begins |
| Dependencies | numpy only | No sklearn, no graph database, no network |
| Storage | < 10 MB for vehicle_profile.bin | SD card friendly |

### 7.3 Language

Python 3.11+ on Pi 5 (Raspberry Pi OS). No compilation step. No cross-compilation. Direct deployment of Python source plus compiled vehicle profile artifact.

---

## 8. Attack Taxonomy Reference

Primary reference: MITRE ATT&CK for ICS (https://attack.mitre.org/matrices/ics/)

Relevant technique families for autonomous vehicle sensor attacks:

- **T0830** -- Adversarial Spoofing (sensor spoofing)
- **T0831** -- Manipulation of Control (parameter injection)
- **T0832** -- Manipulation of View (sensor data manipulation)
- **T0840** -- Network Connection Enumeration (RF reconnaissance pre-attack)
- **T0856** -- Spoof Reporting Message (telemetry replay)
- **T0857** -- System Firmware (ESC firmware compromise)

Secondary reference: Academic literature on UAV adversarial attacks, FAA UAV threat framework, CISA guidance on unmanned systems security.

---

## 9. Open Questions for Session 001

1. What is the distribution of session types across the 60 BIN files -- how many are ground-only versus potential flight sessions?
2. What actual logging frequencies are present in the corpus -- are IMU messages logged at 50Hz, 100Hz, or 400Hz?
3. How many distinct configuration fingerprints exist across the 60 files -- is this one consistent vehicle config or multiple?
4. How many files contain existing anomaly indicators (ERR messages, GPS glitches, compass warnings) that qualify as pre-labelled deviation data?
5. What is the typical session duration -- seconds, minutes, or longer?

These questions are answered by the corpus characterisation tool built in Session 001. No design decisions that depend on these answers should be made before that tool runs.

---

## 10. Success Criteria

**Phase 1 complete** when: structured inventory of all 60 BIN files exists, at least 10 clean baseline files identified, frequency envelopes known for all primary message types.

**Phase 2 complete** when: baseline model trained, cross-sensor consistency rules defined, arming sequence state machine extracted, parameter reference set populated.

**Phase 3 complete** when: all five synthesised attack patterns detected with >90% detection rate and <5% false positive rate on held-out clean files.

**Inflection point reached** when: Phases 1-3 complete AND inference artifact is under 10MB AND runs on Pi 5 within compute budget.

**Phase 4 complete** when: Pi 5 deployment runs without error against live MAVLink stream during a real pre-flight session.

**Phase 5 complete** when: false positive rate on real pre-flight data is <10% without further tuning, confirming the model is production-ready for the ground operation threat surface.

---

*SENTINEL v1.0: From sensor telemetry to adversarial awareness -- onboard, offline, autonomous.*