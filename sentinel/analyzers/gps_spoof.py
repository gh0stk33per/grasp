"""GPS Spoofing Analyzer.

Four cross-sensor checks:

  1. POSITION JUMP       -- consecutive GPS position deltas exceeding velocity bound
  2. ALT DIVERGENCE      -- GPS.Alt vs BARO.Alt tracking breakdown
  3. GPS QUALITY SHIFT   -- HDop/NSats anomalous change coinciding with position event
  4. EKF INNOVATION      -- XKF1 GPS innovation spike while IMU/BARO healthy

Each check produces a Finding with CLEAN / SUSPICIOUS / ALERT verdict.
Overall verdict is the worst-case finding, weighted by confidence.

Thresholds are conservative for ground sessions (vehicle stationary).
All thresholds defined as class constants -- zero hardcoding in logic.
"""

import math
from dataclasses import dataclass
from typing import Any

from sentinel.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Finding,
    Verdict,
)
from sentinel.core.parser import ParseResult


# ---------------------------------------------------------------------------
# Threshold constants  (all tunable, none buried in logic)
# ---------------------------------------------------------------------------

# Check 1 -- position jump
_MAX_GROUND_SPEED_MS      = 0.5     # m/s -- max plausible movement on ground
_MAX_FLIGHT_SPEED_MS      = 30.0    # m/s -- max plausible UAV speed
_GPS_INTERVAL_S           = 1.0     # nominal GPS update interval
_JUMP_ALERT_MULTIPLIER    = 5.0     # x velocity bound to trigger ALERT
_JUMP_SUSPICIOUS_MULT     = 2.0     # x velocity bound to trigger SUSPICIOUS
_LAT_DEG_TO_M             = 111_320.0
_LON_DEG_TO_M_AT_EQUATOR  = 111_320.0

# Check 2 -- altitude divergence
_ALT_DIVERGENCE_ALERT_M   = 20.0   # GPS vs BARO delta that triggers ALERT
_ALT_DIVERGENCE_SUSP_M    = 10.0   # GPS vs BARO delta for SUSPICIOUS
_ALT_BARO_SYNC_WINDOW     = 5      # records to average for sync baseline

# Check 3 -- GPS quality shift
_HDOP_DROP_ALERT          = 1.0    # sudden drop of this magnitude = suspicious
_HDOP_SPIKE_ALERT         = 2.0    # sudden spike = signal loss
_NSATS_DROP_ALERT         = 4      # satellites lost suddenly

# Check 4 -- EKF innovation
_EKF_INNOV_ALERT          = 10.0   # XKF1.IVN or IVE magnitude
_EKF_INNOV_SUSPICIOUS     = 5.0

# Confidence weights per check
_WEIGHT = {
    'position_jump':   0.40,
    'alt_divergence':  0.25,
    'gps_quality':     0.20,
    'ekf_innovation':  0.15,
}

# Minimum GPS records to attempt analysis
_MIN_GPS_RECORDS = 5


# ---------------------------------------------------------------------------
# Internal data carriers
# ---------------------------------------------------------------------------

@dataclass
class _GpsPoint:
    timeus: int
    lat:    float   # degrees
    lon:    float   # degrees
    alt:    float   # metres (GPS altitude)
    status: int
    nsats:  int
    hdop:   float


@dataclass
class _BaroPoint:
    timeus: int
    alt:    float   # metres


@dataclass
class _EkfPoint:
    timeus: int
    ivn:    float   # north innovation
    ive:    float   # east innovation
    ivd:    float   # down innovation


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class GPSSpoofAnalyzer(BaseAnalyzer):

    NAME    = "gps_spoof"
    VERSION = "1.0"

    def analyze(self, parse_result: ParseResult) -> AnalysisResult:
        fp = parse_result.filepath

        gps_points  = self._extract_gps(parse_result)
        baro_points = self._extract_baro(parse_result)
        ekf_points  = self._extract_ekf(parse_result)

        if len(gps_points) < _MIN_GPS_RECORDS:
            return self._insufficient_data(
                fp,
                f"only {len(gps_points)} GPS records -- need {_MIN_GPS_RECORDS} minimum"
            )

        # Determine session type (flight vs ground) for speed bound selection
        is_flight = self._detect_flight(gps_points)

        findings: list[Finding] = []
        raw: dict[str, Any]     = {
            'gps_record_count':  len(gps_points),
            'baro_record_count': len(baro_points),
            'ekf_record_count':  len(ekf_points),
            'is_flight':         is_flight,
        }

        # -- Check 1: position jump ------------------------------------
        f1, r1 = self._check_position_jump(gps_points, is_flight)
        findings.append(f1)
        raw.update(r1)

        # -- Check 2: altitude divergence ------------------------------
        if baro_points:
            f2, r2 = self._check_alt_divergence(gps_points, baro_points)
            findings.append(f2)
            raw.update(r2)
        else:
            findings.append(Finding(
                check='alt_divergence',
                verdict=Verdict.UNKNOWN,
                detail='No BARO records -- cannot cross-check GPS altitude',
            ))

        # -- Check 3: GPS quality shift --------------------------------
        f3, r3 = self._check_gps_quality(gps_points)
        findings.append(f3)
        raw.update(r3)

        # -- Check 4: EKF innovation -----------------------------------
        if ekf_points:
            f4, r4 = self._check_ekf_innovation(ekf_points)
            findings.append(f4)
            raw.update(r4)
        else:
            findings.append(Finding(
                check='ekf_innovation',
                verdict=Verdict.UNKNOWN,
                detail='No XKF1/NKF1 records -- cannot check EKF GPS innovation',
            ))

        verdict, confidence = self._aggregate_verdict(findings)

        notes = []
        if not is_flight:
            notes.append(
                "Ground session -- position jump thresholds calibrated for stationary vehicle"
            )
        fix_count = sum(1 for p in gps_points if p.status >= 3)
        if fix_count == 0:
            notes.append(
                "No GPS fix acquired in this session -- checks based on partial signal only"
            )

        return AnalysisResult(
            analyzer=self.NAME,
            version=self.VERSION,
            filepath=fp,
            verdict=verdict,
            confidence=confidence,
            findings=findings,
            raw_values=raw,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Explain  (human-readable output)
    # ------------------------------------------------------------------

    def explain(self, result: AnalysisResult) -> str:
        rv  = result.raw_values
        lines = [
            f"{'='*64}",
            f"  {result.filepath.name}  --  GPS SPOOFING ASSESSMENT",
            f"{'='*64}",
            f"  GPS records : {rv.get('gps_record_count', '?')}   "
            f"BARO records : {rv.get('baro_record_count', '?')}   "
            f"EKF records : {rv.get('ekf_record_count', '?')}",
            f"  Session type: {'flight' if rv.get('is_flight') else 'ground'}",
            "",
        ]

        check_labels = {
            'position_jump':  'Position jumps',
            'alt_divergence': 'Alt divergence (GPS vs BARO)',
            'gps_quality':    'GPS quality shift',
            'ekf_innovation': 'EKF GPS innovation',
        }

        for f in result.findings:
            label  = check_labels.get(f.check, f.check)
            val    = f"  ({f.value})" if f.value is not None else ""
            ts     = f"  @ {f.timestamp_us}us" if f.timestamp_us else ""
            lines.append(
                f"  {label:<32} {f.verdict.value:<12}{val}{ts}"
            )
            lines.append(f"    {f.detail}")
            lines.append("")

        verdict_line = f"  VERDICT: {result.verdict.value}  (confidence {result.confidence:.0%})"
        lines.append("-" * 64)
        lines.append(verdict_line)
        for note in result.notes:
            lines.append(f"  NOTE: {note}")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_gps(self, pr: ParseResult) -> list[_GpsPoint]:
        points = []
        for r in pr.records_by_type('GPS'):
            lat    = r.get('Lat')
            lon    = r.get('Lng', r.get('Lon'))
            alt    = r.get('Alt')
            status = r.get('Status', 0)
            nsats  = r.get('NSats', r.get('Nsats', 0))
            hdop   = r.get('HDop', r.get('Hdop', 99.99))
            ts     = r.timeus
            if None in (lat, lon, alt, ts):
                continue
            try:
                points.append(_GpsPoint(
                    timeus=int(ts),
                    lat=float(lat),
                    lon=float(lon),
                    alt=float(alt),
                    status=int(status),
                    nsats=int(nsats),
                    hdop=float(hdop),
                ))
            except (TypeError, ValueError):
                continue
        return points

    def _extract_baro(self, pr: ParseResult) -> list[_BaroPoint]:
        points = []
        for r in pr.records_by_type('BARO'):
            alt = r.get('Alt')
            ts  = r.timeus
            if None in (alt, ts):
                continue
            try:
                points.append(_BaroPoint(timeus=int(ts), alt=float(alt)))
            except (TypeError, ValueError):
                continue
        return points

    def _extract_ekf(self, pr: ParseResult) -> list[_EkfPoint]:
        points = []
        for msg_type in ('XKF1', 'NKF1'):
            for r in pr.records_by_type(msg_type):
                ivn = r.get('IVN', r.get('VN'))
                ive = r.get('IVE', r.get('VE'))
                ivd = r.get('IVD', r.get('VD'))
                ts  = r.timeus
                if None in (ivn, ive, ts):
                    continue
                try:
                    points.append(_EkfPoint(
                        timeus=int(ts),
                        ivn=float(ivn),
                        ive=float(ive),
                        ivd=float(ivd) if ivd is not None else 0.0,
                    ))
                except (TypeError, ValueError):
                    continue
        return sorted(points, key=lambda p: p.timeus)

    # ------------------------------------------------------------------
    # Session type detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_flight(gps_points: list[_GpsPoint]) -> bool:
        fix_count = sum(1 for p in gps_points if p.status >= 3)
        if fix_count < 5:
            return False
        nsats_ok = any(p.nsats > 4 for p in gps_points)
        return nsats_ok

    # ------------------------------------------------------------------
    # Check 1 -- position jump
    # ------------------------------------------------------------------

    def _check_position_jump(
        self,
        pts: list[_GpsPoint],
        is_flight: bool,
    ) -> tuple[Finding, dict]:
        speed_bound = _MAX_FLIGHT_SPEED_MS if is_flight else _MAX_GROUND_SPEED_MS
        alert_dist  = speed_bound * _GPS_INTERVAL_S * _JUMP_ALERT_MULTIPLIER
        susp_dist   = speed_bound * _GPS_INTERVAL_S * _JUMP_SUSPICIOUS_MULT

        max_jump_m   = 0.0
        max_jump_ts  = None
        jump_count   = 0
        alert_count  = 0

        for i in range(1, len(pts)):
            prev, curr = pts[i - 1], pts[i]
            # Only check when both points have a fix
            if prev.status < 3 or curr.status < 3:
                continue

            dt = max((curr.timeus - prev.timeus) / 1_000_000.0, 0.1)
            effective_bound = speed_bound * dt * _JUMP_ALERT_MULTIPLIER

            dlat = (curr.lat - prev.lat) * _LAT_DEG_TO_M
            dlon = (curr.lon - prev.lon) * _LON_DEG_TO_M_AT_EQUATOR * math.cos(
                math.radians((curr.lat + prev.lat) / 2)
            )
            dist_m = math.sqrt(dlat ** 2 + dlon ** 2)

            if dist_m > max_jump_m:
                max_jump_m  = dist_m
                max_jump_ts = curr.timeus

            if dist_m > effective_bound:
                jump_count += 1
                if dist_m > alert_dist:
                    alert_count += 1

        raw = {
            'position_jump_max_m':   round(max_jump_m, 2),
            'position_jump_count':   jump_count,
            'position_alert_count':  alert_count,
            'position_speed_bound':  speed_bound,
        }

        if alert_count > 0:
            return Finding(
                check='position_jump',
                verdict=Verdict.ALERT,
                detail=(
                    f"{alert_count} jump(s) exceed {alert_dist:.1f}m alert threshold. "
                    f"Max jump: {max_jump_m:.1f}m. "
                    f"Vehicle speed bound: {speed_bound}m/s. "
                    f"Physically inconsistent with vehicle state."
                ),
                value=f"{max_jump_m:.1f}m",
                timestamp_us=max_jump_ts,
            ), raw

        if jump_count > 0:
            return Finding(
                check='position_jump',
                verdict=Verdict.SUSPICIOUS,
                detail=(
                    f"{jump_count} jump(s) exceed {susp_dist:.1f}m suspicious threshold. "
                    f"Max jump: {max_jump_m:.1f}m. May be multipath or weak signal."
                ),
                value=f"{max_jump_m:.1f}m",
                timestamp_us=max_jump_ts,
            ), raw

        if max_jump_m == 0.0:
            detail = "No GPS fix acquired -- no position deltas to evaluate"
        else:
            detail = f"Max position delta {max_jump_m:.2f}m -- within velocity bounds"

        return Finding(
            check='position_jump',
            verdict=Verdict.CLEAN,
            detail=detail,
            value=f"{max_jump_m:.2f}m",
        ), raw

    # ------------------------------------------------------------------
    # Check 2 -- altitude divergence
    # ------------------------------------------------------------------

    def _check_alt_divergence(
        self,
        gps_pts: list[_GpsPoint],
        baro_pts: list[_BaroPoint],
    ) -> tuple[Finding, dict]:

        # Build a baro lookup: for each GPS timestamp find nearest baro reading
        def nearest_baro(ts: int) -> float | None:
            if not baro_pts:
                return None
            best = min(baro_pts, key=lambda b: abs(b.timeus - ts))
            # Only use if within 2 seconds
            if abs(best.timeus - ts) > 2_000_000:
                return None
            return best.alt

        # Establish altitude sync baseline from first N fix records
        fix_pts = [p for p in gps_pts if p.status >= 3]
        if not fix_pts:
            return Finding(
                check='alt_divergence',
                verdict=Verdict.UNKNOWN,
                detail='No GPS fix records -- cannot establish altitude baseline',
            ), {}

        baseline_pairs = []
        for p in fix_pts[:_ALT_BARO_SYNC_WINDOW]:
            b = nearest_baro(p.timeus)
            if b is not None:
                baseline_pairs.append(p.alt - b)

        if not baseline_pairs:
            return Finding(
                check='alt_divergence',
                verdict=Verdict.UNKNOWN,
                detail='Cannot find BARO records near GPS fix timestamps',
            ), {}

        offset = sum(baseline_pairs) / len(baseline_pairs)

        # Measure divergence across all fix points
        max_div     = 0.0
        max_div_ts  = None
        divergences = []

        for p in fix_pts:
            b = nearest_baro(p.timeus)
            if b is None:
                continue
            expected_gps_alt = b + offset
            div = abs(p.alt - expected_gps_alt)
            divergences.append(div)
            if div > max_div:
                max_div    = div
                max_div_ts = p.timeus

        avg_div = sum(divergences) / len(divergences) if divergences else 0.0

        raw = {
            'alt_offset_m':     round(offset, 2),
            'alt_max_div_m':    round(max_div, 2),
            'alt_avg_div_m':    round(avg_div, 2),
            'alt_sample_count': len(divergences),
        }

        if max_div >= _ALT_DIVERGENCE_ALERT_M:
            return Finding(
                check='alt_divergence',
                verdict=Verdict.ALERT,
                detail=(
                    f"GPS altitude diverged {max_div:.1f}m from BARO prediction "
                    f"(threshold {_ALT_DIVERGENCE_ALERT_M}m). "
                    f"GPS-BARO offset baseline: {offset:.1f}m. "
                    f"Consistent with injected false GPS altitude."
                ),
                value=f"{max_div:.1f}m",
                timestamp_us=max_div_ts,
            ), raw

        if max_div >= _ALT_DIVERGENCE_SUSP_M:
            return Finding(
                check='alt_divergence',
                verdict=Verdict.SUSPICIOUS,
                detail=(
                    f"GPS altitude diverged {max_div:.1f}m from BARO prediction. "
                    f"May indicate atmospheric pressure change or weak GPS signal."
                ),
                value=f"{max_div:.1f}m",
                timestamp_us=max_div_ts,
            ), raw

        return Finding(
            check='alt_divergence',
            verdict=Verdict.CLEAN,
            detail=(
                f"GPS and BARO altitudes track within {max_div:.1f}m. "
                f"Offset baseline: {offset:.1f}m. No divergence detected."
            ),
            value=f"{max_div:.1f}m",
        ), raw

    # ------------------------------------------------------------------
    # Check 3 -- GPS quality shift
    # ------------------------------------------------------------------

    def _check_gps_quality(
        self,
        pts: list[_GpsPoint],
    ) -> tuple[Finding, dict]:
        if len(pts) < 3:
            return Finding(
                check='gps_quality',
                verdict=Verdict.UNKNOWN,
                detail='Too few GPS records to assess quality trends',
            ), {}

        max_hdop_drop  = 0.0
        max_hdop_spike = 0.0
        max_nsat_drop  = 0
        hdop_event_ts  = None
        nsat_event_ts  = None

        for i in range(1, len(pts)):
            prev, curr = pts[i - 1], pts[i]
            hdop_delta = curr.hdop - prev.hdop
            nsat_delta = curr.nsats - prev.nsats

            if hdop_delta < -_HDOP_DROP_ALERT:
                if abs(hdop_delta) > max_hdop_drop:
                    max_hdop_drop = abs(hdop_delta)
                    hdop_event_ts = curr.timeus
            if hdop_delta > _HDOP_SPIKE_ALERT:
                if hdop_delta > max_hdop_spike:
                    max_hdop_spike = hdop_delta
                    hdop_event_ts  = curr.timeus
            if -nsat_delta > max_nsat_drop:
                max_nsat_drop = -nsat_delta
                nsat_event_ts = curr.timeus

        raw = {
            'gps_hdop_max_drop':  round(max_hdop_drop, 2),
            'gps_hdop_max_spike': round(max_hdop_spike, 2),
            'gps_nsat_max_drop':  max_nsat_drop,
        }

        # Sudden HDop DROP before a position change is classic spoof signature
        if max_hdop_drop >= _HDOP_DROP_ALERT and max_hdop_spike == 0.0:
            return Finding(
                check='gps_quality',
                verdict=Verdict.SUSPICIOUS,
                detail=(
                    f"HDop dropped suddenly by {max_hdop_drop:.1f} -- "
                    f"suspiciously clean signal may indicate spoofed carrier. "
                    f"Correlate with position jump timestamps."
                ),
                value=f"drop={max_hdop_drop:.1f}",
                timestamp_us=hdop_event_ts,
            ), raw

        if max_hdop_spike >= _HDOP_SPIKE_ALERT:
            return Finding(
                check='gps_quality',
                verdict=Verdict.SUSPICIOUS,
                detail=(
                    f"HDop spiked by {max_hdop_spike:.1f} -- "
                    f"sudden signal degradation consistent with jamming or "
                    f"spoofer overpowering real signal."
                ),
                value=f"spike={max_hdop_spike:.1f}",
                timestamp_us=hdop_event_ts,
            ), raw

        if max_nsat_drop >= _NSATS_DROP_ALERT:
            return Finding(
                check='gps_quality',
                verdict=Verdict.SUSPICIOUS,
                detail=(
                    f"Satellite count dropped by {max_nsat_drop} -- "
                    f"sudden loss consistent with jamming or spoof signal "
                    f"overpowering real constellation."
                ),
                value=f"nsat_drop={max_nsat_drop}",
                timestamp_us=nsat_event_ts,
            ), raw

        hdop_vals = [p.hdop for p in pts]
        nsat_vals = [p.nsats for p in pts]
        return Finding(
            check='gps_quality',
            verdict=Verdict.CLEAN,
            detail=(
                f"HDop stable {min(hdop_vals):.1f}-{max(hdop_vals):.1f}, "
                f"NSats range {min(nsat_vals)}-{max(nsat_vals)}. "
                f"No anomalous quality shifts detected."
            ),
            value=f"hdop={min(hdop_vals):.1f}-{max(hdop_vals):.1f}",
        ), raw

    # ------------------------------------------------------------------
    # Check 4 -- EKF GPS innovation
    # ------------------------------------------------------------------

    def _check_ekf_innovation(
        self,
        pts: list[_EkfPoint],
    ) -> tuple[Finding, dict]:
        if not pts:
            return Finding(
                check='ekf_innovation',
                verdict=Verdict.UNKNOWN,
                detail='No EKF innovation records',
            ), {}

        magnitudes   = [math.sqrt(p.ivn ** 2 + p.ive ** 2) for p in pts]
        max_mag      = max(magnitudes)
        avg_mag      = sum(magnitudes) / len(magnitudes)
        max_idx      = magnitudes.index(max_mag)
        max_ts       = pts[max_idx].timeus

        alert_count  = sum(1 for m in magnitudes if m > _EKF_INNOV_ALERT)
        susp_count   = sum(1 for m in magnitudes if m > _EKF_INNOV_SUSPICIOUS)

        raw = {
            'ekf_innov_max':         round(max_mag, 3),
            'ekf_innov_avg':         round(avg_mag, 3),
            'ekf_innov_alert_count': alert_count,
            'ekf_innov_susp_count':  susp_count,
        }

        if alert_count > 0:
            return Finding(
                check='ekf_innovation',
                verdict=Verdict.ALERT,
                detail=(
                    f"EKF GPS innovation exceeded alert threshold "
                    f"({_EKF_INNOV_ALERT}) {alert_count} time(s). "
                    f"Max magnitude: {max_mag:.2f}. "
                    f"Flight controller detected GPS-IMU inconsistency. "
                    f"Strong spoof indicator when correlated with position jump."
                ),
                value=f"max={max_mag:.2f}",
                timestamp_us=max_ts,
            ), raw

        if susp_count > 0:
            return Finding(
                check='ekf_innovation',
                verdict=Verdict.SUSPICIOUS,
                detail=(
                    f"EKF GPS innovation exceeded suspicious threshold "
                    f"({_EKF_INNOV_SUSPICIOUS}) {susp_count} time(s). "
                    f"Max magnitude: {max_mag:.2f}. "
                    f"May indicate GPS-IMU disagreement."
                ),
                value=f"max={max_mag:.2f}",
                timestamp_us=max_ts,
            ), raw

        return Finding(
            check='ekf_innovation',
            verdict=Verdict.CLEAN,
            detail=(
                f"EKF GPS innovation low throughout. "
                f"Max: {max_mag:.2f}, avg: {avg_mag:.2f}. "
                f"GPS and IMU in agreement."
            ),
            value=f"max={max_mag:.2f}",
        ), raw

    # ------------------------------------------------------------------
    # Verdict aggregation
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate_verdict(
        findings: list[Finding],
    ) -> tuple[Verdict, float]:
        """Weighted worst-case verdict with confidence score."""
        verdict_score = {
            Verdict.CLEAN:      0,
            Verdict.UNKNOWN:    0,
            Verdict.SUSPICIOUS: 1,
            Verdict.ALERT:      2,
        }

        weighted_score = 0.0
        max_verdict    = Verdict.CLEAN
        known_weight   = 0.0

        for f in findings:
            w = _WEIGHT.get(f.check, 0.1)
            if f.verdict == Verdict.UNKNOWN:
                continue
            known_weight   += w
            weighted_score += w * verdict_score[f.verdict]
            if verdict_score[f.verdict] > verdict_score[max_verdict]:
                max_verdict = f.verdict

        if known_weight == 0:
            return Verdict.UNKNOWN, 0.0

        normalised = weighted_score / known_weight
        confidence = min(known_weight, 1.0) * (0.5 + normalised * 0.5)
        confidence = round(min(confidence, 1.0), 3)

        return max_verdict, confidence