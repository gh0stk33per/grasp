"""DataFlash Corpus Characterisation Tool.

Session 001 of SENTINEL -- corpus inventory for all BIN files.
Extends sentinel/tools/investigate.py binary parsing layer.
Standard library only.

Usage:
    python3 sentinel/tools/corpus_scan.py --data-dir sentinel/data/

Output:
    sentinel/data/corpus_inventory.json   -- per-file detail
    sentinel/data/corpus_summary.json     -- aggregated
    stdout                                -- summary table
"""

import argparse
import collections
import hashlib
import json
import pathlib
import struct
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# DataFlash binary format constants (from investigate.py)
# ---------------------------------------------------------------------------

HEADER_BYTE_1 = 0xA3
HEADER_BYTE_2 = 0x95
FMT_TYPE_ID   = 0x80

FMT_PAYLOAD_STRUCT = struct.Struct("<BB4s16s64s")

FORMAT_CHARS = {
    'b': ('b', 'int8'),
    'B': ('B', 'uint8'),
    'h': ('h', 'int16'),
    'H': ('H', 'uint16'),
    'i': ('i', 'int32'),
    'I': ('I', 'uint32'),
    'f': ('f', 'float32'),
    'd': ('d', 'float64'),
    'n': ('4s',  'char[4]'),
    'N': ('16s', 'char[16]'),
    'Z': ('64s', 'char[64]'),
    'c': ('h', 'int16_scaled_100'),
    'C': ('H', 'uint16_scaled_100'),
    'e': ('i', 'int32_scaled_100'),
    'E': ('I', 'uint32_scaled_100'),
    'L': ('i', 'int32_lat_lon'),
    'M': ('B', 'flight_mode'),
    'q': ('q', 'int64'),
    'Q': ('Q', 'uint64'),
}

SCALE_100 = {'c', 'C', 'e', 'E'}
GPS_COORD  = {'L'}

# ---------------------------------------------------------------------------
# Domain constants
# ---------------------------------------------------------------------------

SAFETY_CRITICAL_PARAMS = {
    "ARMING_CHECK", "FS_THR_ENABLE", "FS_THR_VALUE",
    "FS_GCS_ENABLE", "FENCE_ENABLE", "FENCE_ACTION",
    "EKF_TYPE", "AHRS_EKF_TYPE",
    "MOT_SPIN_ARM", "MOT_SPIN_MIN",
    "COMPASS_USE", "COMPASS_AUTODEC",
    "GPS_TYPE", "GPS_GNSS_MODE",
    "BARO_PRIMARY", "INS_USE",
}

# ERR SubSys codes relevant to anomaly detection
ERR_SUBSYS = {
    3:  "voltage",
    6:  "compass",
    8:  "ekf",
    10: "arming",
}

# Frequency measurement: message types we care about
FREQ_MSG_TYPES = {"IMU", "ATT", "GPS", "BARO", "MAG", "RCIN", "MOTB"}

# Altitude delta threshold for flight detection (metres)
FLIGHT_ALT_DELTA_M = 5.0
GROUND_ALT_DELTA_M = 2.0

# Flight modes that indicate sustained flight (ArduCopter mode numbers)
FLIGHT_MODES = {3, 4, 5, 6, 9, 10, 13, 14, 15, 16, 17, 18, 20, 21}  # AUTO,GUIDED,LOITER etc.
GROUND_MODES = {0, 1, 2}  # STABILIZE, ACRO, ALT_HOLD (ambiguous but common on ground)


# ---------------------------------------------------------------------------
# Binary parsing layer (from investigate.py -- do not modify)
# ---------------------------------------------------------------------------

def _parse_fmt_payload(payload: bytes) -> dict | None:
    if len(payload) < FMT_PAYLOAD_STRUCT.size:
        return None
    try:
        type_id, length, name_b, fmt_b, cols_b = FMT_PAYLOAD_STRUCT.unpack(
            payload[:FMT_PAYLOAD_STRUCT.size]
        )
    except struct.error:
        return None

    name = name_b.rstrip(b'\x00').decode('ascii', errors='replace').strip()
    fmt  = fmt_b.rstrip(b'\x00').decode('ascii', errors='replace').strip()
    cols = cols_b.rstrip(b'\x00').decode('ascii', errors='replace').strip()

    if not name or not fmt:
        return None

    field_names = [c.strip() for c in cols.split(',') if c.strip()]
    struct_fmt  = '<'
    field_defs  = []

    for i, ch in enumerate(fmt):
        if ch not in FORMAT_CHARS:
            continue
        sc, desc = FORMAT_CHARS[ch]
        struct_fmt += sc
        fname = field_names[i] if i < len(field_names) else f"field_{i}"
        field_defs.append({'name': fname, 'fmt_char': ch, 'type_desc': desc})

    try:
        compiled = struct.Struct(struct_fmt)
    except struct.error:
        compiled = None

    return {
        'type_id':  type_id,
        'length':   length,
        'name':     name,
        'format':   fmt,
        'fields':   field_defs,
        'struct':   compiled,
    }


def _decode_value(raw, fmt_char: str):
    if isinstance(raw, bytes):
        return raw.rstrip(b'\x00').decode('ascii', errors='replace').strip()
    if fmt_char in SCALE_100:
        return raw / 100.0
    if fmt_char in GPS_COORD:
        return raw / 1e7
    return raw


def _build_schema(data: bytes) -> dict[int, dict]:
    """Pass 1: extract all FMT records and build schema."""
    schema = {}
    pos    = 0
    total  = len(data)

    while pos < total - 2:
        if data[pos] == HEADER_BYTE_1 and data[pos + 1] == HEADER_BYTE_2:
            if pos + 3 > total:
                break
            if data[pos + 2] == FMT_TYPE_ID:
                payload_start = pos + 3
                payload_end   = payload_start + FMT_PAYLOAD_STRUCT.size
                if payload_end <= total:
                    defn = _parse_fmt_payload(data[payload_start:payload_end])
                    if defn:
                        schema[defn['type_id']] = defn
        pos += 1

    return schema


# ---------------------------------------------------------------------------
# Corpus scanner
# ---------------------------------------------------------------------------

class _FileScanner:
    """Scans a single BIN file and extracts all characterisation signals."""

    def __init__(self, filepath: pathlib.Path):
        self.filepath = filepath
        self.data     = filepath.read_bytes()
        self.total    = len(self.data)
        self.schema   = {}

        # Accumulators
        self.timeus: dict[str, list[int]]      = collections.defaultdict(list)
        self.params: dict[str, float]          = {}
        self.firmware_version: str             = ""
        self.gps_status: list[int]             = []
        self.gps_nsats:  list[int]             = []
        self.gps_hdop:   list[float]           = []
        self.gps_lat:    list[float]           = []
        self.baro_alt:   list[float]           = []
        self.flight_modes: list[int]           = []
        self.arming_events: list[dict]         = []
        self.err_records: list[dict]           = []
        self.motb_throttle: list[float]        = []
        self.xkf4_ss: list[int]                = []
        self.powr_vcc: list[float]             = []
        self.rcin_c3:  list[int]               = []  # throttle channel

    # ------------------------------------------------------------------
    def scan(self) -> dict:
        self.schema = _build_schema(self.data)
        if not self.schema:
            return self._verdict_exclude("no_schema")

        self._pass2()
        return self._build_result()

    # ------------------------------------------------------------------
    def _pass2(self) -> None:
        pos   = 0
        total = self.total
        data  = self.data

        while pos < total - 2:
            if data[pos] != HEADER_BYTE_1 or data[pos + 1] != HEADER_BYTE_2:
                pos += 1
                continue
            if pos + 3 > total:
                break

            msg_type = data[pos + 2]

            if msg_type == FMT_TYPE_ID:
                pos += 89
                continue

            if msg_type not in self.schema:
                pos += 3
                continue

            defn       = self.schema[msg_type]
            compiled   = defn['struct']
            record_len = defn['length']
            msg_name   = defn['name']

            if compiled is None or record_len == 0:
                pos += 3
                continue

            payload_start = pos + 3
            payload_end   = pos + record_len
            if payload_end > total:
                pos += 1
                continue

            payload = data[payload_start:payload_end]
            if len(payload) < compiled.size:
                pos += record_len if record_len > 3 else 4
                continue

            try:
                raw_vals = compiled.unpack(payload[:compiled.size])
            except struct.error:
                pos += record_len if record_len > 3 else 4
                continue

            fields = defn['fields']
            parsed = {}
            for i, fd in enumerate(fields):
                if i < len(raw_vals):
                    parsed[fd['name']] = _decode_value(raw_vals[i], fd['fmt_char'])

            self._route(msg_name, parsed)
            pos += record_len if record_len > 3 else 4

    # ------------------------------------------------------------------
    def _route(self, name: str, p: dict) -> None:
        """Route parsed record to the appropriate accumulator."""

        # TimeUS collection for frequency measurement
        if name in FREQ_MSG_TYPES and 'TimeUS' in p:
            v = p['TimeUS']
            if isinstance(v, (int, float)) and v > 0:
                self.timeus[name].append(int(v))

        if name == 'MSG':
            msg_text = p.get('Message', '')
            if 'ArduCopter' in msg_text or 'ArduPilot' in msg_text:
                self.firmware_version = msg_text.strip()

        elif name == 'PARM':
            pname = p.get('Name', '')
            pval  = p.get('Value', None)
            if pname and pval is not None:
                try:
                    self.params[pname] = float(pval)
                except (TypeError, ValueError):
                    pass

        elif name == 'GPS':
            if 'Status' in p:
                self.gps_status.append(int(p['Status']))
            if 'NSats' in p:
                self.gps_nsats.append(int(p['NSats']))
            if 'HDop' in p:
                self.gps_hdop.append(float(p['HDop']))
            if 'Lat' in p:
                self.gps_lat.append(float(p['Lat']))

        elif name == 'BARO':
            if 'Alt' in p:
                self.baro_alt.append(float(p['Alt']))

        elif name == 'MODE':
            mode = p.get('Mode', p.get('ModeNum', None))
            if mode is not None:
                self.flight_modes.append(int(mode))

        elif name == 'ERR':
            subsys = p.get('Subsys', p.get('SubSys', None))
            ecode  = p.get('ECode', None)
            if subsys is not None:
                self.err_records.append({
                    'subsys': int(subsys),
                    'ecode':  int(ecode) if ecode is not None else 0,
                })

        elif name == 'EV':
            # EV ID=15 = armed, ID=16 = disarmed
            ev_id = p.get('Id', p.get('ID', None))
            if ev_id == 15:
                self.arming_events.append({'result': 'armed'})
            elif ev_id == 16:
                self.arming_events.append({'result': 'disarmed'})

        elif name == 'MOTB':
            thr = p.get('ThO', p.get('ThrOut', None))
            if thr is not None:
                self.motb_throttle.append(float(thr))

        elif name in ('XKF4', 'NKF4'):
            ss = p.get('SS', p.get('Flags', None))
            if ss is not None:
                self.xkf4_ss.append(int(ss))

        elif name == 'POWR':
            vcc = p.get('Vcc', None)
            if vcc is not None:
                self.powr_vcc.append(float(vcc))

        elif name == 'RCIN':
            c3 = p.get('C3', None)
            if c3 is not None:
                self.rcin_c3.append(int(c3))

    # ------------------------------------------------------------------
    def _build_result(self) -> dict:

        # -- Duration ---------------------------------------------------
        duration_s = self._calc_duration()

        # -- GPS state --------------------------------------------------
        fix_acquired     = any(s >= 3 for s in self.gps_status)
        nsats_max        = max(self.gps_nsats) if self.gps_nsats else 0
        hdop_min         = min(self.gps_hdop)  if self.gps_hdop  else 99.99
        pos_changes      = self._count_position_changes()

        gps_state = {
            'fix_acquired':     fix_acquired,
            'nsats_max':        nsats_max,
            'hdop_min':         round(hdop_min, 2),
            'position_changes': pos_changes,
        }

        # -- Arming events ---------------------------------------------
        armed_count  = sum(1 for e in self.arming_events if e['result'] == 'armed')
        arm_failures = sum(
            1 for e in self.err_records
            if e['subsys'] == 10 and e['ecode'] > 0
        )
        arming_events = {
            'count':      len(self.arming_events),
            'successful': armed_count,
            'failed':     arm_failures,
        }

        # -- Logging frequencies ----------------------------------------
        logging_frequencies = {}
        for msg, ts in self.timeus.items():
            hz = self._calc_frequency(ts)
            if hz is not None:
                logging_frequencies[msg] = round(hz, 1)

        # -- Parameter fingerprint --------------------------------------
        param_fingerprint, safety_params = self._calc_fingerprint()

        # -- Anomaly indicators ----------------------------------------
        err_subsys_counts = collections.Counter(
            ERR_SUBSYS.get(e['subsys'], f"subsys_{e['subsys']}")
            for e in self.err_records
        )
        err_codes = [
            {'subsys': e['subsys'], 'ecode': e['ecode']}
            for e in self.err_records
        ]

        gps_glitches     = self._count_gps_glitches()
        compass_warnings = (
            err_subsys_counts.get('compass', 0) +
            sum(1 for ss in self.xkf4_ss if ss & 0x04)
        )
        voltage_alerts   = (
            err_subsys_counts.get('voltage', 0) +
            sum(1 for v in self.powr_vcc if v < 4.5)
        )
        ekf_warnings     = err_subsys_counts.get('ekf', 0)

        anomaly_indicators = {
            'err_count':        len(self.err_records),
            'err_codes':        err_codes[:20],  # cap for json size
            'gps_glitches':     gps_glitches,
            'compass_warnings': compass_warnings,
            'voltage_alerts':   voltage_alerts,
            'ekf_warnings':     ekf_warnings,
            'arming_failures':  arm_failures,
        }

        # -- Motor activity --------------------------------------------
        max_thr = max(self.motb_throttle) if self.motb_throttle else 0.0
        motor_activity = {
            'max_throttle_out':    round(max_thr, 3),
            'motor_test_detected': max_thr > 0.05,
        }

        # -- Message types present -------------------------------------
        msg_types_present = sorted(
            defn['name']
            for defn in self.schema.values()
            if defn['name'] != 'FMT'
        )

        # -- Session type ----------------------------------------------
        session_type = self._classify_session()

        # -- Verdict ---------------------------------------------------
        verdict, verdict_reasons = self._classify_verdict(
            anomaly_indicators, fix_acquired, duration_s
        )

        return {
            'file':                   self.filepath.name,
            'size_bytes':             self.total,
            'duration_seconds':       round(duration_s, 1) if duration_s else None,
            'session_type':           session_type,
            'firmware_version':       self.firmware_version or 'unknown',
            'gps_state':              gps_state,
            'arming_events':          arming_events,
            'message_types_present':  msg_types_present,
            'logging_frequencies':    logging_frequencies,
            'parameter_fingerprint':  param_fingerprint,
            'safety_critical_params': safety_params,
            'anomaly_indicators':     anomaly_indicators,
            'motor_activity':         motor_activity,
            'usability_verdict':      verdict,
            'verdict_reasons':        verdict_reasons,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _calc_duration(self) -> float | None:
        """Derive session duration from the highest-frequency TimeUS stream."""
        best = None
        for ts in self.timeus.values():
            if len(ts) > 1:
                span = (ts[-1] - ts[0]) / 1_000_000.0
                if best is None or span > best:
                    best = span
        return best

    @staticmethod
    def _calc_frequency(timestamps: list[int]) -> float | None:
        if len(timestamps) < 2:
            return None
        intervals = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
            if timestamps[i + 1] > timestamps[i]
        ]
        if not intervals:
            return None
        intervals.sort()
        median_us = intervals[len(intervals) // 2]
        if median_us <= 0:
            return None
        return 1_000_000 / median_us

    def _count_position_changes(self) -> int:
        if len(self.gps_lat) < 2:
            return 0
        changes = 0
        for i in range(1, len(self.gps_lat)):
            if abs(self.gps_lat[i] - self.gps_lat[i - 1]) > 1e-5:
                changes += 1
        return changes

    def _count_gps_glitches(self) -> int:
        """GPS fix drops from >=3 to <=1 after initial acquisition."""
        glitches   = 0
        had_fix    = False
        lost_fix   = False
        for s in self.gps_status:
            if s >= 3:
                if lost_fix and had_fix:
                    glitches += 1
                had_fix  = True
                lost_fix = False
            elif s <= 1 and had_fix:
                lost_fix = True
        return glitches

    def _calc_fingerprint(self) -> tuple[str, dict]:
        safety = {k: v for k, v in self.params.items() if k in SAFETY_CRITICAL_PARAMS}
        if not safety:
            return 'unknown', {}
        param_str   = "|".join(f"{k}={v:.4f}" for k, v in sorted(safety.items()))
        fingerprint = hashlib.sha256(param_str.encode()).hexdigest()[:8]
        return fingerprint, safety

    def _classify_session(self) -> str:
        # Flight indicators
        if self.gps_status:
            fix_count = sum(1 for s in self.gps_status if s >= 3)
            if fix_count > 5:
                nsats_ok = any(n > 4 for n in self.gps_nsats)
                if nsats_ok:
                    return 'flight'

        if self.baro_alt and len(self.baro_alt) > 1:
            alt_range = max(self.baro_alt) - min(self.baro_alt)
            if alt_range > FLIGHT_ALT_DELTA_M:
                return 'flight'
            if alt_range <= GROUND_ALT_DELTA_M:
                if all(s <= 1 for s in self.gps_status):
                    return 'ground'

        if self.flight_modes:
            if any(m in FLIGHT_MODES for m in self.flight_modes):
                return 'flight'
            if all(m in GROUND_MODES for m in self.flight_modes):
                return 'ground'

        # Fallback: no GPS fix and no baro excursion = likely ground
        if self.gps_status and all(s <= 1 for s in self.gps_status):
            return 'ground'

        return 'unknown'

    def _classify_verdict(
        self,
        anomaly: dict,
        fix_acquired: bool,
        duration_s: float | None,
    ) -> tuple[str, list[str]]:
        reasons = []

        if duration_s is not None and duration_s < 5:
            return 'exclude', ['duration_too_short']

        total_err = anomaly['err_count']
        has_anomaly = (
            total_err > 0 or
            anomaly['gps_glitches'] > 0 or
            anomaly['compass_warnings'] > 0 or
            anomaly['voltage_alerts'] > 0 or
            anomaly['ekf_warnings'] > 0 or
            anomaly['arming_failures'] > 0
        )

        if has_anomaly:
            if total_err > 0:
                reasons.append(f"err_count={total_err}")
            if anomaly['gps_glitches'] > 0:
                reasons.append(f"gps_glitches={anomaly['gps_glitches']}")
            if anomaly['compass_warnings'] > 0:
                reasons.append(f"compass_warnings={anomaly['compass_warnings']}")
            if anomaly['voltage_alerts'] > 0:
                reasons.append(f"voltage_alerts={anomaly['voltage_alerts']}")
            if anomaly['ekf_warnings'] > 0:
                reasons.append(f"ekf_warnings={anomaly['ekf_warnings']}")
            if anomaly['arming_failures'] > 0:
                reasons.append(f"arming_failures={anomaly['arming_failures']}")
            return 'contains_deviations', reasons

        # No anomaly indicators -- check for review flags
        if not self.params:
            reasons.append('no_parm_records')
        if duration_s is not None and duration_s < 30:
            reasons.append('short_duration')

        if reasons:
            return 'review', reasons

        return 'clean_baseline', []

    def _verdict_exclude(self, reason: str) -> dict:
        return {
            'file':                   self.filepath.name,
            'size_bytes':             self.total,
            'duration_seconds':       None,
            'session_type':           'unknown',
            'firmware_version':       'unknown',
            'gps_state':              {'fix_acquired': False, 'nsats_max': 0,
                                       'hdop_min': 99.99, 'position_changes': 0},
            'arming_events':          {'count': 0, 'successful': 0, 'failed': 0},
            'message_types_present':  [],
            'logging_frequencies':    {},
            'parameter_fingerprint':  'unknown',
            'safety_critical_params': {},
            'anomaly_indicators':     {'err_count': 0, 'err_codes': [],
                                       'gps_glitches': 0, 'compass_warnings': 0,
                                       'voltage_alerts': 0, 'ekf_warnings': 0,
                                       'arming_failures': 0},
            'motor_activity':         {'max_throttle_out': 0.0,
                                       'motor_test_detected': False},
            'usability_verdict':      'exclude',
            'verdict_reasons':        [reason],
        }


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def _build_summary(inventory: list[dict]) -> dict:
    verdict_counts = collections.Counter(r['usability_verdict'] for r in inventory)

    fingerprints: dict[str, list[str]] = collections.defaultdict(list)
    for r in inventory:
        fp = r.get('parameter_fingerprint', 'unknown')
        fingerprints[fp].append(r['file'])

    # Median logging frequencies across clean_baseline files
    clean = [r for r in inventory if r['usability_verdict'] == 'clean_baseline']
    freq_lists: dict[str, list[float]] = collections.defaultdict(list)
    for r in clean:
        for msg, hz in r.get('logging_frequencies', {}).items():
            freq_lists[msg].append(hz)

    median_freqs = {}
    for msg, vals in freq_lists.items():
        vals.sort()
        median_freqs[msg] = round(vals[len(vals) // 2], 1)

    durations = [
        r['duration_seconds'] for r in inventory
        if r.get('duration_seconds') is not None
    ]
    durations.sort()

    session_counts = collections.Counter(r.get('session_type', 'unknown') for r in inventory)

    return {
        'generated_at':            datetime.now().isoformat(),
        'total_files':             len(inventory),
        'verdict_counts':          dict(verdict_counts),
        'session_type_counts':     dict(session_counts),
        'config_fingerprints':     {
            fp: {'count': len(files), 'files': files}
            for fp, files in sorted(fingerprints.items())
        },
        'median_logging_frequencies_hz': median_freqs,
        'duration_stats': {
            'min_s':    round(durations[0], 1)               if durations else None,
            'max_s':    round(durations[-1], 1)              if durations else None,
            'median_s': round(durations[len(durations)//2], 1) if durations else None,
        },
    }


# ---------------------------------------------------------------------------
# Console summary table
# ---------------------------------------------------------------------------

def _print_summary_table(inventory: list[dict], summary: dict) -> None:
    hdr = f"{'FILE':<20} {'SIZE_KB':>8} {'DUR_S':>7} {'TYPE':<8} {'GPS':>5} {'ARMS':>5} {'ERRS':>5} VERDICT"
    print()
    print(hdr)
    print('-' * len(hdr))

    for r in inventory:
        size_kb  = r['size_bytes'] // 1024
        dur      = r.get('duration_seconds')
        dur_str  = f"{dur:.0f}" if dur is not None else '-'
        stype    = r.get('session_type', 'unk')[:7]
        gps_fix  = 'yes' if r['gps_state']['fix_acquired'] else 'no'
        arms     = r['arming_events']['successful']
        errs     = r['anomaly_indicators']['err_count']
        verdict  = r['usability_verdict']
        print(
            f"{r['file']:<20} {size_kb:>8} {dur_str:>7} {stype:<8} "
            f"{gps_fix:>5} {arms:>5} {errs:>5} {verdict}"
        )

    print()
    print("CORPUS SUMMARY")
    print(f"  Total files         : {summary['total_files']}")
    for verdict, count in sorted(summary['verdict_counts'].items()):
        print(f"  {verdict:<22}: {count}")

    print()
    print(f"  Config fingerprints : {len(summary['config_fingerprints'])} distinct")
    for fp, info in summary['config_fingerprints'].items():
        print(f"    {fp}: {info['count']} files")

    print()
    print("  Logging frequencies (median across clean_baseline files):")
    for msg in ('IMU', 'ATT', 'GPS', 'BARO', 'MAG', 'RCIN', 'MOTB'):
        hz = summary['median_logging_frequencies_hz'].get(msg)
        if hz is not None:
            print(f"    {msg:<6}: {hz:>6.1f} Hz")

    ds = summary['duration_stats']
    if ds['min_s'] is not None:
        print()
        print(f"  Duration -- min: {ds['min_s']}s  "
              f"median: {ds['median_s']}s  max: {ds['max_s']}s")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='SENTINEL corpus characterisation tool'
    )
    parser.add_argument(
        '--data-dir', required=True,
        help='Directory containing DataFlash .BIN files'
    )
    args = parser.parse_args()

    data_dir = pathlib.Path(args.data_dir)
    if not data_dir.is_dir():
        print(f"ERROR: {data_dir} is not a directory")
        sys.exit(1)

    bin_files = sorted(data_dir.glob('*.BIN')) + sorted(data_dir.glob('*.bin'))
    if not bin_files:
        print(f"ERROR: No .BIN files found in {data_dir}")
        sys.exit(1)

    print(f"SENTINEL Corpus Scan -- {datetime.now().isoformat()}")
    print(f"Found {len(bin_files)} BIN files in {data_dir}")
    print()

    inventory = []
    for i, filepath in enumerate(bin_files, 1):
        size_kb = filepath.stat().st_size // 1024
        print(f"  [{i:02d}/{len(bin_files)}] {filepath.name} ({size_kb} KB) ... ", end='', flush=True)
        try:
            result = _FileScanner(filepath).scan()
        except Exception as exc:
            result = {
                'file':                   filepath.name,
                'size_bytes':             filepath.stat().st_size,
                'duration_seconds':       None,
                'session_type':           'unknown',
                'firmware_version':       'unknown',
                'gps_state':              {'fix_acquired': False, 'nsats_max': 0,
                                           'hdop_min': 99.99, 'position_changes': 0},
                'arming_events':          {'count': 0, 'successful': 0, 'failed': 0},
                'message_types_present':  [],
                'logging_frequencies':    {},
                'parameter_fingerprint':  'unknown',
                'safety_critical_params': {},
                'anomaly_indicators':     {'err_count': 0, 'err_codes': [],
                                           'gps_glitches': 0, 'compass_warnings': 0,
                                           'voltage_alerts': 0, 'ekf_warnings': 0,
                                           'arming_failures': 0},
                'motor_activity':         {'max_throttle_out': 0.0,
                                           'motor_test_detected': False},
                'usability_verdict':      'exclude',
                'verdict_reasons':        [f'parse_error: {exc}'],
            }
        inventory.append(result)
        print(result['usability_verdict'])

    summary = _build_summary(inventory)
    _print_summary_table(inventory, summary)

    inv_path = data_dir / 'corpus_inventory.json'
    sum_path = data_dir / 'corpus_summary.json'

    inv_path.write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    sum_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')

    print(f"Written: {inv_path}")
    print(f"Written: {sum_path}")


if __name__ == '__main__':
    main()