"""DataFlash Binary Investigation Tool.

Stage 1 of UAV data discovery for GRASP.
No external dependencies - standard library only.

Purpose:
    Discover the structure and content of ArduPilot DataFlash .BIN files
    from first principles. No prior schema knowledge assumed.

What this script does:
    1. Reads raw binary and identifies the DataFlash format signature
    2. Extracts the embedded schema from FMT records (self-describing format)
    3. Counts records per message type across the full file
    4. Samples up to 5 values per field from each message type
    5. Computes basic statistics per field (min, max, unique count)
    6. Writes a human-readable report for session documentation

Usage:
    python3 tools/mavlink/investigate.py

Output:
    - stdout: progress and summary
    - tools/mavlink/investigation_report.txt: full report
"""

import struct
import collections
import json
import pathlib
import sys
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# DataFlash binary format constants
# ---------------------------------------------------------------------------

# Every DataFlash record starts with these two header bytes
HEADER_BYTE_1 = 0xA3
HEADER_BYTE_2 = 0x95

# FMT message type ID - defines all other message types
FMT_TYPE_ID = 0x80  # 128 decimal

# FMT record structure (fixed, always 89 bytes total including 3-byte header)
# Header:  2 bytes (0xA3 0x95)
# Type:    1 byte  (0x80 for FMT)
# Payload: 86 bytes
#   type_id:   1 byte  - the message type this FMT record defines
#   length:    1 byte  - total record length including header
#   name:      4 bytes - message name (null-padded)
#   format:    16 bytes - format string (one char per field)
#   columns:   64 bytes - comma-separated field names (null-padded)
FMT_PAYLOAD_STRUCT = struct.Struct("<BB4s16s64s")

# Format character to Python struct character and description
# These are the ArduPilot DataFlash format codes
FORMAT_CHARS = {
    'b': ('b', 'int8'),
    'B': ('B', 'uint8'),
    'h': ('h', 'int16'),
    'H': ('H', 'uint16'),
    'i': ('i', 'int32'),
    'I': ('I', 'uint32'),
    'f': ('f', 'float32'),
    'd': ('d', 'float64'),
    'n': ('4s', 'char[4]'),
    'N': ('16s', 'char[16]'),
    'Z': ('64s', 'char[64]'),
    'c': ('h', 'int16_scaled_100'),   # value / 100
    'C': ('H', 'uint16_scaled_100'),  # value / 100
    'e': ('i', 'int32_scaled_100'),   # value / 100
    'E': ('I', 'uint32_scaled_100'),  # value / 100
    'L': ('i', 'int32_lat_lon'),      # value / 1e7 (GPS coords)
    'M': ('B', 'flight_mode'),
    'q': ('q', 'int64'),
    'Q': ('Q', 'uint64'),
}

SCALE_100 = {'c', 'C', 'e', 'E'}
GPS_COORD = {'L'}


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

class Report:
    """Accumulates report lines and writes to file and stdout."""

    def __init__(self, path: pathlib.Path):
        self._path = path
        self._lines: list[str] = []

    def line(self, text: str = "") -> None:
        self._lines.append(text)
        print(text)

    def save(self) -> None:
        self._path.write_text("\n".join(self._lines), encoding="utf-8")
        print(f"\nReport saved to: {self._path}")


# ---------------------------------------------------------------------------
# FMT record parser
# ---------------------------------------------------------------------------

def parse_fmt_payload(payload: bytes) -> dict | None:
    """Parse a FMT record payload into a message type definition.

    Returns None if the record is malformed.
    """
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

    # Build struct format for this message type
    struct_fmt = '<'
    field_defs = []
    for i, ch in enumerate(fmt):
        if ch not in FORMAT_CHARS:
            # Unknown format char - skip gracefully
            continue
        sc, desc = FORMAT_CHARS[ch]
        struct_fmt += sc
        fname = field_names[i] if i < len(field_names) else f"field_{i}"
        field_defs.append({
            'name': fname,
            'fmt_char': ch,
            'type_desc': desc,
        })

    try:
        compiled = struct.Struct(struct_fmt)
    except struct.error:
        compiled = None

    return {
        'type_id': type_id,
        'length': length,
        'name': name,
        'format': fmt,
        'fields': field_defs,
        'struct': compiled,
    }


# ---------------------------------------------------------------------------
# Value decoder
# ---------------------------------------------------------------------------

def decode_value(raw, fmt_char: str):
    """Convert raw parsed value to a human-readable Python value."""
    if isinstance(raw, bytes):
        return raw.rstrip(b'\x00').decode('ascii', errors='replace').strip()
    if fmt_char in SCALE_100:
        return raw / 100.0
    if fmt_char in GPS_COORD:
        return raw / 1e7
    return raw


# ---------------------------------------------------------------------------
# Core file scanner
# ---------------------------------------------------------------------------

def scan_file(filepath: pathlib.Path, report: Report) -> dict:
    """Scan a single DataFlash .BIN file.

    Pass 1: Extract all FMT records to build the schema.
    Pass 2: Parse all data records, count by type, sample values.

    Returns a summary dict for cross-file comparison.
    """
    report.line(f"\n{'='*70}")
    report.line(f"FILE: {filepath.name}  ({filepath.stat().st_size:,} bytes)")
    report.line(f"{'='*70}")

    data = filepath.read_bytes()
    total_bytes = len(data)

    # ------------------------------------------------------------------
    # Pass 1: Extract schema from FMT records
    # ------------------------------------------------------------------
    report.line("\n-- PASS 1: Schema Discovery --")

    schema: dict[int, dict] = {}   # type_id -> message def
    pos = 0
    fmt_count = 0
    header_found = False

    while pos < total_bytes - 2:
        if data[pos] == HEADER_BYTE_1 and data[pos + 1] == HEADER_BYTE_2:
            if not header_found:
                report.line(f"DataFlash header signature found at byte {pos}")
                header_found = True
            if pos + 3 > total_bytes:
                break
            msg_type = data[pos + 2]
            if msg_type == FMT_TYPE_ID:
                # FMT record: header(2) + type(1) + payload(86)
                payload_start = pos + 3
                payload_end   = payload_start + FMT_PAYLOAD_STRUCT.size
                if payload_end <= total_bytes:
                    payload = data[payload_start:payload_end]
                    defn = parse_fmt_payload(payload)
                    if defn:
                        schema[defn['type_id']] = defn
                        fmt_count += 1
        pos += 1

    if not header_found:
        report.line("ERROR: No DataFlash header signature found. File may be corrupt.")
        return {}

    report.line(f"Schema records (FMT) found: {fmt_count}")
    report.line(f"Message types defined:      {len(schema)}")

    # ------------------------------------------------------------------
    # Pass 2: Parse all records, count and sample
    # ------------------------------------------------------------------
    report.line("\n-- PASS 2: Record Scan --")

    type_counts: dict[int, int] = collections.defaultdict(int)
    # field samples: msg_name -> field_name -> list of values (up to 5)
    field_samples: dict[str, dict[str, list]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )
    # field stats: msg_name -> field_name -> set of unique values (capped)
    field_uniques: dict[str, dict[str, set]] = collections.defaultdict(
        lambda: collections.defaultdict(set)
    )
    field_min: dict[str, dict[str, float]] = collections.defaultdict(dict)
    field_max: dict[str, dict[str, float]] = collections.defaultdict(dict)

    unknown_types: set[int] = set()
    parse_errors = 0
    total_records = 0
    pos = 0

    while pos < total_bytes - 2:
        if data[pos] != HEADER_BYTE_1 or data[pos + 1] != HEADER_BYTE_2:
            pos += 1
            continue

        if pos + 3 > total_bytes:
            break

        msg_type = data[pos + 2]
        type_counts[msg_type] += 1
        total_records += 1

        if msg_type == FMT_TYPE_ID:
            # Skip FMT records in pass 2 (already processed)
            pos += 89
            continue

        if msg_type not in schema:
            unknown_types.add(msg_type)
            pos += 3
            continue

        defn = schema[msg_type]
        msg_name = defn['name']
        compiled = defn['struct']
        record_len = defn['length']

        if compiled is None or record_len == 0:
            pos += 3
            continue

        # Record: header(2) + type(1) + payload
        payload_start = pos + 3
        payload_end   = pos + record_len
        if payload_end > total_bytes:
            pos += 1
            continue

        payload = data[payload_start:payload_end]
        expected = compiled.size

        if len(payload) < expected:
            parse_errors += 1
            pos += record_len if record_len > 3 else 4
            continue

        try:
            values = compiled.unpack(payload[:expected])
        except struct.error:
            parse_errors += 1
            pos += record_len if record_len > 3 else 4
            continue

        for i, field_def in enumerate(defn['fields']):
            if i >= len(values):
                break
            fname = field_def['name']
            fchar = field_def['fmt_char']
            val   = decode_value(values[i], fchar)

            # Sample up to 5 values per field
            samples = field_samples[msg_name][fname]
            if len(samples) < 5:
                samples.append(val)

            # Track unique values (cap at 500 to control memory)
            uniq = field_uniques[msg_name][fname]
            if len(uniq) < 500:
                uniq.add(val if not isinstance(val, float)
                         else round(val, 6))

            # Track numeric min/max
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                mn = field_min[msg_name]
                mx = field_max[msg_name]
                if fname not in mn or val < mn[fname]:
                    mn[fname] = val
                if fname not in mx or val > mx[fname]:
                    mx[fname] = val

        pos += record_len if record_len > 3 else 4

    report.line(f"Total records scanned:  {total_records:,}")
    report.line(f"Parse errors:           {parse_errors:,}")
    report.line(f"Unknown type IDs:       {len(unknown_types)}")

    # ------------------------------------------------------------------
    # Schema report
    # ------------------------------------------------------------------
    report.line("\n-- DISCOVERED SCHEMA --")
    report.line(f"{'MSG':<12} {'TYPE_ID':<8} {'FORMAT':<20} FIELDS")
    report.line("-" * 70)

    for type_id in sorted(schema.keys()):
        defn = schema[type_id]
        field_names = [f['name'] for f in defn['fields']]
        report.line(
            f"{defn['name']:<12} {type_id:<8} {defn['format']:<20} "
            f"{', '.join(field_names)}"
        )

    # ------------------------------------------------------------------
    # Record counts
    # ------------------------------------------------------------------
    report.line("\n-- RECORD COUNTS BY MESSAGE TYPE --")
    report.line(f"{'MSG':<12} {'TYPE_ID':<8} {'COUNT':>10}  {'% of total':>10}")
    report.line("-" * 50)

    sorted_counts = sorted(
        type_counts.items(), key=lambda x: x[1], reverse=True
    )
    for type_id, count in sorted_counts:
        if type_id in schema:
            name = schema[type_id]['name']
        elif type_id == FMT_TYPE_ID:
            name = 'FMT'
        else:
            name = f'UNKNOWN_{type_id}'
        pct = count / total_records * 100 if total_records > 0 else 0
        report.line(f"{name:<12} {type_id:<8} {count:>10,}  {pct:>9.1f}%")

    # ------------------------------------------------------------------
    # Field samples and statistics
    # ------------------------------------------------------------------
    report.line("\n-- FIELD SAMPLES AND STATISTICS --")

    for msg_name in sorted(field_samples.keys()):
        count = type_counts.get(
            next((tid for tid, d in schema.items()
                  if d['name'] == msg_name), -1), 0
        )
        report.line(f"\n  [{msg_name}]  ({count:,} records)")

        defn = next(
            (d for d in schema.values() if d['name'] == msg_name), None
        )

        for field_def in (defn['fields'] if defn else []):
            fname = field_def['name']
            ftype = field_def['type_desc']
            samples = field_samples[msg_name].get(fname, [])
            uniq    = field_uniques[msg_name].get(fname, set())
            mn      = field_min.get(msg_name, {}).get(fname, None)
            mx      = field_max.get(msg_name, {}).get(fname, None)

            sample_str = ', '.join(str(v) for v in samples[:5])
            uniq_str   = f"{len(uniq)} unique"
            range_str  = (f"  range=[{mn}, {mx}]"
                          if mn is not None else "")

            report.line(
                f"    {fname:<20} ({ftype:<22})  "
                f"samples=[{sample_str}]  "
                f"{uniq_str}{range_str}"
            )

    # ------------------------------------------------------------------
    # Summary dict for cross-file comparison
    # ------------------------------------------------------------------
    return {
        'file': filepath.name,
        'size_bytes': total_bytes,
        'total_records': total_records,
        'message_types': sorted(
            [schema[tid]['name']
             for tid in type_counts if tid in schema]
        ),
        'record_counts': {
            schema[tid]['name']: cnt
            for tid, cnt in type_counts.items()
            if tid in schema
        },
        'schema_field_count': sum(
            len(d['fields']) for d in schema.values()
        ),
    }


# ---------------------------------------------------------------------------
# Cross-file comparison
# ---------------------------------------------------------------------------

def compare_files(summaries: list[dict], report: Report) -> None:
    """Compare schema and record distribution across files."""
    if len(summaries) < 2:
        return

    report.line(f"\n{'='*70}")
    report.line("CROSS-FILE COMPARISON")
    report.line(f"{'='*70}")

    all_types = set()
    for s in summaries:
        all_types.update(s.get('message_types', []))

    report.line(f"\n{'MSG TYPE':<16}", )
    header = f"{'MSG TYPE':<16}" + "".join(
        f"{s['file'][:20]:>22}" for s in summaries
    )
    report.line(header)
    report.line("-" * (16 + 22 * len(summaries)))

    for msg in sorted(all_types):
        row = f"{msg:<16}"
        for s in summaries:
            cnt = s.get('record_counts', {}).get(msg, 0)
            row += f"{cnt:>22,}"
        report.line(row)

    report.line("\nSummary:")
    for s in summaries:
        report.line(
            f"  {s['file']}: {s['total_records']:,} total records, "
            f"{len(s['message_types'])} message types, "
            f"{s['schema_field_count']} total fields defined"
        )

    # Types present in one file but not the other
    if len(summaries) == 2:
        types_a = set(summaries[0].get('message_types', []))
        types_b = set(summaries[1].get('message_types', []))
        only_a  = types_a - types_b
        only_b  = types_b - types_a
        common  = types_a & types_b
        report.line(f"\n  Common message types:           {len(common)}")
        report.line(f"  Only in {summaries[0]['file']}: {sorted(only_a)}")
        report.line(f"  Only in {summaries[1]['file']}: {sorted(only_b)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    tools_dir = pathlib.Path(__file__).parent
    bin_files  = sorted(tools_dir.glob("*.BIN")) + sorted(tools_dir.glob("*.bin"))

    if not bin_files:
        print("No .BIN files found in tools/mavlink/")
        print("Expected: tools/mavlink/00000028.BIN  tools/mavlink/00000029.BIN")
        sys.exit(1)

    report_path = tools_dir / "investigation_report.txt"
    report = Report(report_path)

    report.line("GRASP - DataFlash Binary Investigation Report")
    report.line(f"Generated: {datetime.now().isoformat()}")
    report.line(f"Files found: {len(bin_files)}")
    for f in bin_files:
        report.line(f"  {f.name}  ({f.stat().st_size:,} bytes)")

    summaries = []
    for filepath in bin_files:
        summary = scan_file(filepath, report)
        if summary:
            summaries.append(summary)

    if len(summaries) > 1:
        compare_files(summaries, report)

    report.line(f"\n{'='*70}")
    report.line("END OF REPORT")
    report.line(f"{'='*70}")

    report.save()


if __name__ == "__main__":
    main()