"""DataFlash binary parser -- shared core module.

Extracted from sentinel/tools/corpus_scan.py.
All analyzers and tools import from here. Single parser in the codebase.

Public API:
    parse_file(filepath)  ->  ParseResult
    ParseResult.schema    ->  dict[int, MessageDef]
    ParseResult.records   ->  list[Record]
    Record.name           ->  str
    Record.fields         ->  dict[str, Any]
    Record.timeus         ->  int | None
"""

import pathlib
import struct
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Binary format constants
# ---------------------------------------------------------------------------

HEADER_BYTE_1   = 0xA3
HEADER_BYTE_2   = 0x95
FMT_TYPE_ID     = 0x80

_FMT_PAYLOAD_STRUCT = struct.Struct("<BB4s16s64s")

_FORMAT_CHARS: dict[str, tuple[str, str]] = {
    'b': ('b',   'int8'),
    'B': ('B',   'uint8'),
    'h': ('h',   'int16'),
    'H': ('H',   'uint16'),
    'i': ('i',   'int32'),
    'I': ('I',   'uint32'),
    'f': ('f',   'float32'),
    'd': ('d',   'float64'),
    'n': ('4s',  'char4'),
    'N': ('16s', 'char16'),
    'Z': ('64s', 'char64'),
    'c': ('h',   'int16_x100'),
    'C': ('H',   'uint16_x100'),
    'e': ('i',   'int32_x100'),
    'E': ('I',   'uint32_x100'),
    'L': ('i',   'lat_lon'),
    'M': ('B',   'flight_mode'),
    'q': ('q',   'int64'),
    'Q': ('Q',   'uint64'),
}

_SCALE_100 = frozenset('cCeE')
_GPS_COORD  = frozenset('L')


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------

@dataclass
class FieldDef:
    name:     str
    fmt_char: str
    type_desc: str


@dataclass
class MessageDef:
    type_id:  int
    length:   int
    name:     str
    format:   str
    fields:   list[FieldDef]
    _struct:  struct.Struct | None = field(repr=False, default=None)


@dataclass
class Record:
    name:   str
    fields: dict[str, Any]

    @property
    def timeus(self) -> int | None:
        v = self.fields.get('TimeUS')
        if isinstance(v, (int, float)) and v > 0:
            return int(v)
        return None

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def __contains__(self, key: str) -> bool:
        return key in self.fields


@dataclass
class ParseResult:
    filepath: pathlib.Path
    schema:   dict[int, MessageDef]
    records:  list[Record]

    @property
    def size_bytes(self) -> int:
        return self.filepath.stat().st_size

    def records_by_type(self, name: str) -> list[Record]:
        """Return all records of a given message type."""
        return [r for r in self.records if r.name == name]

    def has_message(self, name: str) -> bool:
        return any(r.name == name for r in self.records)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decode_value(raw: Any, fmt_char: str) -> Any:
    if isinstance(raw, bytes):
        return raw.rstrip(b'\x00').decode('ascii', errors='replace').strip()
    if fmt_char in _SCALE_100:
        return raw / 100.0
    if fmt_char in _GPS_COORD:
        return raw / 1e7
    return raw


def _parse_fmt_payload(payload: bytes) -> MessageDef | None:
    if len(payload) < _FMT_PAYLOAD_STRUCT.size:
        return None
    try:
        type_id, length, name_b, fmt_b, cols_b = _FMT_PAYLOAD_STRUCT.unpack(
            payload[:_FMT_PAYLOAD_STRUCT.size]
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
    field_defs: list[FieldDef] = []

    for i, ch in enumerate(fmt):
        if ch not in _FORMAT_CHARS:
            continue
        sc, desc = _FORMAT_CHARS[ch]
        struct_fmt += sc
        fname = field_names[i] if i < len(field_names) else f"field_{i}"
        field_defs.append(FieldDef(name=fname, fmt_char=ch, type_desc=desc))

    try:
        compiled = struct.Struct(struct_fmt)
    except struct.error:
        compiled = None

    return MessageDef(
        type_id=type_id,
        length=length,
        name=name,
        format=fmt,
        fields=field_defs,
        _struct=compiled,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_file(filepath: pathlib.Path | str) -> ParseResult:
    """Parse a DataFlash .BIN file.

    Two-pass:
      Pass 1 -- extract FMT records and build schema
      Pass 2 -- decode all message records

    Returns ParseResult with schema and full record list.
    Raises ValueError if file cannot be read or schema is empty.
    """
    filepath = pathlib.Path(filepath)
    if not filepath.exists():
        raise ValueError(f"File not found: {filepath}")

    data  = filepath.read_bytes()
    total = len(data)

    if total < 3:
        raise ValueError(f"File too small to contain DataFlash data: {filepath}")

    # -- Pass 1: schema ------------------------------------------------
    schema: dict[int, MessageDef] = {}
    pos = 0
    while pos < total - 2:
        if data[pos] == HEADER_BYTE_1 and data[pos + 1] == HEADER_BYTE_2:
            if pos + 3 <= total and data[pos + 2] == FMT_TYPE_ID:
                end = pos + 3 + _FMT_PAYLOAD_STRUCT.size
                if end <= total:
                    defn = _parse_fmt_payload(data[pos + 3:end])
                    if defn:
                        schema[defn.type_id] = defn
        pos += 1

    if not schema:
        raise ValueError(f"No FMT records found -- not a valid DataFlash file: {filepath}")

    # -- Pass 2: records -----------------------------------------------
    records: list[Record] = []
    pos = 0

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

        if msg_type not in schema:
            pos += 3
            continue

        defn       = schema[msg_type]
        compiled   = defn._struct
        record_len = defn.length

        if compiled is None or record_len == 0:
            pos += 3
            continue

        payload_end = pos + record_len
        if payload_end > total:
            pos += 1
            continue

        payload = data[pos + 3:payload_end]
        if len(payload) < compiled.size:
            pos += record_len if record_len > 3 else 4
            continue

        try:
            raw_vals = compiled.unpack(payload[:compiled.size])
        except struct.error:
            pos += record_len if record_len > 3 else 4
            continue

        parsed: dict[str, Any] = {}
        for i, fd in enumerate(defn.fields):
            if i < len(raw_vals):
                parsed[fd.name] = _decode_value(raw_vals[i], fd.fmt_char)

        records.append(Record(name=defn.name, fields=parsed))
        pos += record_len if record_len > 3 else 4

    return ParseResult(filepath=filepath, schema=schema, records=records)