"""Field value feature extraction.

Takes raw values from a single JSON field and computes a numeric
feature vector suitable for unsupervised clustering. This is pure
computation -- no ML, no heuristics, no assumptions about what the
data means.

The feature vector captures the statistical fingerprint of a field's
values: how long are they, what characters appear, how much entropy
is present, how consistent is the format, what separators appear,
and how many unique values exist.

These features allow the clustering engine to group fields that
share statistical properties -- without knowing what those properties
mean. Interpretation happens in the labeling stage, not here.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# JSON Flattener
# ---------------------------------------------------------------------------


def flatten_event(event: dict[str, Any], sep: str = ".") -> dict[str, Any]:
    """Flatten a nested JSON event into dot-notation field paths.

    Nested objects produce dotted keys: {"a": {"b": 1}} -> {"a.b": 1}
    Arrays produce indexed keys: {"a": [1, 2]} -> {"a.0": 1, "a.1": 2}
    Null values are preserved as None.

    Args:
        event: Arbitrarily nested JSON dict.
        sep: Separator for nested keys (default: dot).

    Returns:
        Flat dict mapping dot-notation paths to leaf values.
    """
    flat: dict[str, Any] = {}
    _flatten_recursive(event, "", sep, flat)
    return flat


def _flatten_recursive(
    obj: Any, prefix: str, sep: str, out: dict[str, Any]
) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{sep}{k}" if prefix else k
            _flatten_recursive(v, key, sep, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}{sep}{i}" if prefix else str(i)
            _flatten_recursive(v, key, sep, out)
    else:
        out[prefix] = obj


def collect_field_values(
    payloads: list[dict[str, Any]],
) -> dict[str, list[Any]]:
    """Flatten all events and collect values per field path.

    Returns a dict mapping each unique field path to the list of
    observed values across all events. Null values are included
    to enable null-rate computation.
    """
    fields: dict[str, list[Any]] = {}
    for payload in payloads:
        flat = flatten_event(payload)
        seen_in_event: set[str] = set()
        for path, val in flat.items():
            fields.setdefault(path, []).append(val)
            seen_in_event.add(path)
        # Mark fields absent in this event as None
        for existing_path in list(fields.keys()):
            if existing_path not in seen_in_event:
                fields[existing_path].append(None)
    return fields


# ---------------------------------------------------------------------------
# Feature Vector Computation
# ---------------------------------------------------------------------------

# Feature vector indices (for documentation and testing)
FEATURE_NAMES = [
    "mean_length",
    "median_length",
    "stddev_length",
    "min_length",
    "max_length",
    "alpha_ratio",
    "numeric_ratio",
    "hex_ratio",
    "punct_ratio",
    "whitespace_ratio",
    "uppercase_ratio",
    "entropy",
    "format_consistency",
    "dot_separator_ratio",
    "dash_separator_ratio",
    "colon_separator_ratio",
    "slash_separator_ratio",
    "underscore_separator_ratio",
    "at_separator_ratio",
    "mean_separator_count",
    "is_numeric_ratio",
    "numeric_range_span",
    "is_integer_ratio",
    "cardinality_ratio",
    "null_ratio",
    "length_variance_ratio",
    "has_fixed_length",
]

FEATURE_DIM = len(FEATURE_NAMES)


@dataclass
class FieldFeatures:
    """Computed feature vector for a single field with metadata."""
    field_path: str
    vector: list[float]
    sample_count: int
    null_count: int
    unique_count: int
    sample_values: list[str]


def extract_features(field_path: str, values: list[Any]) -> FieldFeatures:
    """Compute the feature vector for a field from its observed values.

    Handles nulls, non-string values, and empty value lists gracefully.
    All features are normalized to [0, 1] or small bounded ranges to
    ensure clustering algorithms treat them comparably.

    Args:
        field_path: Dot-notation field path.
        values: All observed values for this field across sampled events.

    Returns:
        FieldFeatures with the computed vector and metadata.
    """
    total = len(values)
    nulls = sum(1 for v in values if v is None)
    non_null = [v for v in values if v is not None]

    # Convert everything to strings for character analysis
    str_vals = [str(v) for v in non_null]
    unique_vals = set(str_vals)
    unique_count = len(unique_vals)

    # Sample values for profile inspection (up to 10, deduplicated)
    sample = list(unique_vals)[:10]

    if not str_vals:
        return FieldFeatures(
            field_path=field_path,
            vector=[0.0] * FEATURE_DIM,
            sample_count=total,
            null_count=nulls,
            unique_count=0,
            sample_values=[],
        )

    # --- String length statistics ---
    lengths = [len(s) for s in str_vals]
    n = len(lengths)
    mean_len = sum(lengths) / n
    sorted_len = sorted(lengths)
    median_len = float(sorted_len[n // 2])
    var_len = sum((l - mean_len) ** 2 for l in lengths) / n
    std_len = math.sqrt(var_len)
    min_len = float(sorted_len[0])
    max_len = float(sorted_len[-1])

    # Normalize lengths to reasonable range (cap at 1000)
    cap = 1000.0
    mean_len_n = min(mean_len / cap, 1.0)
    median_len_n = min(median_len / cap, 1.0)
    std_len_n = min(std_len / cap, 1.0)
    min_len_n = min(min_len / cap, 1.0)
    max_len_n = min(max_len / cap, 1.0)

    # --- Character distribution ---
    all_chars = "".join(str_vals)
    total_chars = len(all_chars) if all_chars else 1

    alpha_count = sum(1 for c in all_chars if c.isalpha())
    numeric_count = sum(1 for c in all_chars if c.isdigit())
    hex_chars = set("0123456789abcdefABCDEF")
    hex_count = sum(1 for c in all_chars if c in hex_chars)
    punct_count = sum(
        1 for c in all_chars if not c.isalnum() and not c.isspace()
    )
    ws_count = sum(1 for c in all_chars if c.isspace())
    upper_count = sum(1 for c in all_chars if c.isupper())

    alpha_ratio = alpha_count / total_chars
    numeric_ratio = numeric_count / total_chars
    hex_ratio = hex_count / total_chars
    punct_ratio = punct_count / total_chars
    ws_ratio = ws_count / total_chars
    upper_ratio = upper_count / total_chars

    # --- Shannon entropy ---
    char_counts = Counter(all_chars)
    entropy = 0.0
    for count in char_counts.values():
        p = count / total_chars
        if p > 0:
            entropy -= p * math.log2(p)
    # Normalize: max entropy for ASCII printable ~6.6 bits
    entropy_n = min(entropy / 7.0, 1.0)

    # --- Format consistency ---
    # Replace alpha with 'A', digits with 'N', keep separators
    def format_pattern(s: str) -> str:
        out = []
        for c in s:
            if c.isalpha():
                out.append("A")
            elif c.isdigit():
                out.append("N")
            else:
                out.append(c)
        return "".join(out)

    patterns = [format_pattern(s) for s in str_vals]
    pattern_counts = Counter(patterns)
    most_common_count = pattern_counts.most_common(1)[0][1]
    format_consistency = most_common_count / n

    # --- Separator analysis ---
    seps = {"dot": ".", "dash": "-", "colon": ":", "slash": "/",
            "underscore": "_", "at": "@"}
    sep_ratios = {}
    sep_counts_list: list[float] = []
    for name, ch in seps.items():
        counts = [s.count(ch) for s in str_vals]
        has_sep = sum(1 for c in counts if c > 0)
        sep_ratios[name] = has_sep / n
        sep_counts_list.extend(counts)

    mean_sep_count = (
        sum(sep_counts_list) / len(sep_counts_list)
        if sep_counts_list else 0.0
    )
    # Normalize separator count
    mean_sep_n = min(mean_sep_count / 10.0, 1.0)

    # --- Numeric properties ---
    numeric_parseable = 0
    numeric_values: list[float] = []
    int_count = 0
    for s in str_vals:
        try:
            fv = float(s)
            numeric_parseable += 1
            numeric_values.append(fv)
            if s.lstrip("-").isdigit():
                int_count += 1
        except (ValueError, OverflowError):
            pass

    is_numeric_ratio = numeric_parseable / n
    numeric_range = 0.0
    if numeric_values:
        nr = max(numeric_values) - min(numeric_values)
        # Normalize: cap at 100000
        numeric_range = min(nr / 100000.0, 1.0)
    is_int_ratio = int_count / n if n > 0 else 0.0

    # --- Cardinality ---
    cardinality = unique_count / n if n > 0 else 0.0

    # --- Null ratio ---
    null_ratio = nulls / total if total > 0 else 0.0

    # --- Length variance ratio (tight = fixed format) ---
    length_var_ratio = (
        min(var_len / (mean_len ** 2 + 1e-10), 1.0) if mean_len > 0 else 0.0
    )

    # --- Fixed length indicator ---
    has_fixed_length = 1.0 if (max_len == min_len and n > 1) else 0.0

    vector = [
        mean_len_n,
        median_len_n,
        std_len_n,
        min_len_n,
        max_len_n,
        alpha_ratio,
        numeric_ratio,
        hex_ratio,
        punct_ratio,
        ws_ratio,
        upper_ratio,
        entropy_n,
        format_consistency,
        sep_ratios["dot"],
        sep_ratios["dash"],
        sep_ratios["colon"],
        sep_ratios["slash"],
        sep_ratios["underscore"],
        sep_ratios["at"],
        mean_sep_n,
        is_numeric_ratio,
        numeric_range,
        is_int_ratio,
        cardinality,
        null_ratio,
        length_var_ratio,
        has_fixed_length,
    ]

    return FieldFeatures(
        field_path=field_path,
        vector=vector,
        sample_count=total,
        null_count=nulls,
        unique_count=unique_count,
        sample_values=sample,
    )