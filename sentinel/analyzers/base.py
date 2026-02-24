"""Base classes for SENTINEL analyzers.

Every attack-domain analyzer inherits BaseAnalyzer and returns AnalysisResult.
The engine calls analyze() and explain() -- no other interface required.

Verdict scale:
    CLEAN       -- no indicators detected
    SUSPICIOUS  -- weak or ambiguous indicators, warrants review
    ALERT       -- strong indicators, high confidence
    UNKNOWN     -- insufficient data to assess
"""

import pathlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    CLEAN      = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    ALERT      = "ALERT"
    UNKNOWN    = "UNKNOWN"


# ---------------------------------------------------------------------------
# Finding -- one specific indicator within an analysis
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    check:       str            # e.g. "position_jump"
    verdict:     Verdict
    detail:      str            # human-readable explanation
    value:       Any = None     # the measured value that triggered this
    timestamp_us: int | None = None  # TimeUS of the event if known

    def __str__(self) -> str:
        ts = f" @ {self.timestamp_us}us" if self.timestamp_us else ""
        val = f" [{self.value}]" if self.value is not None else ""
        return f"  {self.check:<28} {self.verdict.value:<12}{val}{ts}  {self.detail}"


# ---------------------------------------------------------------------------
# AnalysisResult -- what every analyzer returns
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    analyzer:    str            # BaseAnalyzer.NAME
    version:     str            # BaseAnalyzer.VERSION
    filepath:    pathlib.Path
    verdict:     Verdict
    confidence:  float          # 0.0 - 1.0
    findings:    list[Finding]  = field(default_factory=list)
    raw_values:  dict[str, Any] = field(default_factory=dict)
    notes:       list[str]      = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'analyzer':   self.analyzer,
            'version':    self.version,
            'file':       self.filepath.name,
            'verdict':    self.verdict.value,
            'confidence': round(self.confidence, 3),
            'findings': [
                {
                    'check':        f.check,
                    'verdict':      f.verdict.value,
                    'detail':       f.detail,
                    'value':        f.value,
                    'timestamp_us': f.timestamp_us,
                }
                for f in self.findings
            ],
            'raw_values': self.raw_values,
            'notes':      self.notes,
        }


# ---------------------------------------------------------------------------
# BaseAnalyzer
# ---------------------------------------------------------------------------

class BaseAnalyzer:
    """Abstract base for all SENTINEL attack-domain analyzers.

    Subclass contract:
        NAME     -- short identifier used in reports and CLI (e.g. "gps_spoof")
        VERSION  -- semantic version string (e.g. "1.0")
        analyze  -- accepts ParseResult, returns AnalysisResult
        explain  -- accepts AnalysisResult, returns human-readable string
    """

    NAME    = ""
    VERSION = "1.0"

    def analyze(self, parse_result: Any) -> AnalysisResult:
        raise NotImplementedError(f"{self.__class__.__name__}.analyze() not implemented")

    def explain(self, result: AnalysisResult) -> str:
        """Render a human-readable report block for this result."""
        lines = [
            f"{'='*60}",
            f"  {result.filepath.name}  --  {self.NAME.upper().replace('_', ' ')} ASSESSMENT",
            f"{'='*60}",
        ]
        for f in result.findings:
            lines.append(str(f))
        lines.append("")
        lines.append(
            f"  VERDICT: {result.verdict.value}  "
            f"(confidence {result.confidence:.0%})"
        )
        for note in result.notes:
            lines.append(f"  NOTE: {note}")
        lines.append("")
        return "\n".join(lines)

    def _insufficient_data(
        self,
        filepath: pathlib.Path,
        reason: str,
    ) -> AnalysisResult:
        return AnalysisResult(
            analyzer=self.NAME,
            version=self.VERSION,
            filepath=filepath,
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            notes=[reason],
        )