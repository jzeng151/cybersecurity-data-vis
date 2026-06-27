"""Semantic color constants for severity.

MIRRORED in app/src/lib/tokens.ts — keep the two in sync; together they are the single
visual-language contract so Python-emitted chart specs agree with TS-rendered charts.
"""

BENIGN = "#5b6b7a"       # calm slate — normal / not a threat
SUSPICIOUS = "#e0a341"   # amber — worth a look
MALICIOUS = "#d2483f"    # red — confirmed bad
NEUTRAL = "#8a94a6"      # grey — unlabeled / noise
ACCENT = "#3b82f6"       # blue — non-severity emphasis

SEVERITY = {"benign": BENIGN, "suspicious": SUSPICIOUS, "malicious": MALICIOUS, "noise": NEUTRAL}
