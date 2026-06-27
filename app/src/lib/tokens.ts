// Visual-language contract. MIRRORED in analysis/src/cyberviz/colors.py and globals.css @theme.
// Keep all three in sync — Python emits chart specs using these hexes; TS renders with them.

export const SEVERITY = {
  benign: "#5b6b7a",
  suspicious: "#e0a341",
  malicious: "#d2483f",
  noise: "#8a94a6",
} as const;

export const ACCENT = "#3b82f6";

export type Severity = keyof typeof SEVERITY;

// The artifact bundle version the app reads. Bump in lockstep with paths.py BUNDLE_VERSION.
export const BUNDLE_VERSION = "v2";

// Honesty-flag display labels for fit ratings. ("forced" fits are never emitted, only documented.)
export const FIT_LABEL: Record<string, string> = {
  strong: "strong fit",
  moderate: "moderate fit",
  forced: "forced fit",
};

// Map technique keys to the hex.tech technique names for display.
export const TECHNIQUE_LABEL: Record<string, string> = {
  cluster: "Cluster analysis",
  cohort: "Cohort analysis",
  timeseries: "Time-series analysis",
  regression: "Regression",
  pca_factor: "Factor analysis (PCA)",
  monte_carlo: "Monte Carlo",
  text_sentiment: "Sentiment / text",
};

// The four dataset families from the source-doc inventory.
export const CATEGORY_LABEL: Record<string, string> = {
  "network-flow": "Network / flow",
  "host-log": "Host / endpoint log",
  "threat-intel": "Threat intelligence",
  "phishing-email": "Phishing / email",
};

// Stable display order for the four categories on the index.
export const CATEGORY_ORDER = ["network-flow", "host-log", "threat-intel", "phishing-email"] as const;
