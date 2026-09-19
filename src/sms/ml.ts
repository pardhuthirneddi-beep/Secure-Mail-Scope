/**
 * ML layer: risk classification and anomaly detection.
 *
 * Design contract:
 * - Features are extracted deterministically from evidence.
 * - The risk classifier is a simple logistic-regression model with fixed,
 *   published weights (inspectable, reproducible, offline).
 * - Anomaly detection uses an Isolation Forest-style ensemble over the
 *   session feature space, trained on the current capture population.
 * - The ML layer NEVER overrules deterministic facts; it classifies risk and
 *   prioritizes. It outputs labels and scores, and its output is always
 *   labeled "AI-Assessed".
 */

export interface SessionFeatures {
  tlsVersionRank: number; // 0..4 (SSL3.0..TLS1.3), -1 when no TLS
  hasTls: 0 | 1;
  forwardSecrecy: number; // 1 true, 0 false, 0.5 unknown
  cipherStrength: number; // 0..1 from rule classification
  certExpired: 0 | 1;
  certSelfSigned: 0 | 1;
  certWeakKey: 0 | 1;
  certChainUnavailable: 0 | 1;
  starttlsFailed: 0 | 1;
  plaintextSession: 0 | 1;
  findingCriticalCount: number;
  findingHighCount: number;
  findingMediumCount: number;
  findingLowCount: number;
  recordCountNorm: number; // normalized handshake record count
}

export const FEATURE_NAMES: (keyof SessionFeatures)[] = [
  "tlsVersionRank",
  "hasTls",
  "forwardSecrecy",
  "cipherStrength",
  "certExpired",
  "certSelfSigned",
  "certWeakKey",
  "certChainUnavailable",
  "starttlsFailed",
  "plaintextSession",
  "findingCriticalCount",
  "findingHighCount",
  "findingMediumCount",
  "findingLowCount",
  "recordCountNorm",
];

export type RiskLabel = "Low" | "Medium" | "High" | "Critical";

/**
 * Logistic risk model with published weights. Two heads:
 * - "attack surface" head: probability the session needs urgent attention
 * - Each output includes per-factor contributions for the AI transparency panel.
 */
export const RISK_MODEL_WEIGHTS: Record<string, number> = {
  bias: -2.6,
  tlsVersionRank: -0.55,
  hasTls: 0.4,
  forwardSecrecy: -0.5,
  cipherStrength: -0.8,
  certExpired: 1.9,
  certSelfSigned: 1.1,
  certWeakKey: 1.4,
  certChainUnavailable: 0.4,
  starttlsFailed: 1.6,
  plaintextSession: 2.1,
  findingCriticalCount: 0.9,
  findingHighCount: 0.55,
  findingMediumCount: 0.2,
  findingLowCount: 0.05,
  recordCountNorm: 0.1,
};

function sigmoid(z: number): number {
  return 1 / (1 + Math.exp(-z));
}

export interface RiskModelOutput {
  pUrgent: number; // 0..1
  label: RiskLabel;
  contributions: Array<{ feature: string; value: number; weight: number; contribution: number }>;
}

export function riskModelPredict(f: SessionFeatures): RiskModelOutput {
  const weights = RISK_MODEL_WEIGHTS;
  let z = weights.bias;
  const contributions: RiskModelOutput["contributions"] = [];
  for (const name of FEATURE_NAMES) {
    const value = f[name];
    const weight = weights[name];
    const c = value * weight;
    z += c;
    if (c !== 0) {
      contributions.push({ feature: name, value, weight, contribution: c });
    }
  }
  const pUrgent = sigmoid(z);
  let label: RiskLabel;
  if (pUrgent >= 0.9) label = "Critical";
  else if (pUrgent >= 0.65) label = "High";
  else if (pUrgent >= 0.3) label = "Medium";
  else label = "Low";
  contributions.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  return { pUrgent, label, contributions };
}

// ---------------------------------------------------------------------------
// Anomaly detection: Isolation Forest-style ensemble
// ---------------------------------------------------------------------------

interface IfTree {
  featureIndex: number;
  threshold: number;
  left: IfTree | null;
  right: IfTree | null;
  size: number;
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildIfTree(
  data: number[][],
  depth: number,
  maxDepth: number,
  rng: () => number,
): IfTree {
  const size = data.length;
  if (depth >= maxDepth || size <= 1) {
    return { featureIndex: -1, threshold: 0, left: null, right: null, size };
  }
  const featureIndex = Math.floor(rng() * data[0].length);
  const values = data.map((row) => row[featureIndex]);
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (min === max) {
    return { featureIndex: -1, threshold: 0, left: null, right: null, size };
  }
  const threshold = min + rng() * (max - min);
  const leftData = data.filter((row) => row[featureIndex] < threshold);
  const rightData = data.filter((row) => row[featureIndex] >= threshold);
  return {
    featureIndex,
    threshold,
    left: buildIfTree(leftData, depth + 1, maxDepth, rng),
    right: buildIfTree(rightData, depth + 1, maxDepth, rng),
    size,
  };
}

function pathLength(tree: IfTree, row: number[], depth: number): number {
  if (tree.featureIndex === -1 || tree.left === null || tree.right === null) {
    return depth;
  }
  const next = row[tree.featureIndex] < tree.threshold ? tree.left : tree.right;
  return pathLength(next, row, depth + 1);
}

function cFactor(n: number): number {
  if (n <= 1) return 0;
  return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1)) / n;
}

export interface AnomalyModel {
  trees: IfTree[];
  n: number;
  featureNames: string[];
}

/** Train an Isolation Forest-style ensemble on the capture population. */
export function trainAnomalyModel(
  rows: number[][],
  featureNames: string[],
  nTrees: number = 64,
  seed: number = 20260101,
): AnomalyModel {
  const rng = mulberry32(seed);
  const trees: IfTree[] = [];
  const sampleSize = Math.min(rows.length, 128);
  const maxDepth = Math.ceil(Math.log2(Math.max(sampleSize, 2)));
  for (let t = 0; t < nTrees; t++) {
    // subsample
    const idx: number[] = [];
    for (let i = 0; i < sampleSize; i++) {
      idx.push(Math.floor(rng() * rows.length));
    }
    const sample = idx.map((i) => rows[i]);
    trees.push(buildIfTree(sample, 0, maxDepth, rng));
  }
  return { trees, n: rows.length, featureNames };
}

export interface AnomalyScore {
  score: number; // 0..1, higher = more anomalous
  classification: "normal" | "unusual";
  depthStats: { mean: number; expected: number };
}

export function scoreAnomaly(model: AnomalyModel, row: number[]): AnomalyScore {
  if (model.trees.length === 0 || row.length === 0) {
    return { score: 0, classification: "normal", depthStats: { mean: 0, expected: 0 } };
  }
  let sum = 0;
  for (const tree of model.trees) {
    sum += pathLength(tree, row, 0);
  }
  const meanDepth = sum / model.trees.length;
  const expected = cFactor(Math.min(model.n, 128));
  const score = Math.pow(2, -meanDepth / (expected || 1));
  // Threshold: scores above the capture's typical band are "unusual".
  // 0.62 chosen by validating against labeled synthetic scenarios (see docs).
  const classification = score > 0.62 ? "unusual" : "normal";
  return { score, classification, depthStats: { mean: meanDepth, expected } };
}

/**
 * Calibrate the anomaly threshold on this capture: an adaptive cut at the
 * 90th percentile of population scores, floored at 0.62, when the population
 * is large enough. Keeps single-session captures from false-flagging.
 */
export function calibrateThreshold(model: AnomalyModel, rows: number[][]): number {
  if (rows.length < 8) return 0.62;
  const scores = rows.map((r) => scoreAnomaly(model, r).score);
  scores.sort((a, b) => a - b);
  const p90 = scores[Math.floor(scores.length * 0.9)];
  return Math.max(0.62, p90);
}
