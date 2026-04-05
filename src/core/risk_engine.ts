/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Risk Scoring Engine
 *
 *  Simple weighted additive scoring. No kill-chain.
 *  Scores from parent AND phantom packages combined.
 *  Gemini results add weight when present.
 *
 *  Adapted to P2's actual scanner output format:
 *    All scanners return { category: string[] }
 *    (flat string arrays, not structured objects)
 *
 *  Weights:
 *    phantom:          +50
 *    scripts:          +40
 *    exec:             +35
 *    eval:             +30
 *    network:          +25
 *    fs:               +25
 *    entropy:          +20
 *    gemini_malicious: +30
 *
 *  Score is NOT capped — a truly malicious package can score 255+.
 * ═══════════════════════════════════════════════════════════
 */

import { RiskInput, RiskScore } from '../types';

// ═════════════════════════════════════════════════════════════
//  EXPORTED INTERFACES
// ═════════════════════════════════════════════════════════════

/** Gemini typosquat/slopsquat classification */
export interface GeminiTyposquatResult {
  verdict: 'legitimate' | 'typosquat' | 'slopsquat';
  confidence: number;
  reasoning: string;
}

/** Gemini script analysis */
export interface GeminiScriptResult {
  verdict: 'safe' | 'suspicious' | 'malicious';
  risk_level: string;
  techniques: string[];
  reasoning: string;
}

/** Gemini domain trust verdict */
export type DomainDecision = 'SAFE_NECESSARY' | 'SAFE_UNNECESSARY' | 'SUSPICIOUS' | 'MALICIOUS';

export interface GeminiDomainVerdict {
  domain: string;
  decision: DomainDecision;
  confidence: number;
  risk_score: number;
  reasoning: string;
  signals: {
    known_service: boolean;
    data_collection_pattern: boolean;
    uses_https: boolean;
    suspicious_keywords: string[];
    ip_based: boolean;
  };
}

/** Gemini false positive validation result */
export interface GeminiValidationResult {
  false_positives: string[];
  confirmed_threats: string[];
  reasoning: Record<string, string>;
}

/** Combined Gemini results — null if not invoked */
export interface GeminiResults {
  typosquat?: GeminiTyposquatResult;
  script?: GeminiScriptResult;
  domainVerdicts?: GeminiDomainVerdict[];
  validation?: GeminiValidationResult;
}

/**
 * P2's actual scanner output format.
 * All categories are flat string[] arrays of human-readable findings.
 */
export interface ScannerOutput {
  scripts: string[];
  network: string[];
  entropy: string[];
  fs: string[];
  exec: string[];
  eval: string[];
}

/** Scan results from a recursive phantom package scan */
export interface PhantomScanResult {
  packageName: string;
  packageVersion: string;
  scannerOutput: ScannerOutput;
  gemini?: GeminiResults | null;
}

/**
 * Full input to the risk engine.
 * Works with P2's actual string[] format.
 */
export interface FullScanInput {
  packageName: string;
  packageVersion: string;
  ecosystem?: string;
  /** Phantom dependency names from comparator */
  phantomDeps: string[];
  /** Dependencies both declared AND found in source — used for ratio scoring */
  usedDeps?: string[];
  /** Total source file count in the extracted package — used for compiled package dampening */
  totalFileCount?: number;
  /** P2's scanner output for the parent package */
  scannerOutput: ScannerOutput;
  /** Gemini results for parent (null if not invoked) */
  gemini?: GeminiResults | null;
  /** Recursive scan results from each phantom dependency */
  phantomScanResults?: PhantomScanResult[];
}

/** Per-category score breakdown */
export interface FullRiskBreakdown {
  phantom: number;
  scripts: number;
  exec: number;
  eval: number;
  network: number;
  fs: number;
  entropy: number;
  gemini: number;
  geminiDeduction: number;
  phantomPackages: number;
}

/** Full scoring result */
export interface FullRiskScore {
  total: number;
  breakdown: FullRiskBreakdown;
  phantomDetails: Array<{
    packageName: string;
    score: number;
    signals: Partial<FullRiskBreakdown>;
  }>;
}

// ═════════════════════════════════════════════════════════════
//  WEIGHTS
// ═════════════════════════════════════════════════════════════

export const WEIGHTS = {
  phantom: 50,
  scripts: 40,
  exec: 35,
  eval: 30,
  network: 25,
  fs: 25,
  entropy: 20,
  gemini_malicious: 30,
} as const;

// ═════════════════════════════════════════════════════════════
//  SCORING HELPERS
// ═════════════════════════════════════════════════════════════

/**
 * Scores a ScannerOutput (P2's string[] format).
 * Binary check: if a category has any findings, add its weight.
 */
function scoreScannerOutput(
  output: ScannerOutput | undefined
): Omit<FullRiskBreakdown, 'phantom' | 'gemini' | 'geminiDeduction' | 'phantomPackages'> {
  // Defensive: handle undefined/null from upstream
  const scripts = output?.scripts || [];
  const exec = output?.exec || [];
  const evalArr = output?.eval || [];
  const network = output?.network || [];
  const fs = output?.fs || [];
  const entropy = output?.entropy || [];

  return {
    scripts: scripts.length > 0 ? WEIGHTS.scripts : 0,
    exec: exec.length > 0 ? WEIGHTS.exec : 0,
    eval: evalArr.length > 0 ? WEIGHTS.eval : 0,
    network: network.length > 0 ? WEIGHTS.network : 0,
    fs: fs.length > 0 ? WEIGHTS.fs : 0,
    entropy: entropy.length > 0 ? WEIGHTS.entropy : 0,
  };
}

/**
 * Scores Gemini results. Adds weight only for non-legitimate / malicious verdicts.
 * Domain verdicts modulate the network score:
 *   SAFE_NECESSARY  → -15 (verified safe, reduce false positives)
 *   SAFE_UNNECESSARY → +5  (analytics/tracking, slight concern)
 *   SUSPICIOUS       → +15 (unknown domain, raise alert)
 *   MALICIOUS        → +40 (confirmed threat)
 */
function scoreGemini(gemini: GeminiResults | null | undefined): number {
  if (!gemini) return 0;
  let score = 0;

  if (gemini.typosquat && gemini.typosquat.verdict !== 'legitimate') {
    score += WEIGHTS.gemini_malicious;
  }
  if (gemini.script && gemini.script.verdict === 'malicious') {
    score += WEIGHTS.gemini_malicious;
  }

  // Domain trust verdicts
  if (gemini.domainVerdicts && gemini.domainVerdicts.length > 0) {
    let domainAdj = 0;
    for (const v of gemini.domainVerdicts) {
      switch (v.decision) {
        case 'SAFE_NECESSARY':  domainAdj -= 15; break;
        case 'SAFE_UNNECESSARY': domainAdj += 5;  break;
        case 'SUSPICIOUS':       domainAdj += 15; break;
        case 'MALICIOUS':        domainAdj += 40; break;
      }
    }
    // If ALL are safe & necessary, fully negate network weight
    const allSafe = gemini.domainVerdicts.every(v => v.decision === 'SAFE_NECESSARY');
    if (allSafe) domainAdj = -25;
    // Clamp: don't let adjustment go below -25 or above +80
    score += Math.max(-25, Math.min(80, domainAdj));
  }

  return score;
}

// ═════════════════════════════════════════════════════════════
//  MAIN EXPORTS
// ═════════════════════════════════════════════════════════════

/**
 * Full risk calculation with recursive phantom scanning support.
 *
 * @param input - Full scan input (parent + phantoms + gemini)
 * @returns FullRiskScore with total, breakdown, and phantom details
 */
export function calculateFullRisk(input: FullScanInput): FullRiskScore {
  // 1. Phantom deps score — proportional, ratio-based
  const phantomDeps = input.phantomDeps || [];
  const usedDeps = input.usedDeps || [];
  const totalDeclaredDeps = phantomDeps.length + usedDeps.length;
  const phantomRatio = totalDeclaredDeps > 0 ? phantomDeps.length / totalDeclaredDeps : 0;

  let phantomScore = 0;
  if (phantomDeps.length === 0) {
    phantomScore = 0;
  } else if (phantomDeps.length <= 2 && phantomRatio > 0.3) {
    // 1-2 phantom deps making up a large chunk of a small package → very suspicious
    phantomScore = 50;
  } else if (phantomRatio > 0.5) {
    // More than half the declared deps are phantom → suspicious
    phantomScore = 40;
  } else if (phantomRatio > 0.2) {
    // Moderate ratio → likely compiled package with import erasure
    phantomScore = 15;
  } else {
    // Very low ratio → almost certainly a compiled/bundled package
    phantomScore = 5;
  }

  // Dampen for large compiled packages (>100 source files)
  if (input.totalFileCount && input.totalFileCount > 100 && phantomScore > 0) {
    phantomScore = Math.floor(phantomScore * 0.3);
  }

  // 2. Parent scanner signals
  const parentSignals = scoreScannerOutput(input.scannerOutput);

  // 2b. Apply false positive deductions from Gemini validation
  const fpCategories = input.gemini?.validation?.false_positives ?? [];
  const validatedSignals = { ...parentSignals };
  let geminiDeduction = 0;
  for (const cat of fpCategories) {
    const key = cat as keyof typeof validatedSignals;
    if (key in validatedSignals && validatedSignals[key] > 0) {
      geminiDeduction += validatedSignals[key];
      validatedSignals[key] = 0;
    }
  }

  // 3. Parent Gemini (additive)
  const geminiScore = scoreGemini(input.gemini);

  // 4. Recursive phantom package scores
  const phantomScanResults = input.phantomScanResults || [];
  const phantomDetails: FullRiskScore['phantomDetails'] = [];
  let totalPhantomScore = 0;

  for (const pkg of phantomScanResults) {
    const pkgSignals = scoreScannerOutput(pkg.scannerOutput);
    const pkgGemini = scoreGemini(pkg.gemini);
    const pkgTotal =
      Object.values(pkgSignals).reduce((s, v) => s + v, 0) + pkgGemini;

    totalPhantomScore += pkgTotal;
    phantomDetails.push({
      packageName: pkg.packageName,
      score: pkgTotal,
      signals: { ...pkgSignals, gemini: pkgGemini },
    });
  }

  // 5. Build breakdown (uses validatedSignals — FP categories are zeroed)
  const breakdown: FullRiskBreakdown = {
    phantom: phantomScore,
    ...validatedSignals,
    gemini: geminiScore,
    geminiDeduction,
    phantomPackages: totalPhantomScore,
  };

  // 6. Total — clamped at 0
  const total = Math.max(0,
    phantomScore +
    Object.values(validatedSignals).reduce((s, v) => s + v, 0) +
    geminiScore +
    totalPhantomScore
  );

  return { total, breakdown, phantomDetails };
}

/**
 * Backward-compatible wrapper for existing pipeline code.
 * Accepts original RiskInput (structured types) and returns RiskScore.
 */
export function calculateRisk(input: RiskInput): RiskScore {
  // Convert structured SecurityScanResult to P2's string[] format
  const security = input.security || {} as RiskInput['security'];
  const scannerOutput: ScannerOutput = {
    scripts: (security.scripts || []).map((s) => `${s.scriptName}: ${s.command}`),
    network: (security.network || []).map((n) => n.match),
    entropy: (security.entropy || []).map((e) => e.value),
    fs: (security.fs || []).map((f) => f.match),
    exec: (security.exec || []).map((e) => e.match),
    eval: (security.eval || []).map((e) => e.match),
  };

  const fullResult = calculateFullRisk({
    packageName: input.packageName,
    packageVersion: input.packageVersion,
    phantomDeps: input.comparator?.phantom || [],
    scannerOutput,
  });

  return {
    total: fullResult.total,
    breakdown: {
      phantom: fullResult.breakdown.phantom,
      scripts: fullResult.breakdown.scripts,
      exec: fullResult.breakdown.exec,
      eval: fullResult.breakdown.eval,
      network: fullResult.breakdown.network,
      entropy: fullResult.breakdown.entropy,
      fs: fullResult.breakdown.fs,
    },
  };
}

// Backward compatibility
export const RISK_WEIGHTS = WEIGHTS;
