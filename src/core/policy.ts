/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Policy Engine
 *
 *  Thresholds:
 *    score > 70  → BLOCK
 *    score > 40  → FLAG
 *    score <= 40 → ALLOW
 *
 *  Generates reasons from P2's string[] scanner output.
 * ═══════════════════════════════════════════════════════════
 */

import { Decision, PolicyResult, RiskInput } from '../types';
import {
  FullScanInput,
  FullRiskScore,
  WEIGHTS,
} from './risk_engine';

/** Decision thresholds */
export const THRESHOLDS = {
  BLOCK: 70,
  FLAG: 40,
} as const;

/** Global whitelist for legitimate packages containing heavy install scripts */
export const KNOWN_SAFE_PACKAGES = new Set([
  'esbuild',
  'sharp',
  'puppeteer',
  'node-sass',
  'sqlite3',
  'bcrypt'
]);

/**
 * Simple threshold check.
 */
export function decide(score: number): Decision {
  if (score > THRESHOLDS.BLOCK) return 'BLOCK';
  if (score > THRESHOLDS.FLAG) return 'FLAG';
  return 'ALLOW';
}

/**
 * Generates human-readable reasons from FullScanInput + FullRiskScore.
 * Works with P2's string[] format — includes the actual finding strings.
 */
function generateReasons(input: FullScanInput, riskScore: FullRiskScore): string[] {
  const reasons: string[] = [];
  const b = riskScore.breakdown;
  const out = input.scannerOutput || {
    scripts: [], network: [], entropy: [], fs: [], exec: [], eval: [],
  };

  if (b.phantom > 0) {
    const list = (input.phantomDeps || []).join(', ');
    reasons.push(`🔴 Phantom dependencies (declared but never used): ${list} [+${b.phantom}]`);
  }

  if (b.scripts > 0) {
    reasons.push(`🔴 Suspicious install scripts [+${b.scripts}]`);
    for (const finding of out.scripts.slice(0, 3)) {
      reasons.push(`   ↳ ${finding}`);
    }
    if (out.scripts.length > 3) reasons.push(`   ↳ ...and ${out.scripts.length - 3} more`);
  }

  if (b.exec > 0) {
    reasons.push(`🔴 Process execution patterns [+${b.exec}]`);
    for (const finding of out.exec.slice(0, 3)) {
      reasons.push(`   ↳ ${finding}`);
    }
    if (out.exec.length > 3) reasons.push(`   ↳ ...and ${out.exec.length - 3} more`);
  }

  if (b.eval > 0) {
    reasons.push(`🟠 Dynamic code evaluation [+${b.eval}]`);
    for (const finding of out.eval.slice(0, 3)) {
      reasons.push(`   ↳ ${finding}`);
    }
    if (out.eval.length > 3) reasons.push(`   ↳ ...and ${out.eval.length - 3} more`);
  }

  if (b.network > 0) {
    reasons.push(`🟠 Network indicators [+${b.network}]`);
    for (const finding of out.network.slice(0, 3)) {
      reasons.push(`   ↳ ${finding}`);
    }
    if (out.network.length > 3) reasons.push(`   ↳ ...and ${out.network.length - 3} more`);
  }

  if (b.fs > 0) {
    reasons.push(`🟠 Sensitive filesystem access [+${b.fs}]`);
    for (const finding of out.fs.slice(0, 3)) {
      reasons.push(`   ↳ ${finding}`);
    }
    if (out.fs.length > 3) reasons.push(`   ↳ ...and ${out.fs.length - 3} more`);
  }

  if (b.entropy > 0) {
    reasons.push(`🟡 High-entropy strings (possible obfuscation) [+${b.entropy}]`);
    for (const finding of out.entropy.slice(0, 3)) {
      reasons.push(`   ↳ ${finding}`);
    }
    if (out.entropy.length > 3) reasons.push(`   ↳ ...and ${out.entropy.length - 3} more`);
  }

  if (b.gemini > 0) {
    const g = input.gemini;
    const parts: string[] = [];
    if (g?.typosquat && g.typosquat.verdict !== 'legitimate') {
      parts.push(`${g.typosquat.verdict}: ${g.typosquat.reasoning}`);
    }
    if (g?.script && g.script.verdict === 'malicious') {
      parts.push(`malicious script: ${g.script.techniques.join(', ')}`);
    }
    reasons.push(`🔴 Gemini AI flagged: ${parts.join('; ')} [+${b.gemini}]`);
  }

  if (b.geminiDeduction > 0) {
    const fp = input.gemini?.validation?.false_positives ?? [];
    reasons.push(`✅ Gemini validated false positives: [${fp.join(', ')}] [-${b.geminiDeduction}]`);
  }

  // Phantom package sub-scores
  for (const phantom of riskScore.phantomDetails) {
    if (phantom.score > 0) {
      reasons.push(`🔴 Phantom package "${phantom.packageName}" scored ${phantom.score} from its own signals`);
    }
  }

  if (reasons.length === 0) {
    reasons.push('✅ No security issues detected.');
  }

  return reasons;
}

/**
 * Full policy evaluation.
 *
 * @param riskScore - From calculateFullRisk()
 * @param input     - The original FullScanInput
 */
export function applyFullPolicy(
  riskScore: FullRiskScore,
  input: FullScanInput
): PolicyResult {
  const decision = decide(riskScore.total);
  const reasons = generateReasons(input, riskScore);

  if (KNOWN_SAFE_PACKAGES.has(input.packageName) && decision !== 'ALLOW') {
    reasons.push('✅ Verdict overridden: Package is on the global whitelist. Known safe despite aggressive install scripts.');
    return {
      decision: 'ALLOW',
      score: riskScore.total,
      reasons,
    };
  }

  return {
    decision,
    score: riskScore.total,
    reasons,
  };
}

/**
 * Backward-compatible applyPolicy for existing pipeline code.
 */
export function applyPolicy(
  riskScore: { total: number; breakdown: Record<string, number> },
  input: RiskInput
): PolicyResult {
  const decision = decide(riskScore.total);
  const reasons = Object.entries(riskScore.breakdown)
    .filter(([_, score]) => score > 0)
    .map(([category, score]) => `${category}: +${score}`);

  if (reasons.length === 0) reasons.push('✅ No security issues detected.');

  return { decision, score: riskScore.total, reasons };
}
