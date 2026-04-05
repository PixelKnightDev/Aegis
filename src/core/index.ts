/**
 * ═══════════════════════════════════════════════════════════
 * AEGIS-AST — Core Barrel Export & Orchestration
 * * Re-exports all core modules and provides the master
 * orchestration function for the Person 1 pipeline.
 * ═══════════════════════════════════════════════════════════
 */

import { fetchPackage } from './fetcher';
import { extractImports } from './imports';
import { compareDependencies } from './comparator';
import { ComparatorResult } from '../types';

const DEBUG = process.env.AEGIS_DEBUG === 'true';

// 1. Re-export everything exactly as you had it
export { fetchPackage, parsePackageJson, cleanup } from './fetcher';
export { extractImports, normalizeImport, IMPORT_PATTERNS } from './imports';
export { compareDependencies } from './comparator';
export { calculateRisk, RISK_WEIGHTS } from './risk_engine';
export { applyPolicy, THRESHOLDS } from './policy';

// 2. Add your Master Pipeline Function
export interface CorePipelineResult {
  extractedPath: string;           // Handed off to Person 2 (Scanners)
  comparatorData: ComparatorResult; // Handed off to Person 3 (Risk Engine)
}

/**
 * Runs the complete Core Engine pipeline (Fetch -> Extract -> Compare).
 * This is the primary entry point for Person 4 (CLI) to trigger Person 1's work.
 */
export async function runCorePipeline(
  packageName: string,
  version: string = 'latest'
): Promise<CorePipelineResult> {
  if (DEBUG) console.log(`[Core] Fetching ${packageName}@${version}...`);
  const { extractedPath, metadata } = await fetchPackage(packageName, version);

  if (DEBUG) console.log(`[Core] Extracting imports from ${extractedPath}...`);
  const imports = await extractImports(extractedPath);

  if (DEBUG) console.log(`[Core] Comparing dependencies...`);
  const comparatorData = compareDependencies(metadata, imports);

  // Return the raw path so Person 2 can run their heuristic scans,
  // and the comparator data so Person 3 can calculate risk.
  return {
    extractedPath,
    comparatorData
  };
}