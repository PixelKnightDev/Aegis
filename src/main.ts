#!/usr/bin/env node
import * as dotenv from 'dotenv';
dotenv.config();
/**
 * ═══════════════════════════════════════════════════════════
 *  🛡️  AEGIS-AST — Main CLI Entry Point
 *  Owner: Person 4 (CLI + Demo + UX)
 *
 *  Usage:
 *    ags install <package-name>     Scan & install a package
 *    ags scan <package-name>        Scan only (don't install)
 *    ags history <package-name>     View scan history
 *
 *  Pipeline:
 *    fetch → scan → compare → score → decide → log
 * ═══════════════════════════════════════════════════════════
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { execSync } from 'child_process';
import * as readline from 'readline';

// Core modules (P1)
import { fetchPackage, extractImports, compareDependencies, cleanup } from './core';

// P3 risk engine & policy (uses FullScanInput, not old SecurityScanResult)
import {
  calculateFullRisk,
  FullScanInput,
  FullRiskScore,
  ScannerOutput,
} from './core/risk_engine';
import { applyFullPolicy } from './core/policy';

// Scanners (P2 — return string[] format)
import {
  scanScripts,
  scanNetwork,
  scanEntropy,
  scanFsAccess,
  scanExec,
  scanEval,
} from './scanner/index';

// Gemini (conditional)
import { runGeminiAnalysis } from './scanner/gemini';

// Utils
import { logScan, getScanHistory, initDatabase, closeDatabase } from './utils/logger';

// Types
import { PolicyResult } from './types';

const program = new Command();

program
  .name('ags')
  .description(
    chalk.bold.cyan('🛡️  Aegis-AST') +
    ' — Secure Package Installation via Static Code Verification'
  )
  .version('1.0.0');

// ─── Helpers ─────────────────────────────────────────────

/**
 * Prompts the user with a yes/no question and returns the answer.
 */
function askUser(question: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y' || answer.trim().toLowerCase() === 'yes');
    });
  });
}

/**
 * Runs the full scan pipeline and returns the results.
 * When verbose=true (scan command): shows spinners, banner, and full report.
 * When verbose=false (install command): silent — no output, just returns data.
 */
async function runPipeline(packageName: string, version: string, verbose: boolean): Promise<{
  input: FullScanInput;
  policy: PolicyResult;
  riskScore: FullRiskScore;
  extractedPath: string;
}> {
  // ── 1. Show banner ──────────────────────────────────────
  if (verbose) {
    console.log(chalk.bold.cyan('\n🛡️  Aegis-AST Security Scanner\n'));
  }

  // ── 2. Fetch package ────────────────────────────────────
  let packageData;
  if (verbose) {
    const spinner = ora(`Fetching package ${packageName}@${version}...`).start();
    try {
      packageData = await fetchPackage(packageName, version);
      spinner.succeed(`Fetched ${chalk.bold(packageName)} v${packageData.metadata.version}`);
    } catch (error: any) {
      spinner.fail(`Failed to fetch package: ${error.message}`);
      process.exit(1);
    }
  } else {
    try {
      packageData = await fetchPackage(packageName, version);
    } catch (error: any) {
      console.error(chalk.red(`✖ Failed to fetch ${packageName}: ${error.message}`));
      process.exit(1);
    }
  }

  // ── 3. Extract imports & compare dependencies ───────────
  if (verbose) {
    const compareSpinner = ora('Analyzing dependencies...').start();
    const imports = await extractImports(packageData.extractedPath);
    let comparator = compareDependencies(packageData.metadata, imports);

    // Walk all source files: used for string-literal fallback AND file count (compiled package detection)
    const allContents: string[] = [];
    {
      const SOURCE_EXTS = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx']);
      const HARD_SKIP = new Set(['node_modules', '.git']);
      function walkAll(dir: string): void {
        let entries;
        try { entries = require('fs').readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const entry of entries) {
          const full = require('path').join(dir, entry.name);
          if (entry.isDirectory() && !HARD_SKIP.has(entry.name)) { walkAll(full); }
          else if (entry.isFile() && !entry.name.endsWith('.d.ts') &&
            SOURCE_EXTS.has(require('path').extname(entry.name).toLowerCase())) {
            try { allContents.push(require('fs').readFileSync(full, 'utf-8')); } catch { /* skip */ }
          }
        }
      }
      walkAll(packageData.extractedPath);
    }

    // String-literal fallback: remove phantom deps that appear as string literals in source
    if (comparator.phantom.length > 0) {
      const confirmedPhantoms = comparator.phantom.filter(dep => {
        const escaped = dep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const literal = new RegExp(`['"\`]${escaped}['"\`]`);
        return !allContents.some(content => literal.test(content));
      });
      comparator = { ...comparator, phantom: confirmedPhantoms };
    }

    compareSpinner.succeed('Dependency analysis complete');

    if (comparator.phantom.length > 0) {
      console.log(chalk.red.bold(`  🚨 ${comparator.phantom.length} PHANTOM DEPENDENCY(S) DETECTED`));
      for (const dep of comparator.phantom) {
        console.log(chalk.red(`     ⚠  ${dep} — declared but NEVER used in source code`));
      }
      console.log();
    }

    // ── 4. Run all scanners in parallel ─────────────────────
    const scanSpinner = ora('Running security scanners...').start();
    const [scripts, network, entropy, fs, exec, evalScan] = await Promise.all([
      scanScripts(packageData.extractedPath),
      scanNetwork(packageData.extractedPath),
      scanEntropy(packageData.extractedPath),
      scanFsAccess(packageData.extractedPath),
      scanExec(packageData.extractedPath),
      scanEval(packageData.extractedPath),
    ]);
    scanSpinner.succeed('Security scans complete');

    const scannerOutput: ScannerOutput = {
      scripts: scripts.scripts,
      network: network.network,
      entropy: entropy.entropy,
      fs: fs.fs,
      exec: exec.exec,
      eval: evalScan.eval,
    };

    let flagCount = 0;
    for (const findings of Object.values(scannerOutput)) {
      if (findings.length > 0) flagCount++;
    }

    // ── 5. Gemini AI analysis ─────────────────────────────
    const geminiResult = await runGeminiAnalysis(
      flagCount + (comparator.phantom.length > 0 ? 1 : 0),
      packageName,
      scannerOutput.scripts.length > 0 ? scannerOutput.scripts.join('\n') : undefined,
      { scripts: scannerOutput.scripts, entropy: scannerOutput.entropy, fs: scannerOutput.fs, exec: scannerOutput.exec, eval: scannerOutput.eval },
      { similarTo: packageName, downloads: 0, ageDays: 0 }
    );

    // ── 6. Build FullScanInput ─────────────────────────────
    const input: FullScanInput = {
      packageName,
      packageVersion: packageData.metadata.version,
      ecosystem: 'npm',
      phantomDeps: comparator.phantom,
      usedDeps: comparator.usedDependencies,
      totalFileCount: allContents.length,
      scannerOutput,
      gemini: geminiResult,
    };

    const riskScore = calculateFullRisk(input);
    const policy = applyFullPolicy(riskScore, input);

    // ── 7. Display full results ────────────────────────────
    console.log(chalk.bold('\n═══════════════════════════════════════════'));
    console.log(chalk.bold('  📊  SCAN RESULTS'));
    console.log(chalk.bold('═══════════════════════════════════════════\n'));

    console.log(`  ${chalk.dim('Package:')}   ${chalk.bold(packageName)}`);
    console.log(`  ${chalk.dim('Version:')}   ${packageData.metadata.version}`);
    console.log();

    const scoreColor = riskScore.total > 70 ? chalk.red : riskScore.total > 40 ? chalk.yellow : chalk.green;
    console.log(`  ${chalk.dim('Risk Score:')} ${scoreColor.bold(String(riskScore.total))}`);
    console.log();

    console.log(chalk.dim('  ── Score Breakdown ──────────────────────'));
    const phantomUsedCount = input.usedDeps?.length ?? 0;
    const phantomTotalDecl = input.phantomDeps.length + phantomUsedCount;
    const phantomRatioLabel = phantomTotalDecl > 0
      ? `(${input.phantomDeps.length}/${phantomTotalDecl} deps unused, ratio: ${(input.phantomDeps.length / phantomTotalDecl).toFixed(2)})`
      : '';
    const breakdownEntries = Object.entries(riskScore.breakdown) as [string, number][];
    for (const [category, score] of breakdownEntries) {
      if (score === 0) continue;
      if (category === 'geminiDeduction') {
        console.log(`    🟢 ${chalk.dim(category.padEnd(16))} -${score}`);
      } else if (category === 'phantom') {
        const icon = score >= 40 ? '🔴' : score >= 20 ? '🟡' : '🟢';
        console.log(`    ${icon} ${chalk.dim(category.padEnd(16))} +${score}  ${chalk.dim(phantomRatioLabel)}`);
      } else {
        const icon = score >= 40 ? '🔴' : score >= 20 ? '🟡' : '🟢';
        console.log(`    ${icon} ${chalk.dim(category.padEnd(16))} +${score}`);
      }
    }
    console.log();

    const summaries: Array<[string, string[], string]> = [
      ['Suspicious script(s)', scannerOutput.scripts, 'yellow'],
      ['Network reference(s)', scannerOutput.network, 'yellow'],
      ['High-entropy string(s)', scannerOutput.entropy, 'yellow'],
      ['Filesystem access pattern(s)', scannerOutput.fs, 'yellow'],
      ['Exec/spawn call(s)', scannerOutput.exec, 'yellow'],
      ['Eval/Function usage(s)', scannerOutput.eval, 'red'],
    ];

    for (const [label, findings, color] of summaries) {
      if (findings.length > 0) {
        const colorFn = color === 'red' ? chalk.red : chalk.yellow;
        const icon = color === 'red' ? '🚨' : '⚠';
        console.log(colorFn(`  ${icon}  ${findings.length} ${label}`));
      }
    }

    if (geminiResult) {
      if (geminiResult.typosquat && geminiResult.typosquat.verdict !== 'legitimate') {
        console.log(chalk.red(`  🤖 Gemini: ${geminiResult.typosquat.verdict} — ${geminiResult.typosquat.reasoning}`));
      }
      if (geminiResult.script && geminiResult.script.verdict !== 'safe') {
        console.log(chalk.red(`  🤖 Gemini: ${geminiResult.script.verdict} script — ${geminiResult.script.reasoning}`));
      }
      if (geminiResult.validation) {
        const { false_positives, confirmed_threats, reasoning } = geminiResult.validation;
        if (false_positives.length > 0) {
          console.log(chalk.dim('  ── Gemini Validation (False Positive Reduction) ──'));
          for (const cat of false_positives) {
            console.log(chalk.green(`  ✅ [${cat}] false positive — ${reasoning[cat] ?? 'no detail'}`));
          }
        }
        if (confirmed_threats.length > 0) {
          for (const cat of confirmed_threats) {
            console.log(chalk.red(`  🔴 [${cat}] confirmed threat — ${reasoning[cat] ?? 'no detail'}`));
          }
        }
        if (riskScore.breakdown.geminiDeduction > 0) {
          console.log(chalk.green(`  ↳ Score deducted: -${riskScore.breakdown.geminiDeduction}`));
        }
      }
    }
    console.log();

    const decisionIcon = policy.decision === 'ALLOW' ? '✅' : policy.decision === 'FLAG' ? '⚠️' : '🛑';
    const decisionColor = policy.decision === 'ALLOW' ? chalk.green : policy.decision === 'FLAG' ? chalk.yellow : chalk.red;
    console.log(chalk.bold(`  ${decisionIcon}  Decision: ${decisionColor.bold(policy.decision)}`));
    console.log();

    if (policy.reasons.length > 0) {
      console.log(chalk.dim('  ── Reasons ─────────────────────────────'));
      for (const reason of policy.reasons) {
        console.log(`    ${reason}`);
      }
      console.log();
    }

    console.log(chalk.bold('═══════════════════════════════════════════\n'));

    return { input, policy, riskScore, extractedPath: packageData.extractedPath };

  } else {
    // ── Silent path (install mode) ───────────────────────
    const imports = await extractImports(packageData.extractedPath);
    let comparator = compareDependencies(packageData.metadata, imports);

    const allContents: string[] = [];
    {
      const SOURCE_EXTS = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx']);
      const HARD_SKIP = new Set(['node_modules', '.git']);
      function walkAll(dir: string): void {
        let entries;
        try { entries = require('fs').readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const entry of entries) {
          const full = require('path').join(dir, entry.name);
          if (entry.isDirectory() && !HARD_SKIP.has(entry.name)) { walkAll(full); }
          else if (entry.isFile() && !entry.name.endsWith('.d.ts') &&
            SOURCE_EXTS.has(require('path').extname(entry.name).toLowerCase())) {
            try { allContents.push(require('fs').readFileSync(full, 'utf-8')); } catch { /* skip */ }
          }
        }
      }
      walkAll(packageData.extractedPath);
    }

    if (comparator.phantom.length > 0) {
      const confirmedPhantoms = comparator.phantom.filter(dep => {
        const escaped = dep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const literal = new RegExp(`['"\`]${escaped}['"\`]`);
        return !allContents.some(content => literal.test(content));
      });
      comparator = { ...comparator, phantom: confirmedPhantoms };
    }

    const [scripts, network, entropy, fs, exec, evalScan] = await Promise.all([
      scanScripts(packageData.extractedPath),
      scanNetwork(packageData.extractedPath),
      scanEntropy(packageData.extractedPath),
      scanFsAccess(packageData.extractedPath),
      scanExec(packageData.extractedPath),
      scanEval(packageData.extractedPath),
    ]);

    const scannerOutput: ScannerOutput = {
      scripts: scripts.scripts,
      network: network.network,
      entropy: entropy.entropy,
      fs: fs.fs,
      exec: exec.exec,
      eval: evalScan.eval,
    };

    let flagCount = 0;
    for (const findings of Object.values(scannerOutput)) {
      if (findings.length > 0) flagCount++;
    }

    const geminiResult = await runGeminiAnalysis(
      flagCount + (comparator.phantom.length > 0 ? 1 : 0),
      packageName,
      scannerOutput.scripts.length > 0 ? scannerOutput.scripts.join('\n') : undefined,
      { scripts: scannerOutput.scripts, entropy: scannerOutput.entropy, fs: scannerOutput.fs, exec: scannerOutput.exec, eval: scannerOutput.eval },
      { similarTo: packageName, downloads: 0, ageDays: 0 }
    );

    const input: FullScanInput = {
      packageName,
      packageVersion: packageData.metadata.version,
      ecosystem: 'npm',
      phantomDeps: comparator.phantom,
      usedDeps: comparator.usedDependencies,
      totalFileCount: allContents.length,
      scannerOutput,
      gemini: geminiResult,
    };

    const riskScore = calculateFullRisk(input);
    const policy = applyFullPolicy(riskScore, input);

    return { input, policy, riskScore, extractedPath: packageData.extractedPath };
  }
}

// ─── aegis install <package> ─────────────────────────────

program
  .command('install <packageName>')
  .description('Scan a package for threats, then install if safe')
  .option('-v, --pkg-version <version>', 'Package version', 'latest')
  .option('--skip-db', 'Skip MongoDB logging', false)
  .action(async (packageName: string, options) => {
    const { input, policy, riskScore, extractedPath } = await runPipeline(packageName, options.pkgVersion, false);

    const ref = `${packageName}@${input.packageVersion}`;
    const score = riskScore.total;

    // Top-level reasons only (exclude ↳ sub-detail lines)
    const topReasons = policy.reasons.filter(r => !r.startsWith('   ↳'));

    let shouldInstall = false;

    if (policy.decision === 'ALLOW') {
      console.log(chalk.green(`✅ ${ref} — Score: ${score} — ALLOWED`));
      console.log(chalk.dim(`   Installing...`));
      shouldInstall = true;
    } else if (policy.decision === 'FLAG') {
      console.log(chalk.yellow(`⚠️  ${ref} — Score: ${score} — FLAGGED\n`));
      console.log(`Reasons:`);
      for (const r of topReasons) {
        console.log(`  • ${r}`);
      }
      console.log();
      shouldInstall = await askUser(chalk.yellow(`Proceed with install? (y/n): `));
      if (!shouldInstall) {
        // silent cancel
      }
    } else {
      // BLOCK
      console.log(chalk.red(`🛑 ${ref} — Score: ${score} — BLOCKED\n`));
      console.log(`Reasons:`);
      for (const r of topReasons) {
        console.log(`  • ${r}`);
      }
      console.log();
      console.log(chalk.dim(`Installation aborted. Run 'ags scan ${packageName}' for full report.`));
    }

    // ── Install if allowed ──────────────────────────────
    if (shouldInstall) {
      try {
        const versionSuffix = options.pkgVersion !== 'latest' ? `@${options.pkgVersion}` : '';
        execSync(`npm install ${packageName}${versionSuffix}`, { stdio: 'pipe' });
      } catch (error: any) {
        console.error(chalk.red(`✖ Installation failed: ${error.message}`));
      }
    }

    // ── Log to MongoDB (silent) ─────────────────────────
    if (!options.skipDb) {
      try {
        await initDatabase();
        await logScan(input, riskScore, policy.decision, policy.reasons);
        await closeDatabase();
      } catch {
        // silent
      }
    }

    // ── Clean up temp files ──────────────────────────────
    try {
      await cleanup(extractedPath);
    } catch {
      // silent
    }
  });

// ─── aegis scan <package> ────────────────────────────────

program
  .command('scan <packageName>')
  .description('Scan a package without installing')
  .option('-v, --pkg-version <version>', 'Package version', 'latest')
  .option('--skip-db', 'Skip MongoDB logging', false)
  .action(async (packageName: string, options) => {
    const { input, policy, riskScore, extractedPath } = await runPipeline(packageName, options.pkgVersion, true);

    // Log to MongoDB (silent)
    if (!options.skipDb) {
      try {
        await initDatabase();
        await logScan(input, riskScore, policy.decision, policy.reasons);
        await closeDatabase();
      } catch {
        // silent
      }
    }

    // Clean up temp files
    try {
      await cleanup(extractedPath);
    } catch {
      // silent
    }
  });

// ─── aegis history <package> ─────────────────────────────

program
  .command('history <packageName>')
  .description('View scan history for a package')
  .option('-n, --limit <number>', 'Number of results', '10')
  .action(async (packageName: string, options) => {
    console.log(chalk.bold.cyan('\n🛡️  Aegis-AST Scan History\n'));

    const limit = parseInt(options.limit, 10) || 10;

    try {
      await initDatabase();
      const history = await getScanHistory(packageName, limit);
      await closeDatabase();

      if (history.length === 0) {
        console.log(chalk.dim(`  No scan history found for ${packageName}.\n`));
        return;
      }

      console.log(chalk.dim(`  Showing last ${history.length} scan(s) for ${chalk.bold(packageName)}:\n`));

      for (const entry of history) {
        const decisionColor =
          entry.decision === 'ALLOW' ? chalk.green :
            entry.decision === 'FLAG' ? chalk.yellow : chalk.red;
        const scoreColor =
          entry.score > 70 ? chalk.red :
            entry.score > 40 ? chalk.yellow : chalk.green;

        const timestamp = new Date(entry.timestamp).toLocaleString();

        console.log(chalk.dim('  ──────────────────────────────────────'));
        console.log(`  ${chalk.dim('Date:')}     ${timestamp}`);
        console.log(`  ${chalk.dim('Version:')}  ${entry.version}`);
        console.log(`  ${chalk.dim('Score:')}    ${scoreColor(String(entry.score))}`);
        console.log(`  ${chalk.dim('Decision:')} ${decisionColor.bold(entry.decision)}`);
        if (entry.reasons.length > 0) {
          console.log(`  ${chalk.dim('Reasons:')}`);
          for (const reason of entry.reasons) {
            console.log(`    • ${reason}`);
          }
        }
        console.log();
      }
    } catch (error: any) {
      console.log(chalk.red(`  ✖ ${error.message}\n`));
    }
  });

// ─── Parse and execute ───────────────────────────────────

program.parse(process.argv);

// Show help if no args
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
