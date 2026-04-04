/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Entropy Detection Scanner
 *  Owner: Person 2 (Security Detection Engine)
 *
 *  Scans JS/TS source files for high-entropy string literals —
 *  indicators of obfuscated code, embedded payloads, or hardcoded secrets.
 * ═══════════════════════════════════════════════════════════
 */

import * as fs from 'fs';
import * as path from 'path';
import { walkSourceFiles } from '../utils/file_walker';

const ENTROPY_THRESHOLD = 4.5;
const MIN_STRING_LENGTH = 20;
const OUTPUT_TRUNCATE_LENGTH = 60;

// Matches string literals: single-quoted, double-quoted, or backtick.
// Uses a non-greedy capture so adjacent strings don't bleed into each other.
// Does NOT handle escaped quotes inside strings — good enough for static analysis.
const STRING_LITERAL_RE = /(?:'([^'\\]{20,})'|"([^"\\]{20,})"|`([^`\\]{20,})`)/g;

/**
 * Calculates the Shannon entropy of a string.
 * H = -Σ p(x) * log2(p(x)) for each unique character x.
 * Returns 0 for empty strings.
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Extracts all string literals longer than MIN_STRING_LENGTH from a single line.
 * Returns the raw string content (without surrounding quotes).
 */
function extractStringLiterals(line: string): string[] {
  const results: string[] = [];
  STRING_LITERAL_RE.lastIndex = 0; // reset stateful regex before each line

  let match: RegExpExecArray | null;
  while ((match = STRING_LITERAL_RE.exec(line)) !== null) {
    // Groups 1, 2, 3 correspond to single, double, backtick respectively
    const value = match[1] ?? match[2] ?? match[3];
    if (value && value.length >= MIN_STRING_LENGTH) {
      results.push(value);
    }
  }

  return results;
}

/**
 * Scans all JS/TS source files in packageDir for high-entropy string literals.
 *
 * @param packageDir - Path to the extracted package root
 * @returns Object with `entropy` array of human-readable finding strings.
 *          Returns { entropy: [] } if nothing found. Never throws.
 */
export async function scanEntropy(
  packageDir: string
): Promise<{ entropy: string[] }> {
  let files;
  try {
    files = walkSourceFiles(packageDir);
  } catch {
    return { entropy: [] };
  }

  if (files.length === 0) return { entropy: [] };

  const findings: string[] = [];

  for (const file of files) {
    try {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const literals = extractStringLiterals(lines[i]);
        for (const literal of literals) {
          const h = calculateEntropy(literal);
          if (h > ENTROPY_THRESHOLD) {
            const display =
              literal.length > OUTPUT_TRUNCATE_LENGTH
                ? literal.slice(0, OUTPUT_TRUNCATE_LENGTH) + '...'
                : literal;
            findings.push(
              `${file.relativePath}:${i + 1} — entropy ${h.toFixed(2)} — '${display}'`
            );
          }
        }
      }
    } catch {
      // Skip files that error during processing
    }
  }

  return { entropy: findings };
}

// ─── Self-test ────────────────────────────────────────────────────────────────
// Run directly:  npx ts-node src/scanner/entropy.ts

if (require.main === module) {
  (async () => {
    const testDir = '/tmp/aegis-entropy-test';
    const srcDir = path.join(testDir, 'lib');

    fs.mkdirSync(srcDir, { recursive: true });

    fs.writeFileSync(
      path.join(srcDir, 'index.js'),
      [
        // Clean: short string — below MIN_STRING_LENGTH, should NOT flag
        `const name = 'hello';`,
        // Clean: long but low-entropy (repeated chars) — should NOT flag
        `const spacer = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';`,
        // Clean: readable sentence — low entropy, should NOT flag
        `const msg = 'this is a normal readable message ok';`,
        // Malicious: base64-encoded payload — high entropy, SHOULD flag
        `const payload = 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIGJhc2U2NCBwYXlsb2Fk';`,
        // Malicious: long random-looking key — high entropy, SHOULD flag
        `const key = 'X7kP!mQ2@nR5#sT8$uV1%wY4^zA9&bC3*dE6(fG0)hI';`,
      ].join('\n')
    );

    console.log('Running scanEntropy on fake malicious package...\n');
    const result = await scanEntropy(testDir);

    if (result.entropy.length === 0) {
      console.log('No findings (unexpected — check patterns)');
    } else {
      for (const finding of result.entropy) {
        console.log('  FLAGGED:', finding);
      }
    }

    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('\nCleanup done.');
  })();
}
