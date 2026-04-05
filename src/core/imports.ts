/**
 * ═══════════════════════════════════════════════════════════
 * AEGIS-AST — Import Extractor
 * Owner: Person 1 (Core Engine)
 * * Responsibilities:
 * - Walk all .js/.ts files in extracted package
 * - Extract require() and import statements via AST (Primary)
 * - Fallback to regex extraction if AST parsing fails
 * - Return deduplicated list of used dependencies
 * ═══════════════════════════════════════════════════════════
 */

import { ImportScanResult } from '../types';
import { walkSourceFiles } from '../utils/file_walker';
import * as fsp from 'fs/promises';
import { builtinModules } from 'module';
import * as path from 'path';
import * as parser from '@babel/parser';

const DEBUG = process.env.AEGIS_DEBUG === 'true';

// Safely import Babel traverse for TypeScript environments
import _traverse from '@babel/traverse';
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as any).default;

/**
 * Regex patterns for extracting imports from JavaScript/TypeScript files.
 * Used strictly as a fallback if AST parsing fails.
 */
export const IMPORT_PATTERNS = {
  REQUIRE: /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ES_IMPORT: /import\s+(?:(?:[\w*{}\s,]+)\s+from\s+)?['"]([^'"]+)['"]/g,
  DYNAMIC_IMPORT: /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
};

export async function extractImports(
  extractedPath: string
): Promise<ImportScanResult> {
  const usedDependencies = new Set<string>();
  const rawImports: Array<{ filePath: string; importName: string; line: number }> = [];

  // Helper to process, normalize, and store a found import (used by both AST and Regex)
  function processImportRecord(rawImport: string, line: number, file: string) {
    rawImports.push({
      filePath: file,
      importName: rawImport,
      line: line,
    });

    const normalized = normalizeImport(rawImport);
    if (normalized) {
      usedDependencies.add(normalized);
    }
  }

  // Helper to calculate the line number of a regex match
  function getLineNumber(content: string, matchIndex: number): number {
    return content.substring(0, matchIndex).split('\n').length;
  }

  try {
    // Uses your existing utils/file_walker.ts implementation
    const files = walkSourceFiles(extractedPath);

    for (const sourceFile of files) {
      const file = sourceFile.absolutePath;
      const content = sourceFile.content;

      try {
        // ==========================================
        // PRIMARY ENGINE: Babel AST Parsing
        // ==========================================
        const ast = parser.parse(content, {
          sourceType: 'unambiguous', // Auto-detects ESM vs CommonJS
          plugins: [
            'typescript', 
            'jsx',
            ['decorators', { decoratorsBeforeExport: true }] // Prevents crashes on NestJS/Angular files
          ], 
        });

        if (DEBUG) console.log(`🟢 [AST] Successfully parsed: ${path.basename(file)}`);

        traverse(ast, {
          // Catch: import { x } from 'y'
          ImportDeclaration(astPath: any) {
            if (astPath.node.source && astPath.node.source.value) {
              const line = astPath.node.loc?.start.line || 1;
              processImportRecord(astPath.node.source.value, line, file);
            }
          },

          // Catch: export { x } from 'y'
          ExportNamedDeclaration(astPath: any) {
            if (astPath.node.source && astPath.node.source.value) {
              const line = astPath.node.loc?.start.line || 1;
              processImportRecord(astPath.node.source.value, line, file);
            }
          },

          // Catch: export * from 'y'
          ExportAllDeclaration(astPath: any) {
            if (astPath.node.source && astPath.node.source.value) {
              const line = astPath.node.loc?.start.line || 1;
              processImportRecord(astPath.node.source.value, line, file);
            }
          },

          // Catch: require('y') and import('y')
          CallExpression(astPath: any) {
            const callee = astPath.node.callee;
            const args = astPath.node.arguments;

            if (args.length > 0 && args[0].type === 'StringLiteral') {
              // Handle require()
              if (callee.type === 'Identifier' && callee.name === 'require') {
                const line = astPath.node.loc?.start.line || 1;
                processImportRecord(args[0].value, line, file);
              }
              // Handle dynamic import()
              else if (callee.type === 'Import') {
                const line = astPath.node.loc?.start.line || 1;
                processImportRecord(args[0].value, line, file);
              }
            }
          }
        });

      } catch (astError) {
        // ==========================================
        // BACKUP ENGINE: Regex Parsing
        // Executes if file contains syntax errors / heavily obfuscated code
        // ==========================================
        
        const extractWithRegex = (pattern: RegExp) => {
          let match;
          pattern.lastIndex = 0; // Reset global regex state
          while ((match = pattern.exec(content)) !== null) {
            const rawImport = match[1];
            const lineNumber = getLineNumber(content, match.index);
            processImportRecord(rawImport, lineNumber, file);
          }
        };

        if (DEBUG) console.log(`🟠 [REGEX] AST failed. Regex fallback triggered for: ${path.basename(file)}`);

        extractWithRegex(IMPORT_PATTERNS.REQUIRE);
        extractWithRegex(IMPORT_PATTERNS.ES_IMPORT);
        extractWithRegex(IMPORT_PATTERNS.DYNAMIC_IMPORT);
      }
    }

    return {
      usedDependencies: Array.from(usedDependencies),
      rawImports,
    };
  } catch (error) {
    throw new Error(`Failed to extract imports from ${extractedPath}: ${(error as Error).message}`);
  }
}

/**
 * Normalizes a raw import string to a package name.
 */
export function normalizeImport(rawImport: string): string | null {
  if (rawImport.startsWith('.') || rawImport.startsWith('/')) {
    return null;
  }
  const cleanImport = rawImport.startsWith('node:') ? rawImport.substring(5) : rawImport;
  if (builtinModules.includes(cleanImport)) {
    return null;
  }
  if (cleanImport.startsWith('@')) {
    const parts = cleanImport.split('/');
    if (parts.length >= 2) {
      return `${parts[0]}/${parts[1]}`;
    }
    return cleanImport; 
  }
  return cleanImport.split('/')[0];
}