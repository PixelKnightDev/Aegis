/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — AI Scanner (Groq)
 *
 *  Only invoked when 2+ local scanners flag something.
 *  Three API calls:
 *    1. classifyTyposquat() — is this a typosquat/slopsquat?
 *    2. analyzeScript()     — is this script malicious?
 *    3. validateFindings()  — false positive reduction
 *
 *  Responses are parsed safely with JSON fallback.
 * ═══════════════════════════════════════════════════════════
 */

import Groq from 'groq-sdk';
import { GeminiTyposquatResult, GeminiScriptResult, GeminiDomainVerdict, GeminiResults, GeminiValidationResult } from '../core/risk_engine';

const DEBUG = process.env.AEGIS_DEBUG === 'true';

const MODEL = 'llama-3.3-70b-versatile';

// ─── Init ───────────────────────────────────────────────────

let groq: Groq | null = null;

function getClient(): Groq | null {
  if (!groq) {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
      if (DEBUG) console.warn('⚠️  GROQ_API_KEY not set — AI analysis disabled.');
      return null;
    }
    groq = new Groq({ apiKey });
  }
  return groq;
}

// ─── Safe JSON parsing ──────────────────────────────────────

/**
 * Strips markdown code fences and parses JSON safely.
 * Models sometimes return ```json ... ``` around their response.
 */
function safeParseJSON<T>(text: string): T | null {
  try {
    let cleaned = text.trim();
    if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```(?:json)?\s*\n?/, '').replace(/\n?```\s*$/, '');
    }
    return JSON.parse(cleaned) as T;
  } catch {
    return null;
  }
}

/**
 * Sends a single prompt to Groq and returns the response text.
 */
async function chat(prompt: string): Promise<string> {
  const client = getClient();
  if (!client) throw new Error('Groq client not initialized');

  const response = await client.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: prompt }],
    temperature: 0,
  });

  return response.choices[0]?.message?.content ?? '';
}

// ─── API Functions ──────────────────────────────────────────

/**
 * Classifies whether a package is a typosquat or slopsquat.
 */
export async function classifyTyposquat(
  name: string,
  downloads: number,
  ageDays: number,
  similarTo: string
): Promise<GeminiTyposquatResult> {
  const fallback: GeminiTyposquatResult = {
    verdict: 'legitimate',
    confidence: 0,
    reasoning: 'AI analysis unavailable',
  };

  if (!getClient()) return fallback;

  const prompt = `You are a supply-chain security analyst. Analyze this npm package for typosquatting or slopsquatting.

Package name: "${name}"
Weekly downloads: ${downloads}
Days since published: ${ageDays}
Similar popular package: "${similarTo}" (millions of weekly downloads)

Is this package likely legitimate, a typosquat (intentional name mimicry), or a slopsquat (AI-hallucinated package name)?

Respond ONLY with valid JSON, no markdown, no explanation:
{"verdict": "legitimate" | "typosquat" | "slopsquat", "confidence": 0.0-1.0, "reasoning": "brief explanation"}`;

  try {
    const text = await chat(prompt);
    const parsed = safeParseJSON<GeminiTyposquatResult>(text);

    if (parsed && parsed.verdict && typeof parsed.confidence === 'number') {
      return parsed;
    }
    return { ...fallback, reasoning: `AI returned unparseable response: ${text.substring(0, 100)}` };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (DEBUG) console.warn(`⚠️  Typosquat classification failed: ${msg}`);
    return fallback;
  }
}

/**
 * Analyzes a script for malicious intent.
 */
export async function analyzeScript(
  scriptContent: string,
  downloads: number = 0,
  ageDays: number = 0
): Promise<GeminiScriptResult> {
  const fallback: GeminiScriptResult = {
    verdict: 'safe',
    risk_level: 'unknown',
    techniques: [],
    reasoning: 'AI analysis unavailable',
  };

  if (!getClient()) return fallback;

  const truncated = scriptContent.length > 3000
    ? scriptContent.substring(0, 3000) + '\n... [truncated]'
    : scriptContent;

  const riskContext = downloads > 100000 && ageDays > 180
    ? 'This is a well-established package. Require strong evidence of malicious intent before flagging.'
    : 'This is a new or low-download package. Assume malicious intent unless clearly proven otherwise.';

  const prompt = `You are a malware forensics investigator analyzing a suspicious npm postinstall script. ${riskContext}

Any of the following is a confirmed threat regardless of apparent context:
- Shell execution (exec, spawn, execSync, child_process)
- Base64-encoded or otherwise obfuscated payloads
- Network requests to any hardcoded URL or IP address
- Access to credential files or directories (.ssh, .aws, .env, /etc/passwd, ~/.npmrc)
- Reading or transmitting environment variables (process.env)
- Dynamic code evaluation (eval, Function constructor, vm.runInNewContext)
- Writing files outside the package directory

Do NOT excuse any of the above based on context. A network call in a postinstall script is suspicious regardless of the domain. Credential file access is suspicious regardless of the stated purpose.

Script content:
\`\`\`
${truncated}
\`\`\`

Respond ONLY with valid JSON, no markdown, no explanation:
{"verdict": "safe" | "suspicious" | "malicious", "risk_level": "low" | "medium" | "high" | "critical", "techniques": ["list", "of", "techniques"], "reasoning": "brief explanation"}`;

  try {
    const text = await chat(prompt);
    const parsed = safeParseJSON<GeminiScriptResult>(text);

    if (parsed && parsed.verdict && Array.isArray(parsed.techniques)) {
      return parsed;
    }
    return { ...fallback, reasoning: `AI returned unparseable response: ${text.substring(0, 100)}` };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (DEBUG) console.warn(`⚠️  Script analysis failed: ${msg}`);
    return fallback;
  }
}

// ─── Domain Trust Analysis (disabled — kept for future use) ───

/**
 * Analyzes domains for trust verification.
 * Disabled from the pipeline — token cost too high on free tier.
 * Re-enable by implementing with extractDomainsFromFindings + a Groq prompt.
 */
export async function analyzeDomainTrust(
  _networkFindings: string[]
): Promise<GeminiDomainVerdict[]> {
  return [];
}

// ─── False Positive Validation ────────────────────────────────

const VALIDATABLE_CATEGORIES = ['scripts', 'entropy', 'fs', 'exec', 'eval'] as const;
type ValidatableCategory = typeof VALIDATABLE_CATEGORIES[number];

/**
 * Sends scanner findings (excluding network) to Groq and asks it to classify
 * which categories are false positives. Returns a deduction map so the risk engine
 * can subtract scores for legitimately-flagged-but-harmless patterns.
 *
 * Input is capped at 3000 characters total to stay within token budget.
 */
export async function validateFindings(
  findings: Partial<Record<ValidatableCategory, string[]>>,
  downloads: number = 0,
  ageDays: number = 0
): Promise<GeminiValidationResult> {
  const fallback: GeminiValidationResult = {
    false_positives: [],
    confirmed_threats: [],
    reasoning: {},
  };

  if (!getClient()) return fallback;

  const lines: string[] = [];
  for (const cat of VALIDATABLE_CATEGORIES) {
    const arr = findings[cat];
    if (arr && arr.length > 0) {
      lines.push(`[${cat}]`);
      for (const f of arr) {
        lines.push(`  - ${f}`);
      }
    }
  }

  let findingsText = lines.join('\n');
  if (findingsText.length > 3000) {
    findingsText = findingsText.substring(0, 3000) + '\n... [truncated]';
  }

  if (!findingsText.trim()) return fallback;

  const riskContext = downloads > 100000 && ageDays > 180
    ? 'This is a well-established package. Require strong evidence of malicious intent before flagging.'
    : 'This is a new or low-download package. Assume malicious intent unless clearly proven otherwise.';

  const prompt = `You are a security analyst reviewing flagged findings from a static code scanner. ${riskContext} Assume each finding is a real threat unless you can prove it is inert. When in doubt, mark as confirmed threat.

Scanner findings by category:
${findingsText}

For each category present above, classify whether the findings are confirmed threats or false positives.

A category is a FALSE POSITIVE ONLY if every finding in that category is:
- Inside a source code comment (lines starting with // or /* ... */)
- Inside a documentation string literal that is never assigned to a variable or executed (e.g. JSDoc, README-style string)

Everything else is a CONFIRMED THREAT. This includes:
- Any executable code that calls dangerous functions, even in a utility or tooling package
- String literals that are assigned to variables, passed as arguments, or returned
- Any pattern that could execute if the code runs — do not excuse it based on the package's apparent purpose

Respond ONLY with valid JSON, no markdown:
{
  "false_positives": ["category1"],
  "confirmed_threats": ["category2", "category3"],
  "reasoning": {
    "category1": "one-line explanation",
    "category2": "one-line explanation",
    "category3": "one-line explanation"
  }
}`;

  try {
    const text = await chat(prompt);
    const parsed = safeParseJSON<GeminiValidationResult>(text);

    if (
      parsed &&
      Array.isArray(parsed.false_positives) &&
      Array.isArray(parsed.confirmed_threats) &&
      typeof parsed.reasoning === 'object'
    ) {
      const presentCategories = new Set(
        VALIDATABLE_CATEGORIES.filter(c => (findings[c]?.length ?? 0) > 0)
      );
      return {
        false_positives: parsed.false_positives.filter(c => presentCategories.has(c as ValidatableCategory)),
        confirmed_threats: parsed.confirmed_threats.filter(c => presentCategories.has(c as ValidatableCategory)),
        reasoning: parsed.reasoning,
      };
    }
    return fallback;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (DEBUG) console.warn(`⚠️  Finding validation failed: ${msg}`);
    return fallback;
  }
}

// ─── Combined Runner ───────────────────────────────────────────

/**
 * Runs all AI analyses if conditions are met.
 * Only fires when 2+ scanners have flagged something.
 *
 * Calls:
 *   1. classifyTyposquat()  — is this a typosquat/slopsquat?
 *   2. analyzeScript()      — is this script malicious?
 *   3. validateFindings()   — which scanner categories are false positives?
 */
const KNOWN_SAFE_PACKAGES = new Set([
  'webpack', 'esbuild', 'vite', 'rollup', 'babel', 'typescript',
  'jest', 'mocha', 'eslint', 'prettier', 'postcss', 'sass', 'terser', 'swc',
]);

export async function runGeminiAnalysis(
  flagCount: number,
  packageName: string,
  scriptContent?: string,
  scannerOutput?: Partial<Record<ValidatableCategory, string[]>>,
  metadata?: { downloads?: number; ageDays?: number; similarTo?: string }
): Promise<GeminiResults | null> {
  if (flagCount < 2) return null;

  // Safeguard 1: skip AI for very high-download packages (established, low risk)
  if ((metadata?.downloads ?? 0) > 500000) {
    if (DEBUG) console.log(`[AI] Skipping — downloads (${metadata!.downloads}) exceeds threshold.`);
    return null;
  }

  // Safeguard 2: skip AI for well-known build tools and dev dependencies
  if (KNOWN_SAFE_PACKAGES.has(packageName)) {
    if (DEBUG) console.log(`[AI] Skipping — "${packageName}" is a known safe build tool.`);
    return null;
  }

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    if (DEBUG) console.warn('⚠️  GROQ_API_KEY not set — skipping AI analysis.');
    return null;
  }

  if (DEBUG) console.log(`[AI] ${flagCount} scanners flagged — running Groq analysis...`);

  const downloads = metadata?.downloads ?? 0;
  const ageDays = metadata?.ageDays ?? 0;

  const results: GeminiResults = {};

  // Call 1: Typosquat classification
  if (metadata?.similarTo) {
    if (DEBUG) console.log(`[AI] Classifying "${packageName}" for typosquatting...`);
    results.typosquat = await classifyTyposquat(
      packageName,
      downloads,
      ageDays,
      metadata.similarTo
    );
    if (DEBUG) console.log(`[AI] Verdict: ${results.typosquat.verdict} (${results.typosquat.confidence})`);
  }

  // Call 2: Script analysis
  if (scriptContent && scriptContent.trim().length > 0) {
    if (DEBUG) console.log(`[AI] Analyzing flagged script content...`);
    results.script = await analyzeScript(scriptContent, downloads, ageDays);
    if (DEBUG) console.log(`[AI] Verdict: ${results.script.verdict} (${results.script.risk_level})`);
  }

  // Call 3: False positive validation
  if (scannerOutput) {
    if (DEBUG) console.log(`[AI] Validating scanner findings for false positives...`);
    results.validation = await validateFindings(scannerOutput, downloads, ageDays);
    if (DEBUG) console.log(`[AI] False positives: [${results.validation.false_positives.join(', ')}]`);
  }

  return results;
}
