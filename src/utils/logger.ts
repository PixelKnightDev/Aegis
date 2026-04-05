/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Logger (MongoDB Atlas)
 *
 *  Logs every scan with full signal breakdown.
 *  Adapted to P2's string[] scanner output format.
 *  Graceful fallback — CLI works even without DB.
 * ═══════════════════════════════════════════════════════════
 */

import { MongoClient, Db, Collection } from 'mongodb';
import { Decision } from '../types';
import {
  FullScanInput,
  FullRiskScore,
  GeminiResults,
} from '../core/risk_engine';

const DEBUG = process.env.AEGIS_DEBUG === 'true';

// ─── MongoDB Document Schema ────────────────────────────────

export interface ScanLogDocument {
  package: string;
  version: string;
  ecosystem: string;
  timestamp: Date;
  score: number;
  decision: Decision;
  reasons: string[];
  phantom_deps: string[];
  signals: {
    phantom: string[];
    scripts: string[];
    network: string[];
    entropy: string[];
    fs: string[];
    exec: string[];
    eval: string[];
    gemini: GeminiResults | null;
  };
  phantom_scan_results: Array<{
    packageName: string;
    score: number;
    signals: Record<string, unknown>;
  }> | null;
}

// ─── Module State ───────────────────────────────────────────

let client: MongoClient | null = null;
let db: Db | null = null;
let scanLogsCollection: Collection<ScanLogDocument> | null = null;
let isConnected = false;

const DB_NAME = 'aegis';
const COLLECTION_NAME = 'scan_logs';
const CONNECTION_TIMEOUT_MS = 5000;

// ─── Connection Management ──────────────────────────────────

export async function initDatabase(): Promise<void> {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    if (DEBUG) console.warn('⚠️  MONGODB_URI not set — database logging disabled.');
    return;
  }

  try {
    client = new MongoClient(uri, {
      serverSelectionTimeoutMS: CONNECTION_TIMEOUT_MS,
      connectTimeoutMS: CONNECTION_TIMEOUT_MS,
    });
    await client.connect();
    await client.db('admin').command({ ping: 1 });

    db = client.db(DB_NAME);
    scanLogsCollection = db.collection<ScanLogDocument>(COLLECTION_NAME);

    await scanLogsCollection.createIndex({ package: 1, timestamp: -1 });
    await scanLogsCollection.createIndex({ decision: 1 });
    await scanLogsCollection.createIndex({ score: -1 });
    await scanLogsCollection.createIndex({ ecosystem: 1 });

    isConnected = true;
    if (DEBUG) console.log('✅ Connected to MongoDB Atlas');
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (DEBUG) console.warn(`⚠️  MongoDB connection failed: ${msg}\n   Database logging disabled.`);
    client = null;
    db = null;
    scanLogsCollection = null;
    isConnected = false;
  }
}

/**
 * Logs a scan result to MongoDB.
 * Uses P2's string[] format directly — no conversion needed.
 */
export async function logScan(
  input: FullScanInput,
  riskScore: FullRiskScore,
  decision: Decision,
  reasons: string[]
): Promise<void> {
  if (!isConnected || !scanLogsCollection) return;

  try {
    const out = input.scannerOutput || {
      scripts: [], network: [], entropy: [], fs: [], exec: [], eval: [],
    };

    const doc: ScanLogDocument = {
      package: input.packageName,
      version: input.packageVersion,
      ecosystem: input.ecosystem || 'npm',
      timestamp: new Date(),
      score: riskScore.total,
      decision,
      reasons,
      phantom_deps: input.phantomDeps || [],
      signals: {
        phantom: input.phantomDeps || [],
        scripts: out.scripts,
        network: out.network,
        entropy: out.entropy,
        fs: out.fs,
        exec: out.exec,
        eval: out.eval,
        gemini: input.gemini || null,
      },
      phantom_scan_results:
        riskScore.phantomDetails.length > 0
          ? riskScore.phantomDetails.map((p) => ({
              packageName: p.packageName,
              score: p.score,
              signals: p.signals,
            }))
          : null,
    };

    await scanLogsCollection.insertOne(doc);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (DEBUG) console.warn(`⚠️  Failed to log scan: ${msg}`);
  }
}

/**
 * Backward-compatible logScanReport for old pipeline.
 */
export async function logScanReport(report: {
  package: string;
  version: string;
  timestamp: string;
  score: number;
  decision: Decision;
  reasons: string[];
  details: Record<string, unknown>;
}): Promise<void> {
  if (!isConnected || !scanLogsCollection) return;

  try {
    const doc: Partial<ScanLogDocument> = {
      package: report.package,
      version: report.version,
      ecosystem: 'npm',
      timestamp: new Date(report.timestamp),
      score: report.score,
      decision: report.decision,
      reasons: report.reasons,
      phantom_deps: [],
      signals: {
        phantom: [],
        scripts: [],
        network: [],
        entropy: [],
        fs: [],
        exec: [],
        eval: [],
        gemini: null,
      },
      phantom_scan_results: null,
    };

    await scanLogsCollection.insertOne(doc as ScanLogDocument);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (DEBUG) console.warn(`⚠️  Failed to log scan report: ${msg}`);
  }
}

export async function getScanHistory(
  packageName: string,
  limit: number = 10
): Promise<ScanLogDocument[]> {
  if (!isConnected || !scanLogsCollection) {
    throw new Error('Database not connected. Make sure MongoDB is running and MONGODB_URI is configured.');
  }

  try {
    return await scanLogsCollection
      .find({ package: packageName })
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to retrieve history: ${msg}`);
  }
}

export async function closeDatabase(): Promise<void> {
  if (client) {
    try {
      await client.close();
    } catch {
      // Ignore close errors
    } finally {
      client = null;
      db = null;
      scanLogsCollection = null;
      isConnected = false;
    }
  }
}
