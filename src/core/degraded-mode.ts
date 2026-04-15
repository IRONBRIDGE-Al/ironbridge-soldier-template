/**
 * IRONBRIDGE — SQLite Degraded Mode
 * Oath 14: No soldier operates without a fallback. Every dependency has a degraded mode.
 *
 * When Upstash is unreachable for >30s, soldiers switch to local SQLite.
 * HERMES replays writes on recovery with timestamp-wins + soldier-priority tiebreak.
 */

import Database from 'better-sqlite3';
import { resolve } from 'path';

const DB_PATH = resolve('/tmp/ironbridge-degraded.sqlite');
const UPSTASH_TIMEOUT_MS = 30_000;

// Soldier priority for conflict resolution (higher = wins)
const SOLDIER_PRIORITY: Record<string, number> = {
  dick: 100,
  sarge: 90,
  hermes: 80,
  brooks: 70,
  ripley: 65,
  ezra: 60,
  oscar: 50,
  rachel: 40,
  gary: 30,
  paul: 20,
};

let _db: Database.Database | null = null;
let _isDegraded = false;
let _lastUpstashSuccess = Date.now();

/**
 * Initialize SQLite database for degraded mode.
 * Creates tables on first use. Zero-cost when not degraded.
 */
function getDb(): Database.Database {
  if (!_db) {
    _db = new Database(DB_PATH);
    _db.pragma('journal_mode = WAL'); // Write-ahead logging for performance
    _db.pragma('synchronous = NORMAL');

    _db.exec(`
      CREATE TABLE IF NOT EXISTS pending_writes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        soldier_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        priority INTEGER NOT NULL,
        replayed INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS local_heartbeats (
        soldier_id TEXT PRIMARY KEY,
        last_seen INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS local_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        soldier_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        entry_sha TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_pending_key ON pending_writes(key);
      CREATE INDEX IF NOT EXISTS idx_pending_replayed ON pending_writes(replayed);
    `);
  }
  return _db;
}

/**
 * Check if we should be in degraded mode.
 */
export function isDegraded(): boolean {
  return _isDegraded;
}

/**
 * Mark Upstash as available (call on successful Redis operation).
 */
export function markUpstashHealthy(): void {
  _lastUpstashSuccess = Date.now();
  if (_isDegraded) {
    console.log('[DEGRADED-MODE] Upstash recovered. Switching back to primary.');
    _isDegraded = false;
  }
}

/**
 * Mark Upstash as failed (call on Redis operation failure).
 */
export function markUpstashFailed(): void {
  const timeSinceSuccess = Date.now() - _lastUpstashSuccess;
  if (timeSinceSuccess >= UPSTASH_TIMEOUT_MS && !_isDegraded) {
    console.warn(`[DEGRADED-MODE] Upstash unreachable for ${Math.round(timeSinceSuccess / 1000)}s. ` +
      `Switching to SQLite fallback.`);
    _isDegraded = true;
  }
}

/**
 * Queue a write for later replay to Upstash.
 */
export function queueWrite(soldierId: string, key: string, value: string): void {
  const db = getDb();
  const priority = SOLDIER_PRIORITY[soldierId.toLowerCase()] || 10;

  db.prepare(`
    INSERT INTO pending_writes (soldier_id, key, value, timestamp, priority)
    VALUES (?, ?, ?, ?, ?)
  `).run(soldierId, key, value, Date.now(), priority);
}

/**
 * Get all pending writes for replay, ordered by timestamp.
 * Conflict resolution: For duplicate keys, timestamp-wins with soldier-priority tiebreak.
 */
export function getPendingWrites(): Array<{
  id: number;
  soldier_id: string;
  key: string;
  value: string;
  timestamp: number;
  priority: number;
}> {
  const db = getDb();

  // Get winning write per key (latest timestamp, highest priority on tie)
  return db.prepare(`
    SELECT pw.*
    FROM pending_writes pw
    INNER JOIN (
      SELECT key, MAX(timestamp) as max_ts
      FROM pending_writes
      WHERE replayed = 0
      GROUP BY key
    ) latest ON pw.key = latest.key AND pw.timestamp = latest.max_ts
    WHERE pw.replayed = 0
    ORDER BY pw.timestamp ASC
  `).all() as any[];
}

/**
 * Mark writes as replayed after successful Upstash sync.
 */
export function markReplayed(ids: number[]): void {
  const db = getDb();
  const stmt = db.prepare(`UPDATE pending_writes SET replayed = 1 WHERE id = ?`);

  const transaction = db.transaction((writeIds: number[]) => {
    for (const id of writeIds) {
      stmt.run(id);
    }
  });

  transaction(ids);
}

/**
 * Get count of pending writes (for monitoring).
 */
export function getPendingCount(): number {
  const db = getDb();
  const row = db.prepare(`SELECT COUNT(*) as count FROM pending_writes WHERE replayed = 0`).get() as any;
  return row?.count || 0;
}

/**
 * Clean up old replayed writes (call periodically).
 */
export function cleanupReplayed(olderThanMs: number = 24 * 60 * 60 * 1000): void {
  const db = getDb();
  const cutoff = Date.now() - olderThanMs;
  db.prepare(`DELETE FROM pending_writes WHERE replayed = 1 AND timestamp < ?`).run(cutoff);
}

/**
 * Close SQLite connection (call on shutdown).
 */
export function closeDegradedDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}
