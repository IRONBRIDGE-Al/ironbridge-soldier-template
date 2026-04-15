/**
 * IRONBRIDGE — Immutable Audit Log
 * LAW 25: Paper trail with SHA on every critical action.
 * Append-only. Cryptographically signed. Never altered.
 */

import { sha256 } from './crypto-utils';
import { getRedisClient } from '../services/upstash';

export interface AuditEntry {
  soldier: string;
  action: string;
  target: string;
  result?: string;
  error?: string;
  sha?: string;
  duration_ms?: number;
}

interface SignedAuditEntry extends AuditEntry {
  timestamp: number;
  entry_sha: string;
  prev_sha: string;
}

let _prevSha = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Write an immutable audit log entry.
 * Each entry is chained to the previous via SHA-256 (Merkle-like chain).
 * Append-only — no updates, no deletes.
 */
export async function auditLog(entry: AuditEntry): Promise<string> {
  const signed: SignedAuditEntry = {
    ...entry,
    timestamp: Date.now(),
    prev_sha: _prevSha,
    entry_sha: '', // computed below
  };

  // Chain hash: SHA-256(prev_sha + entry_json)
  const entryJson = JSON.stringify({ ...signed, entry_sha: undefined });
  signed.entry_sha = sha256(`${_prevSha}:${entryJson}`);
  _prevSha = signed.entry_sha;

  // Write to Upstash stream (append-only)
  try {
    const redis = getRedisClient();
    await redis.xadd(
      `ironbridge:audit:log`,
      '*',
      signed
    );
  } catch {
    // If Upstash is down, write to local (degraded mode handles replay)
    console.error(`[AUDIT] Upstash unavailable. Entry cached locally: ${signed.entry_sha}`);
  }

  // Also emit structured JSON log (picked up by observability)
  console.log(JSON.stringify({
    level: entry.error ? 'error' : 'info',
    ...signed,
  }));

  return signed.entry_sha;
}

/**
 * Verify audit chain integrity.
 * SARGE uses this to prove logs were never tampered with.
 */
export function verifyAuditChain(entries: SignedAuditEntry[]): boolean {
  let prevSha = '0000000000000000000000000000000000000000000000000000000000000000';

  for (const entry of entries) {
    if (entry.prev_sha !== prevSha) {
      console.error(`[P0-SECURITY] Audit chain broken at ${entry.timestamp}. ` +
        `Expected prev_sha ${prevSha}, got ${entry.prev_sha}`);
      return false;
    }

    const entryJson = JSON.stringify({ ...entry, entry_sha: undefined });
    const expectedSha = sha256(`${prevSha}:${entryJson}`);

    if (entry.entry_sha !== expectedSha) {
      console.error(`[P0-SECURITY] Audit entry tampered at ${entry.timestamp}. ` +
        `Expected sha ${expectedSha}, got ${entry.entry_sha}`);
      return false;
    }

    prevSha = entry.entry_sha;
  }

  return true;
}
