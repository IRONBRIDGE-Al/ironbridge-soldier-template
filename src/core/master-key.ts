/**
 * IRONBRIDGE — Root-of-Trust Bootstrap
 * LAW 345: Master key lives on iron only.
 * Oath 15: Root of trust lives on iron. Upstash is servant, not master.
 * Oath 17: The master key is never whole in one place except during controlled recovery.
 */

import { readFileSync, statSync } from 'fs';
import { createHmac } from 'crypto';
import { hkdf } from './crypto-utils';

const MASTER_KEY_PATH = '/etc/ironbridge/master.key';
const EXPECTED_MODE = 0o400; // read-only by owner

let _masterKey: Buffer | null = null;

/**
 * Load master key from Hetzner disk with strict permission checks.
 * Fails fast if permissions are wrong — never load a world-readable key.
 */
export function loadMasterKey(): Buffer {
  if (_masterKey) return _masterKey;

  // Verify file permissions before reading
  const stat = statSync(MASTER_KEY_PATH);
  const fileMode = stat.mode & 0o777;

  if (fileMode !== EXPECTED_MODE) {
    throw new Error(
      `[P0-SECURITY] Master key has wrong permissions: ${fileMode.toString(8)}. ` +
      `Expected ${EXPECTED_MODE.toString(8)}. Refusing to load. SARGE: investigate.`
    );
  }

  // Verify owned by ironbridge user (UID check)
  if (stat.uid === 0) {
    throw new Error(
      `[P0-SECURITY] Master key is owned by root. Must be owned by ironbridge user. ` +
      `Refusing to load.`
    );
  }

  _masterKey = readFileSync(MASTER_KEY_PATH);

  if (_masterKey.length < 32) {
    _masterKey = null;
    throw new Error('[P0-SECURITY] Master key too short. Minimum 32 bytes required.');
  }

  return _masterKey;
}

/**
 * Derive a per-soldier key using HKDF from master key.
 * Each soldier gets a unique key for HMAC, JWT, and AES-GCM operations.
 *
 * @param soldierId - e.g., 'dick', 'sarge', 'hermes'
 * @param purpose - e.g., 'hmac', 'jwt', 'aes-gcm'
 * @param salt - unique salt per derivation (default: soldier_id + purpose)
 */
export function deriveSoldierKey(
  soldierId: string,
  purpose: 'hmac' | 'jwt' | 'aes-gcm',
  salt?: string
): Buffer {
  const master = loadMasterKey();
  const info = `ironbridge:${soldierId}:${purpose}`;
  const derivedSalt = salt || `${soldierId}:${purpose}:v1`;

  return hkdf(master, 32, derivedSalt, info);
}

/**
 * Wipe master key from memory (call on graceful shutdown).
 */
export function wipeMasterKey(): void {
  if (_masterKey) {
    _masterKey.fill(0);
    _masterKey = null;
  }
}
