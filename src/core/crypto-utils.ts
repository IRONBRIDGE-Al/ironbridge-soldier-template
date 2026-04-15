/**
 * IRONBRIDGE — Cryptographic Utilities
 * LAW 345: Memory Resilience Protocol — encryption layer
 * DECREE 8: Zero-Trust Runtime
 */

import {
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  hkdf as nodeHkdf,
} from 'crypto';

/**
 * HKDF key derivation (RFC 5869).
 * Used to derive per-soldier keys from master key.
 */
export function hkdf(
  ikm: Buffer,
  length: number,
  salt: string,
  info: string
): Buffer {
  return new Promise<Buffer>((resolve, reject) => {
    nodeHkdf('sha256', ikm, salt, info, length, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(Buffer.from(derivedKey));
    });
  }) as unknown as Buffer;
}

/**
 * Synchronous HKDF using HMAC-based extract-and-expand.
 */
export function hkdfSync(
  ikm: Buffer,
  length: number,
  salt: string,
  info: string
): Buffer {
  // Extract
  const prk = createHmac('sha256', salt).update(ikm).digest();

  // Expand
  let t = Buffer.alloc(0);
  let okm = Buffer.alloc(0);
  let i = 1;

  while (okm.length < length) {
    const input = Buffer.concat([t, Buffer.from(info), Buffer.from([i])]);
    t = createHmac('sha256', prk).update(input).digest();
    okm = Buffer.concat([okm, t]);
    i++;
  }

  return okm.subarray(0, length);
}

/**
 * AES-256-GCM encryption.
 * Used for encrypting sensitive memory before writing to Obsidian/GitHub.
 * Plaintext NEVER touches persistent storage.
 */
export function encrypt(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  // Format: iv:authTag:ciphertext (all hex)
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * AES-256-GCM decryption.
 * Decrypts in-memory only. Result never persisted.
 */
export function decrypt(encryptedStr: string, key: Buffer): string {
  const [ivHex, authTagHex, ciphertext] = encryptedStr.split(':');

  if (!ivHex || !authTagHex || !ciphertext) {
    throw new Error('[CRYPTO] Invalid encrypted format. Expected iv:authTag:ciphertext');
  }

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * HMAC-SHA256 signing for inter-soldier message authentication.
 * Oath 16: Messages are signed. Compromised soldiers cannot impersonate command.
 */
export function signMessage(payload: object, key: Buffer): string {
  const data = JSON.stringify(payload);
  return createHmac('sha256', key).update(data).digest('hex');
}

/**
 * HMAC-SHA256 verification.
 */
export function verifyMessage(payload: object, signature: string, key: Buffer): boolean {
  const expected = signMessage(payload, key);
  // Constant-time comparison
  if (expected.length !== signature.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) {
    result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return result === 0;
}

/**
 * SHA-256 hash for audit trail / paper trail (LAW 25).
 */
export function sha256(data: string): string {
  return createHmac('sha256', 'ironbridge-audit').update(data).digest('hex');
}
