/**
 * IRONBRIDGE — Inter-Soldier Message Authentication
 * Oath 16: Messages are signed. Compromised soldiers cannot impersonate command.
 * All Upstash broadcasts carry HMAC signatures.
 */

import { signMessage, verifyMessage } from './crypto-utils';
import { deriveSoldierKey } from './master-key';
import { getRedisClient } from '../services/upstash';
import { auditLog } from './audit';

export interface SignedBroadcast {
  sender_id: string;
  timestamp: number;
  payload: Record<string, unknown>;
  hmac: string;
}

/**
 * Create a signed broadcast message.
 * Every message includes sender ID, timestamp, payload, and HMAC signature.
 */
export function createBroadcast(
  soldierId: string,
  payload: Record<string, unknown>
): SignedBroadcast {
  const message = {
    sender_id: soldierId,
    timestamp: Date.now(),
    payload,
  };

  const hmacKey = deriveSoldierKey(soldierId, 'hmac');
  const hmac = signMessage(message, hmacKey);

  return { ...message, hmac };
}

/**
 * Verify a received broadcast message.
 * Rejects unsigned, expired, or tampered messages.
 *
 * @param message - The received broadcast
 * @param maxAgeMs - Maximum message age (default: 5 minutes)
 * @returns true if valid, throws on invalid
 */
export function verifyBroadcast(
  message: SignedBroadcast,
  maxAgeMs: number = 5 * 60 * 1000
): boolean {
  // Check required fields
  if (!message.sender_id || !message.timestamp || !message.hmac || !message.payload) {
    throw new Error(`[BROADCAST-REJECT] Missing required fields from claimed sender: ${message.sender_id}`);
  }

  // Check message age (prevents replay attacks)
  const age = Date.now() - message.timestamp;
  if (age > maxAgeMs) {
    throw new Error(
      `[BROADCAST-REJECT] Message from ${message.sender_id} is ${Math.round(age / 1000)}s old. ` +
      `Max age: ${maxAgeMs / 1000}s. Possible replay attack.`
    );
  }

  // Verify HMAC using sender's derived key
  const senderKey = deriveSoldierKey(message.sender_id, 'hmac');
  const { hmac, ...payloadWithoutHmac } = message;
  const valid = verifyMessage(payloadWithoutHmac, hmac, senderKey);

  if (!valid) {
    throw new Error(
      `[P0-SECURITY] HMAC verification FAILED for message from ${message.sender_id}. ` +
      `Possible compromised soldier or impersonation. SARGE: investigate immediately.`
    );
  }

  return true;
}

/**
 * Publish a signed broadcast to Upstash.
 */
export async function publishBroadcast(
  soldierId: string,
  channel: string,
  payload: Record<string, unknown>
): Promise<void> {
  const redis = getRedisClient();
  const broadcast = createBroadcast(soldierId, payload);

  await redis.publish(channel, JSON.stringify(broadcast));

  await auditLog({
    soldier: soldierId,
    action: 'broadcast_sent',
    target: channel,
    sha: broadcast.hmac,
  });
}

/**
 * Subscribe to a channel and verify all incoming messages.
 */
export function onBroadcast(
  channel: string,
  handler: (payload: Record<string, unknown>, senderId: string) => void | Promise<void>
): void {
  const redis = getRedisClient();

  redis.subscribe(channel, async (rawMessage: string) => {
    try {
      const message: SignedBroadcast = JSON.parse(rawMessage);
      verifyBroadcast(message);

      await handler(message.payload, message.sender_id);
    } catch (err) {
      // Log security event — do NOT silently drop
      await auditLog({
        soldier: 'SYSTEM',
        action: 'broadcast_rejected',
        target: channel,
        error: (err as Error).message,
      });
    }
  });
}
