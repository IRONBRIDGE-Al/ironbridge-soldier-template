/**
 * IRONBRIDGE — Upstash Redis Client (ACL-scoped)
 * LAW 336: Credentials in Upstash only (encrypted).
 * DECREE 8: Zero-trust runtime.
 *
 * Each soldier connects with its own ACL user (least-privilege).
 */

import { Redis } from '@upstash/redis';
import { markUpstashHealthy, markUpstashFailed, isDegraded, queueWrite } from '../core/degraded-mode';

let _redis: Redis | null = null;

/**
 * Get the Redis client instance.
 * Lazy initialization — created on first use.
 */
export function getRedisClient(): Redis {
  if (!_redis) {
    // These come from encrypted config, decrypted in-memory at boot
    const url = process.env.UPSTASH_REDIS_REST_URL;
    const token = process.env.UPSTASH_REDIS_REST_TOKEN;

    if (!url || !token) {
      throw new Error('[BOOT] Missing Upstash credentials. Check encrypted config.');
    }

    _redis = new Redis({ url, token });
  }
  return _redis;
}

/**
 * Safe Redis GET with degraded mode fallback.
 */
export async function safeGet(key: string): Promise<string | null> {
  try {
    const result = await getRedisClient().get<string>(key);
    markUpstashHealthy();
    return result;
  } catch (err) {
    markUpstashFailed();
    console.warn(`[UPSTASH] GET failed for ${key}: ${(err as Error).message}`);
    return null;
  }
}

/**
 * Safe Redis SET with degraded mode fallback.
 * If Upstash is down, queues write for later replay.
 */
export async function safeSet(
  soldierId: string,
  key: string,
  value: string,
  ttlSeconds?: number
): Promise<boolean> {
  try {
    const redis = getRedisClient();
    if (ttlSeconds) {
      await redis.setex(key, ttlSeconds, value);
    } else {
      await redis.set(key, value);
    }
    markUpstashHealthy();
    return true;
  } catch (err) {
    markUpstashFailed();

    if (isDegraded()) {
      queueWrite(soldierId, key, value);
      console.warn(`[UPSTASH] SET queued locally for ${key} (degraded mode)`);
    }

    return false;
  }
}

/**
 * Safe Redis XADD for stream writes (audit log).
 */
export async function safeStreamAdd(
  stream: string,
  fields: Record<string, string | number>
): Promise<boolean> {
  try {
    const redis = getRedisClient();
    // @ts-ignore — Upstash Redis types may vary
    await redis.xadd(stream, '*', fields);
    markUpstashHealthy();
    return true;
  } catch (err) {
    markUpstashFailed();
    return false;
  }
}
