/**
 * IRONBRIDGE — API Rate Budget & Circuit Breaker
 * LAW 345: Per-soldier API budget tracking.
 * Prevents any single soldier from starving the others.
 */

import { getRedisClient } from '../services/upstash';
import { auditLog } from './audit';

export interface BudgetConfig {
  platform: string;       // 'groq', 'gemini', 'github', etc.
  softLimit: number;      // Requests per window — warning threshold
  hardLimit: number;      // Requests per window — circuit breaker
  windowMs: number;       // Time window in ms (default: 60s)
  fallback?: string;      // Fallback platform on hard limit
}

interface CircuitState {
  count: number;
  windowStart: number;
  isOpen: boolean;        // true = circuit broken, reject requests
  openedAt: number;
  cooldownMs: number;     // Time to wait before retrying (exponential backoff)
}

const _circuits: Map<string, CircuitState> = new Map();
const _configs: Map<string, BudgetConfig> = new Map();

// Consecutive failure tracking for circuit breaker
const _failures: Map<string, number> = new Map();
const FAILURE_THRESHOLD = 3; // LAW 191: 3 fails = fallback

/**
 * Register a budget configuration for a platform.
 */
export function registerBudget(config: BudgetConfig): void {
  _configs.set(config.platform, config);
  _circuits.set(config.platform, {
    count: 0,
    windowStart: Date.now(),
    isOpen: false,
    openedAt: 0,
    cooldownMs: 5000, // Start at 5s, exponential backoff
  });
}

/**
 * Check if a request is allowed within budget.
 * Returns the platform to use (may be fallback if primary is exhausted).
 *
 * @throws if all platforms exhausted (hard limit + no fallback)
 */
export async function checkBudget(
  soldierId: string,
  platform: string
): Promise<string> {
  const config = _configs.get(platform);
  if (!config) return platform; // No budget configured, allow

  const circuit = _circuits.get(platform)!;

  // Reset window if expired
  if (Date.now() - circuit.windowStart >= config.windowMs) {
    circuit.count = 0;
    circuit.windowStart = Date.now();
  }

  // Check circuit breaker (consecutive failures)
  if (circuit.isOpen) {
    const timeSinceOpen = Date.now() - circuit.openedAt;
    if (timeSinceOpen < circuit.cooldownMs) {
      if (config.fallback) {
        console.warn(`[BUDGET] Circuit open for ${platform}. Falling back to ${config.fallback}`);
        return checkBudget(soldierId, config.fallback);
      }
      throw new Error(`[BUDGET] Circuit open for ${platform}. No fallback. Request denied.`);
    }
    // Cooldown expired, half-open the circuit (allow one test request)
    circuit.isOpen = false;
  }

  // Check hard limit
  if (circuit.count >= config.hardLimit) {
    await auditLog({
      soldier: soldierId,
      action: 'budget_hard_limit',
      target: platform,
      result: `${circuit.count}/${config.hardLimit} requests in window`,
    });

    if (config.fallback) {
      return checkBudget(soldierId, config.fallback);
    }
    throw new Error(`[BUDGET] Hard limit reached for ${platform}. No fallback available.`);
  }

  // Check soft limit (warning only)
  if (circuit.count >= config.softLimit) {
    console.warn(
      `[BUDGET] Soft limit warning: ${platform} at ${circuit.count}/${config.softLimit}. ` +
      `Hard limit: ${config.hardLimit}`
    );
  }

  // Increment counter
  circuit.count++;

  // Also track in Upstash for cross-soldier visibility
  try {
    const redis = getRedisClient();
    await redis.incr(`ironbridge:budget:${platform}:${soldierId}`);
    await redis.expire(`ironbridge:budget:${platform}:${soldierId}`, Math.ceil(config.windowMs / 1000));
  } catch {
    // Upstash down — budget still enforced locally
  }

  return platform;
}

/**
 * Record a successful API call (resets failure counter).
 */
export function recordSuccess(platform: string): void {
  _failures.set(platform, 0);

  const circuit = _circuits.get(platform);
  if (circuit) {
    circuit.cooldownMs = 5000; // Reset backoff
  }
}

/**
 * Record a failed API call. Opens circuit after FAILURE_THRESHOLD consecutive failures.
 */
export function recordFailure(platform: string): void {
  const count = (_failures.get(platform) || 0) + 1;
  _failures.set(platform, count);

  if (count >= FAILURE_THRESHOLD) {
    const circuit = _circuits.get(platform);
    if (circuit && !circuit.isOpen) {
      circuit.isOpen = true;
      circuit.openedAt = Date.now();
      circuit.cooldownMs = Math.min(circuit.cooldownMs * 2, 300_000); // Max 5 min backoff
      console.error(`[BUDGET] Circuit OPEN for ${platform} after ${count} failures. ` +
        `Cooldown: ${circuit.cooldownMs / 1000}s`);
    }
  }
}

/**
 * Register default LLM budgets for IronBridge.
 */
export function registerDefaultBudgets(): void {
  registerBudget({
    platform: 'groq',
    softLimit: 25,      // 25 requests/min soft warning
    hardLimit: 30,       // 30 requests/min hard limit (Groq free = 30 rpm)
    windowMs: 60_000,
    fallback: 'gemini',
  });

  registerBudget({
    platform: 'gemini',
    softLimit: 50,
    hardLimit: 60,
    windowMs: 60_000,
    fallback: undefined, // No fallback — queue the job
  });

  registerBudget({
    platform: 'github',
    softLimit: 4000,
    hardLimit: 5000,     // GitHub API = 5000/hr
    windowMs: 3600_000,
    fallback: undefined,
  });
}
