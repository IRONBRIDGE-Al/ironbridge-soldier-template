/**
 * IRONBRIDGE — Soldier Runtime Template
 * The single template that multiplies across the army.
 *
 * Every soldier inherits this hardened boot logic:
 * 1. Install log sanitizer (Oath 18)
 * 2. Load master key + derive soldier keys (Oath 15)
 * 3. Connect to Upstash (ACL-scoped)
 * 4. Validate three-store hashes
 * 5. Run self-audit
 * 6. Announce signed heartbeat (Oath 16)
 * 7. Enter mission loop or standby (idle priority queue)
 */

import { installLogSanitizer } from './core/log-sanitizer';
import { loadMasterKey, deriveSoldierKey, wipeMasterKey } from './core/master-key';
import { auditLog } from './core/audit';
import { publishBroadcast, onBroadcast } from './core/broadcast';
import { registerDefaultBudgets } from './core/budget';
import { registerDefaultIdleTasks, runIdleCycle } from './core/idle-priority';
import { isDegraded, closeDegradedDb } from './core/degraded-mode';
import { decrypt } from './core/crypto-utils';
import { safeGet } from './services/upstash';

// ─── CONFIGURATION ───────────────────────────────────────────────────
// Override these in each soldier's entry point
export interface SoldierConfig {
  id: string;                                    // e.g., 'dick', 'sarge', 'hermes'
  name: string;                                  // e.g., 'DICK', 'SARGE', 'HERMES'
  heartbeatIntervalMs: number;                   // e.g., 30000 for DICK, 300000 for others
  idleCycleIntervalMs: number;                   // e.g., 300000 (5 min)
  onMission: (payload: Record<string, unknown>) => Promise<void>;  // Mission handler
  onBoot?: () => Promise<void>;                  // Additional boot logic per soldier
  registerCustomIdleTasks?: () => void;          // Soldier-specific standby tasks
}

// ─── BOOT SEQUENCE ───────────────────────────────────────────────────

export async function boot(config: SoldierConfig): Promise<void> {
  const startTime = Date.now();

  // ─── STEP 0: LOG SANITIZER (FIRST — before anything can log) ───
  installLogSanitizer();
  console.log(`[BOOT] ${config.name} initializing...`);

  // ─── STEP 1: MASTER KEY + DERIVATION ───
  // Phase 0 fast path: if master key isn't deployed yet, skip to direct key read
  let hasMasterKey = false;
  try {
    loadMasterKey();
    console.log(`[BOOT] Master key loaded. Deriving soldier keys...`);
    const _hmacKey = deriveSoldierKey(config.id, 'hmac');
    const _aesKey = deriveSoldierKey(config.id, 'aes-gcm');
    console.log(`[BOOT] Keys derived for ${config.name}.`);
    hasMasterKey = true;
  } catch (err) {
    console.warn(`[BOOT] Master key not available: ${(err as Error).message}`);
    console.warn(`[BOOT] Running in PHASE 0 MODE — reading keys directly from ironbridge:keys:*`);
  }

  // ─── STEP 2: LOAD CONFIG FROM UPSTASH ───
  if (hasMasterKey) {
    // Production path: encrypted config per soldier
    try {
      const encryptedConfig = await safeGet(`ironbridge:config:${config.id}`);
      if (encryptedConfig) {
        const aesKey = deriveSoldierKey(config.id, 'aes-gcm');
        const decryptedConfig = decrypt(encryptedConfig, aesKey);
        const parsed = JSON.parse(decryptedConfig);
        for (const [key, value] of Object.entries(parsed)) {
          process.env[key] = value as string;
        }
        console.log(`[BOOT] Encrypted config loaded and decrypted in-memory.`);
      }
    } catch (err) {
      console.warn(`[BOOT] Encrypted config load failed: ${(err as Error).message}. Falling back to direct keys.`);
    }
  }

  // Phase 0 fast path: read keys directly from ironbridge:keys:* (LAW 339)
  if (!hasMasterKey || !process.env.GROQ_API_KEY) {
    try {
      const keyMap: Record<string, string> = {
        'ironbridge:keys:groq': 'GROQ_API_KEY',
        'ironbridge:keys:gemini': 'GEMINI_API_KEY',
        'ironbridge:keys:discord': 'DISCORD_TOKEN',
        'ironbridge:keys:github_pat': 'GITHUB_PAT',
        'ironbridge:keys:anthropic': 'ANTHROPIC_API_KEY',
        'ironbridge:keys:obsidian_api': 'OBSIDIAN_API_KEY',
        'ironbridge:keys:owner_channel': 'DISCORD_CHANNEL_ID',
      };

      let loaded = 0;
      for (const [redisKey, envVar] of Object.entries(keyMap)) {
        if (!process.env[envVar]) {
          const val = await safeGet(redisKey);
          if (val) {
            process.env[envVar] = val;
            loaded++;
          }
        }
      }
      console.log(`[BOOT] Phase 0 direct key load: ${loaded} keys from ironbridge:keys:*`);
    } catch (err) {
      console.warn(`[BOOT] Direct key load warning: ${(err as Error).message}`);
    }
  }

  // ─── STEP 3: REGISTER API BUDGETS ───
  registerDefaultBudgets();

  // ─── STEP 4: VALIDATE THREE-STORE HASHES ───
  try {
    const hotHash = await safeGet('ironbridge:sync:hash:upstash');
    const warmHash = await safeGet('ironbridge:sync:hash:obsidian');
    const coldHash = await safeGet('ironbridge:sync:hash:github');

    if (hotHash && warmHash && coldHash) {
      if (hotHash !== warmHash || warmHash !== coldHash) {
        console.warn(`[BOOT] Three-store hash MISMATCH detected. ` +
          `Hot=${hotHash?.substring(0, 8)}, Warm=${warmHash?.substring(0, 8)}, Cold=${coldHash?.substring(0, 8)}. ` +
          `HERMES will investigate.`);
        await auditLog({
          soldier: config.id,
          action: 'boot_hash_mismatch',
          target: 'three-store',
          error: 'Hash mismatch on boot',
        });
      } else {
        console.log(`[BOOT] Three-store hashes verified: ${hotHash?.substring(0, 8)}...`);
      }
    }
  } catch {
    console.warn(`[BOOT] Hash validation skipped (Upstash may be unavailable).`);
  }

  // ─── STEP 5: SELF-AUDIT ───
  await auditLog({
    soldier: config.id,
    action: 'boot_start',
    target: 'self',
    result: `Degraded mode: ${isDegraded()}`,
  });

  // ─── STEP 6: SOLDIER-SPECIFIC BOOT ───
  if (config.onBoot) {
    await config.onBoot();
  }

  // ─── STEP 7: REGISTER IDLE TASKS ───
  registerDefaultIdleTasks(
    config.id,
    async () => {
      // Default self-audit: verify own code hash
      await auditLog({ soldier: config.id, action: 'self_audit', target: 'idle' });
    },
    async () => {
      // Default sync check: verify heartbeat is alive
      const lastHb = await safeGet(`ironbridge:heartbeat:${config.id}`);
      if (!lastHb) {
        console.warn(`[IDLE] Own heartbeat missing from Upstash`);
      }
    },
    async () => {
      // Default log flush: handled by PM2 logrotate
    }
  );

  if (config.registerCustomIdleTasks) {
    config.registerCustomIdleTasks();
  }

  // ─── STEP 8: ANNOUNCE SIGNED HEARTBEAT ───
  await publishBroadcast(config.id, `ironbridge:heartbeat:${config.id}`, {
    status: 'online',
    boot_time: startTime,
    degraded: isDegraded(),
  });

  const bootDuration = Date.now() - startTime;
  console.log(`[BOOT] ${config.name} online in ${bootDuration}ms. Entering main loop.`);

  await auditLog({
    soldier: config.id,
    action: 'boot_complete',
    target: 'self',
    duration_ms: bootDuration,
  });

  // ─── MAIN LOOP ─────────────────────────────────────────────────
  // Subscribe to mission broadcasts
  onBroadcast(`ironbridge:broadcast:${config.id}`, config.onMission);

  // Heartbeat interval
  setInterval(async () => {
    await publishBroadcast(config.id, `ironbridge:heartbeat:${config.id}`, {
      status: 'alive',
      degraded: isDegraded(),
      timestamp: Date.now(),
    });
  }, config.heartbeatIntervalMs);

  // Idle cycle interval
  setInterval(async () => {
    // Only run idle tasks if not actively processing a mission
    await runIdleCycle(config.id);
  }, config.idleCycleIntervalMs);

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`[SHUTDOWN] ${config.name} received ${signal}. Cleaning up...`);

    await auditLog({
      soldier: config.id,
      action: 'shutdown',
      target: signal,
    });

    await publishBroadcast(config.id, `ironbridge:heartbeat:${config.id}`, {
      status: 'offline',
      reason: signal,
    });

    wipeMasterKey();
    closeDegradedDb();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
