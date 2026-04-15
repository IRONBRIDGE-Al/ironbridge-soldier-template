/**
 * IRONBRIDGE — Idle Work Priority Queue
 * When no orders are queued, soldiers run standby tasks in strict priority.
 * Security > Memory > Observability > Growth > Skill Sharpening
 *
 * Prevents "easy tasks first" drift.
 */

import { auditLog } from './audit';

export type IdlePriority = 1 | 2 | 3 | 4 | 5;

export interface IdleTask {
  name: string;
  priority: IdlePriority;
  handler: () => Promise<void>;
  intervalMs: number;       // Minimum time between runs
  lastRun: number;          // Timestamp of last execution
  enabled: boolean;
}

// Priority labels for logging
const PRIORITY_LABELS: Record<IdlePriority, string> = {
  1: 'SECURITY',
  2: 'MEMORY',
  3: 'OBSERVABILITY',
  4: 'GROWTH',
  5: 'SKILL_SHARPENING',
};

/**
 * Idle task registry. Each soldier registers their standby tasks here.
 */
const _tasks: IdleTask[] = [];

/**
 * Register an idle task with a priority level.
 * Tasks are always executed in priority order (1 first, 5 last).
 */
export function registerIdleTask(
  name: string,
  priority: IdlePriority,
  handler: () => Promise<void>,
  intervalMs: number = 5 * 60 * 1000 // Default: 5 minutes
): void {
  _tasks.push({
    name,
    priority,
    handler,
    intervalMs,
    lastRun: 0,
    enabled: true,
  });

  // Keep sorted by priority
  _tasks.sort((a, b) => a.priority - b.priority);
}

/**
 * Run one idle cycle. Executes all due tasks in priority order.
 * Called by the main loop when no jobs are queued.
 *
 * @param maxDurationMs - Maximum time to spend on idle tasks per cycle (default: 60s)
 */
export async function runIdleCycle(
  soldierId: string,
  maxDurationMs: number = 60_000
): Promise<void> {
  const cycleStart = Date.now();
  let tasksRun = 0;

  for (const task of _tasks) {
    // Check time budget
    if (Date.now() - cycleStart >= maxDurationMs) {
      break;
    }

    // Skip disabled tasks
    if (!task.enabled) continue;

    // Check if task is due
    const timeSinceLastRun = Date.now() - task.lastRun;
    if (timeSinceLastRun < task.intervalMs) continue;

    try {
      const taskStart = Date.now();
      await task.handler();
      const duration = Date.now() - taskStart;

      task.lastRun = Date.now();
      tasksRun++;

      await auditLog({
        soldier: soldierId,
        action: 'idle_task_completed',
        target: task.name,
        result: `priority=${PRIORITY_LABELS[task.priority]}`,
        duration_ms: duration,
      });
    } catch (err) {
      // Log but don't crash — idle tasks should never kill the main loop
      console.error(`[IDLE] Task "${task.name}" failed: ${(err as Error).message}`);

      await auditLog({
        soldier: soldierId,
        action: 'idle_task_failed',
        target: task.name,
        error: (err as Error).message,
      });
    }
  }

  if (tasksRun > 0) {
    console.log(`[IDLE] Completed ${tasksRun} standby tasks in ${Date.now() - cycleStart}ms`);
  }
}

/**
 * Get default idle tasks that ALL soldiers should register.
 * Individual soldiers add their own specific tasks on top.
 */
export function registerDefaultIdleTasks(
  soldierId: string,
  selfAuditFn: () => Promise<void>,
  syncCheckFn: () => Promise<void>,
  logFlushFn: () => Promise<void>
): void {
  // Priority 1: Security — self-audit, key integrity
  registerIdleTask(
    `${soldierId}:self-audit`,
    1,
    selfAuditFn,
    5 * 60 * 1000 // Every 5 minutes
  );

  // Priority 2: Memory — sync verification
  registerIdleTask(
    `${soldierId}:sync-check`,
    2,
    syncCheckFn,
    5 * 60 * 1000
  );

  // Priority 3: Observability — log flush
  registerIdleTask(
    `${soldierId}:log-flush`,
    3,
    logFlushFn,
    2 * 60 * 1000 // Every 2 minutes
  );
}
