/**
 * IRONBRIDGE — PM2 Ecosystem Configuration
 * DECREE 8: Zero-Trust Runtime
 * Enforces cluster mode, log rotation, graceful restart.
 *
 * Usage:
 *   pm2 start ecosystem.config.js
 *   pm2 reload ecosystem.config.js   # Zero-downtime reload
 *   pm2 deploy revert 1              # Rollback (RIPLEY standing order)
 */

const os = require('os');

// Use all available CPU cores for DICK (commander), single instance for others
const CPU_CORES = os.cpus().length;

// Base config shared by all soldiers
const baseConfig = {
  script: './dist/index.js',
  node_args: '--max-old-space-size=256',
  watch: false,                          // Never auto-restart on file changes in prod
  max_memory_restart: '256M',
  kill_timeout: 10000,                   // 10s graceful shutdown window
  listen_timeout: 8000,
  min_uptime: 5000,                      // Must run 5s before considered "started"
  max_restarts: 10,                      // Max restarts in restart_delay window
  restart_delay: 5000,                   // 5s between restart attempts
  autorestart: true,
  merge_logs: true,
  log_date_format: 'YYYY-MM-DDTHH:mm:ss.SSSZ',
  error_file: '/home/ironbridge/logs/error.log',
  out_file: '/home/ironbridge/logs/out.log',
  env: {
    NODE_ENV: 'production',
    IRONBRIDGE_ENV: 'prod',
  },
};

module.exports = {
  apps: [
    // ─── DICK (Commander) ─────────────────────────────────────────
    {
      ...baseConfig,
      name: 'dick-commander',
      cwd: '/home/ironbridge/soldiers/dick',
      instances: 1,                        // Single commander instance
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'dick',
        SOLDIER_NAME: 'DICK',
        HEARTBEAT_INTERVAL_MS: '30000',    // 30s heartbeat (commander)
        IDLE_CYCLE_INTERVAL_MS: '300000',  // 5min idle cycle
      },
    },

    // ─── SARGE (Security Chief) ──────────────────────────────────
    {
      ...baseConfig,
      name: 'sarge-security',
      cwd: '/home/ironbridge/soldiers/sarge',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'sarge',
        SOLDIER_NAME: 'SARGE',
        HEARTBEAT_INTERVAL_MS: '60000',
        IDLE_CYCLE_INTERVAL_MS: '300000',
      },
    },

    // ─── HERMES (Memory & Sync) ──────────────────────────────────
    {
      ...baseConfig,
      name: 'hermes-memory',
      cwd: '/home/ironbridge/soldiers/hermes',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'hermes',
        SOLDIER_NAME: 'HERMES',
        HEARTBEAT_INTERVAL_MS: '60000',
        IDLE_CYCLE_INTERVAL_MS: '60000',   // 1min — sync runs frequently
      },
    },

    // ─── BROOKS (Code Quality) ──────────────────────────────────
    {
      ...baseConfig,
      name: 'brooks-code',
      cwd: '/home/ironbridge/soldiers/brooks',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'brooks',
        SOLDIER_NAME: 'BROOKS',
        HEARTBEAT_INTERVAL_MS: '300000',
        IDLE_CYCLE_INTERVAL_MS: '600000',
      },
    },

    // ─── RIPLEY (Deployment) ─────────────────────────────────────
    {
      ...baseConfig,
      name: 'ripley-deploy',
      cwd: '/home/ironbridge/soldiers/ripley',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'ripley',
        SOLDIER_NAME: 'RIPLEY',
        HEARTBEAT_INTERVAL_MS: '300000',
        IDLE_CYCLE_INTERVAL_MS: '600000',
      },
    },

    // ─── EZRA (QA & Audit) ──────────────────────────────────────
    {
      ...baseConfig,
      name: 'ezra-qa',
      cwd: '/home/ironbridge/soldiers/ezra',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'ezra',
        SOLDIER_NAME: 'EZRA',
        HEARTBEAT_INTERVAL_MS: '300000',
        IDLE_CYCLE_INTERVAL_MS: '600000',
      },
    },

    // ─── OSCAR (Frontend) ───────────────────────────────────────
    {
      ...baseConfig,
      name: 'oscar-frontend',
      cwd: '/home/ironbridge/soldiers/oscar',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'oscar',
        SOLDIER_NAME: 'OSCAR',
        HEARTBEAT_INTERVAL_MS: '300000',
        IDLE_CYCLE_INTERVAL_MS: '600000',
      },
    },

    // ─── RACHEL (Intelligence) ──────────────────────────────────
    {
      ...baseConfig,
      name: 'rachel-intel',
      cwd: '/home/ironbridge/soldiers/rachel',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'rachel',
        SOLDIER_NAME: 'RACHEL',
        HEARTBEAT_INTERVAL_MS: '300000',
        IDLE_CYCLE_INTERVAL_MS: '900000',   // 15min — intel tasks are heavier
      },
    },

    // ─── GARY (Growth) ──────────────────────────────────────────
    {
      ...baseConfig,
      name: 'gary-growth',
      cwd: '/home/ironbridge/soldiers/gary',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'gary',
        SOLDIER_NAME: 'GARY',
        HEARTBEAT_INTERVAL_MS: '300000',
        IDLE_CYCLE_INTERVAL_MS: '900000',
      },
    },

    // ─── PAUL (Product) ─────────────────────────────────────────
    {
      ...baseConfig,
      name: 'paul-product',
      cwd: '/home/ironbridge/soldiers/paul',
      instances: 1,
      env: {
        ...baseConfig.env,
        SOLDIER_ID: 'paul',
        SOLDIER_NAME: 'PAUL',
        HEARTBEAT_INTERVAL_MS: '300000',
        IDLE_CYCLE_INTERVAL_MS: '900000',
      },
    },
  ],
};
