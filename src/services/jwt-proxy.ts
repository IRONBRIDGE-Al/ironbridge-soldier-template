/**
 * IRONBRIDGE — Obsidian JWT Proxy Middleware
 * DECREE 6: Obsidian localhost:27124 only.
 * LAW 345: All Obsidian REST API calls routed through HERMES JWT proxy.
 *
 * No soldier accesses Obsidian directly. All calls go through this proxy
 * which adds JWT authentication + rate limiting per soldier.
 *
 * Deploy on Hetzner as part of HERMES.
 * Other soldiers call the proxy at localhost:27125 instead of localhost:27124.
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { createHmac, randomBytes } from 'crypto';
import { deriveSoldierKey } from '../core/master-key';
import { auditLog } from '../core/audit';

// ─── CONFIGURATION ───────────────────────────────────────────────
const PROXY_PORT = 27125;               // Soldiers connect here
const OBSIDIAN_HOST = 'localhost';
const OBSIDIAN_PORT = 27124;            // Actual Obsidian REST API
const JWT_TTL_MS = 15 * 60 * 1000;     // 15 minutes
const SLIDING_REFRESH_RATIO = 0.8;      // Refresh at 80% TTL
const RATE_LIMIT_WINDOW_MS = 60_000;    // 1 minute
const RATE_LIMIT_MAX = 60;              // 60 requests per minute per soldier

// ─── TOKEN MANAGEMENT ────────────────────────────────────────────
interface TokenEntry {
  token: string;
  soldierId: string;
  issuedAt: number;
  expiresAt: number;
}

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const _activeTokens: Map<string, TokenEntry> = new Map();
const _rateLimits: Map<string, RateLimitEntry> = new Map();

// Primary signing key (HERMES). SARGE has backup.
let _signingKeyHolder: 'hermes' | 'sarge' = 'hermes';

function getSigningKey(): Buffer {
  return deriveSoldierKey(_signingKeyHolder, 'jwt');
}

/**
 * Issue a short-lived JWT for a soldier.
 */
function issueToken(soldierId: string): string {
  const key = getSigningKey();
  const now = Date.now();

  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: soldierId,
    iat: now,
    exp: now + JWT_TTL_MS,
    jti: randomBytes(16).toString('hex'),
  })).toString('base64url');

  const signature = createHmac('sha256', key)
    .update(`${header}.${payload}`)
    .digest('base64url');

  const token = `${header}.${payload}.${signature}`;

  _activeTokens.set(token, {
    token,
    soldierId,
    issuedAt: now,
    expiresAt: now + JWT_TTL_MS,
  });

  return token;
}

/**
 * Verify a JWT and return the soldier ID.
 * Implements sliding refresh — auto-reissues at 80% TTL.
 */
function verifyToken(token: string): { soldierId: string; newToken?: string } {
  const entry = _activeTokens.get(token);

  if (!entry) {
    throw new Error('Invalid or unknown token');
  }

  const now = Date.now();

  if (now >= entry.expiresAt) {
    _activeTokens.delete(token);
    throw new Error('Token expired');
  }

  // Verify HMAC
  const [header, payload, signature] = token.split('.');
  const key = getSigningKey();
  const expected = createHmac('sha256', key)
    .update(`${header}.${payload}`)
    .digest('base64url');

  if (signature !== expected) {
    _activeTokens.delete(token);
    throw new Error('Token signature invalid');
  }

  // Sliding refresh: if past 80% TTL, issue new token
  const elapsed = now - entry.issuedAt;
  const threshold = JWT_TTL_MS * SLIDING_REFRESH_RATIO;
  let newToken: string | undefined;

  if (elapsed >= threshold) {
    newToken = issueToken(entry.soldierId);
    _activeTokens.delete(token); // Old token revoked
  }

  return { soldierId: entry.soldierId, newToken };
}

/**
 * Check rate limit for a soldier.
 */
function checkRateLimit(soldierId: string): boolean {
  const now = Date.now();
  let entry = _rateLimits.get(soldierId);

  if (!entry || now - entry.windowStart >= RATE_LIMIT_WINDOW_MS) {
    entry = { count: 0, windowStart: now };
    _rateLimits.set(soldierId, entry);
  }

  entry.count++;
  return entry.count <= RATE_LIMIT_MAX;
}

/**
 * Forward request to Obsidian REST API with Bearer auth.
 */
async function proxyToObsidian(
  req: IncomingMessage,
  obsidianApiKey: string
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const url = `http://${OBSIDIAN_HOST}:${OBSIDIAN_PORT}${req.url}`;

    const headers: Record<string, string> = {
      'Authorization': `Bearer ${obsidianApiKey}`,
      'Content-Type': req.headers['content-type'] || 'application/json',
    };

    const options = {
      method: req.method,
      headers,
    };

    const http = require('http');
    const proxyReq = http.request(url, options, (proxyRes: any) => {
      let body = '';
      proxyRes.on('data', (chunk: Buffer) => body += chunk.toString());
      proxyRes.on('end', () => {
        resolve({
          status: proxyRes.statusCode,
          body,
          headers: proxyRes.headers,
        });
      });
    });

    proxyReq.on('error', reject);

    // Forward request body
    req.on('data', (chunk: Buffer) => proxyReq.write(chunk));
    req.on('end', () => proxyReq.end());
  });
}

/**
 * Start the JWT proxy server.
 *
 * @param obsidianApiKey - The actual Obsidian REST API key (loaded from encrypted config)
 */
export function startJwtProxy(obsidianApiKey: string): void {
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      // ─── TOKEN ENDPOINT ───────────────────────────────────────
      if (req.url === '/auth/token' && req.method === 'POST') {
        // Soldier requests a token by providing HMAC proof of identity
        let body = '';
        req.on('data', (chunk: Buffer) => body += chunk.toString());
        req.on('end', () => {
          try {
            const { soldier_id, hmac } = JSON.parse(body);
            // Verify soldier identity via HMAC
            const soldierKey = deriveSoldierKey(soldier_id, 'hmac');
            const expected = createHmac('sha256', soldierKey)
              .update(soldier_id)
              .digest('hex');

            if (hmac !== expected) {
              res.writeHead(401);
              res.end(JSON.stringify({ error: 'Invalid HMAC proof' }));
              return;
            }

            const token = issueToken(soldier_id);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ token, expires_in: JWT_TTL_MS }));
          } catch (err) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // ─── PROXY ENDPOINT ───────────────────────────────────────
      const authHeader = req.headers['authorization'];
      if (!authHeader?.startsWith('Bearer ')) {
        res.writeHead(401);
        res.end(JSON.stringify({ error: 'Missing Bearer token' }));
        return;
      }

      const token = authHeader.slice(7);
      const { soldierId, newToken } = verifyToken(token);

      // Rate limit check
      if (!checkRateLimit(soldierId)) {
        res.writeHead(429);
        res.end(JSON.stringify({ error: 'Rate limit exceeded', soldier: soldierId }));
        await auditLog({
          soldier: soldierId,
          action: 'obsidian_rate_limited',
          target: req.url || '/',
        });
        return;
      }

      // Forward to Obsidian
      const result = await proxyToObsidian(req, obsidianApiKey);

      // Return response with optional refreshed token
      const responseHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (newToken) {
        responseHeaders['X-New-Token'] = newToken;
      }

      res.writeHead(result.status, responseHeaders);
      res.end(result.body);

      // Audit the access
      await auditLog({
        soldier: soldierId,
        action: 'obsidian_access',
        target: `${req.method} ${req.url}`,
        result: `${result.status}`,
      });

    } catch (err) {
      res.writeHead(403);
      res.end(JSON.stringify({ error: (err as Error).message }));
    }
  });

  server.listen(PROXY_PORT, '127.0.0.1', () => {
    console.log(`[JWT-PROXY] Obsidian proxy running on localhost:${PROXY_PORT}`);
    console.log(`[JWT-PROXY] Signing key holder: ${_signingKeyHolder.toUpperCase()}`);
  });
}

/**
 * Failover: Switch signing key to SARGE (if HERMES is down).
 */
export function failoverToSarge(): void {
  _signingKeyHolder = 'sarge';
  _activeTokens.clear(); // Invalidate all existing tokens
  console.warn('[JWT-PROXY] FAILOVER: Signing key switched to SARGE (HERMES backup).');
}

/**
 * Recover: Switch signing key back to HERMES.
 */
export function recoverToHermes(): void {
  _signingKeyHolder = 'hermes';
  _activeTokens.clear();
  console.log('[JWT-PROXY] RECOVERED: Signing key switched back to HERMES.');
}
