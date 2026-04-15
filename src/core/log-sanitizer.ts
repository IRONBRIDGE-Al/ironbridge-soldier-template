/**
 * IRONBRIDGE — Log Sanitization Transform Stream
 * Oath 18: Logs are sanitized before they touch disk. Secrets never rest in plaintext.
 *
 * Intercepts all stdout/stderr before PM2 writes to disk.
 * Scrubs patterns matching keys, tokens, secrets, passwords.
 */

import { Transform, TransformCallback } from 'stream';

// Patterns that indicate sensitive data (case-insensitive matching in context)
const SENSITIVE_PATTERNS = [
  // Key-value patterns (JSON, env, config)
  /(?:"|')?\b(?:key|token|secret|password|passwd|api_key|apikey|api_secret|auth|credential|master_key|private_key|access_token|refresh_token|bearer|authorization)\b(?:"|')?\s*[:=]\s*(?:"|')?([^\s"',}{)\]]+)/gi,

  // Upstash Redis URLs with credentials
  /rediss?:\/\/[^@\s]+@[^\s]+/gi,

  // Bearer tokens in headers
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,

  // Base64-encoded blobs that look like keys (40+ chars)
  /(?:^|\s)([A-Za-z0-9+/]{40,}={0,2})(?:\s|$)/g,

  // GitHub PATs
  /gh[ps]_[A-Za-z0-9]{36,}/g,

  // Hex strings that look like keys (64+ chars = 256+ bits)
  /(?:^|\s)([0-9a-fA-F]{64,})(?:\s|$)/g,

  // SSH private key blocks
  /-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----/g,

  // Discord tokens
  /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,

  // Anthropic API keys
  /sk-ant-[A-Za-z0-9\-]{20,}/g,

  // Generic long secret-looking strings after common prefixes
  /(?:GROQ|GEMINI|DISCORD|ANTHROPIC|UPSTASH|REDIS|GITHUB)[_\s]*(?:KEY|TOKEN|SECRET|PASSWORD)\s*[:=]\s*\S+/gi,
];

/**
 * Create a transform stream that sanitizes sensitive data from logs.
 * Attach to process.stdout and process.stderr before PM2 captures them.
 */
export class LogSanitizer extends Transform {
  _transform(chunk: Buffer, _encoding: string, callback: TransformCallback): void {
    let text = chunk.toString();

    for (const pattern of SENSITIVE_PATTERNS) {
      // Reset lastIndex for global patterns
      pattern.lastIndex = 0;
      text = text.replace(pattern, (match) => {
        // Keep a prefix for debugging context, redact the value
        const prefix = match.substring(0, Math.min(8, match.length));
        return `${prefix}[REDACTED-${match.length}chars]`;
      });
    }

    callback(null, Buffer.from(text));
  }
}

/**
 * Install log sanitization on process streams.
 * Call this BEFORE any other initialization so PM2 logs are clean.
 */
export function installLogSanitizer(): void {
  const sanitizer = new LogSanitizer();

  // Intercept stdout
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: any, ...args: any[]) => {
    const sanitized = sanitizeSync(typeof chunk === 'string' ? chunk : chunk.toString());
    return originalStdoutWrite(sanitized, ...args);
  }) as typeof process.stdout.write;

  // Intercept stderr
  const originalStderrWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: any, ...args: any[]) => {
    const sanitized = sanitizeSync(typeof chunk === 'string' ? chunk : chunk.toString());
    return originalStderrWrite(sanitized, ...args);
  }) as typeof process.stderr.write;
}

/**
 * Synchronous sanitization for individual strings.
 */
function sanitizeSync(text: string): string {
  let result = text;
  for (const pattern of SENSITIVE_PATTERNS) {
    pattern.lastIndex = 0;
    result = result.replace(pattern, (match) => {
      const prefix = match.substring(0, Math.min(8, match.length));
      return `${prefix}[REDACTED-${match.length}chars]`;
    });
  }
  return result;
}
