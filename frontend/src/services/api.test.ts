import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApiUrl, authLogin, authRegister } from './api.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('API URL Construction: buildApiUrl', () => {
  it('returns path as-is for empty local development base', () => {
    assert.equal(buildApiUrl('', '/api/projects'), '/api/projects');
    assert.equal(buildApiUrl('', '/api/scans/scan-123'), '/api/scans/scan-123');
  });

  it('ensures leading slash if missing with empty base', () => {
    assert.equal(buildApiUrl('', 'api/system/health'), '/api/system/health');
  });

  it('resolves relative paths for all authentication workflows when base is empty', () => {
    assert.equal(buildApiUrl('', '/api/auth/register'), '/api/auth/register');
    assert.equal(buildApiUrl('', '/api/auth/login'), '/api/auth/login');
    assert.equal(buildApiUrl('', '/api/auth/logout'), '/api/auth/logout');
    assert.equal(buildApiUrl('', '/api/auth/me'), '/api/auth/me');
    assert.equal(buildApiUrl('', '/api/auth/profile'), '/api/auth/profile');
    assert.equal(buildApiUrl('', '/api/auth/password-reset/request'), '/api/auth/password-reset/request');
    assert.equal(buildApiUrl('', '/api/auth/password-reset/confirm'), '/api/auth/password-reset/confirm');
    assert.equal(buildApiUrl('', '/api/auth/verify-email/request'), '/api/auth/verify-email/request');
    assert.equal(buildApiUrl('', '/api/auth/verify-email/confirm'), '/api/auth/verify-email/confirm');
    assert.equal(buildApiUrl('', '/api/auth/github'), '/api/auth/github');
    assert.equal(buildApiUrl('', '/api/auth/github/callback'), '/api/auth/github/callback');
  });

  it('correctly constructs URL when base ends in /api', () => {
    assert.equal(
      buildApiUrl('https://api.sentriq.example/api', '/api/scans/scan-abc'),
      'https://api.sentriq.example/api/scans/scan-abc'
    );
  });

  it('correctly constructs URL when base ends in /api/', () => {
    assert.equal(
      buildApiUrl('https://api.sentriq.example/api/', '/api/scans/scan-abc'),
      'https://api.sentriq.example/api/scans/scan-abc'
    );
  });

  it('correctly constructs URL when base does not include /api', () => {
    assert.equal(
      buildApiUrl('https://api.sentriq.example', '/api/scans/scan-abc'),
      'https://api.sentriq.example/api/scans/scan-abc'
    );
  });

  it('correctly constructs URL when base does not include /api but has trailing slash', () => {
    assert.equal(
      buildApiUrl('https://api.sentriq.example/', '/api/scans/scan-abc'),
      'https://api.sentriq.example/api/scans/scan-abc'
    );
  });
});

describe('Vercel Reverse Proxy Configuration: vercel.json', () => {
  it('validates vercel.json exists and configures same-origin /api rewrite to Render', () => {
    const vercelConfigPath = path.resolve(__dirname, '../../vercel.json');
    assert.ok(fs.existsSync(vercelConfigPath), 'frontend/vercel.json must exist');

    const configContent = fs.readFileSync(vercelConfigPath, 'utf-8');
    const config = JSON.parse(configContent);

    assert.ok(Array.isArray(config.rewrites), 'rewrites must be an array');
    const apiRewrite = config.rewrites.find(
      (r: { source: string; destination: string }) => r.source === '/api/:path*'
    );
    assert.ok(apiRewrite, 'Rewrite for /api/:path* must be configured');
    assert.equal(
      apiRewrite.destination,
      'https://sentriq.onrender.com/api/:path*',
      'Rewrite must proxy to the Render backend origin preserving :path*'
    );
  });

  it('validates vercel.json includes essential HTTP security headers', () => {
    const vercelConfigPath = path.resolve(__dirname, '../../vercel.json');
    const config = JSON.parse(fs.readFileSync(vercelConfigPath, 'utf-8'));

    assert.ok(Array.isArray(config.headers), 'headers must be an array');
    const globalHeaderRule = config.headers.find(
      (h: { source: string }) => h.source === '/(.*)'
    );
    assert.ok(globalHeaderRule, 'Global header rule for /(.*) must exist');

    const headerMap = Object.fromEntries(
      globalHeaderRule.headers.map((h: { key: string; value: string }) => [h.key, h.value])
    );

    assert.equal(headerMap['X-Content-Type-Options'], 'nosniff');
    assert.equal(headerMap['X-Frame-Options'], 'DENY');
    assert.equal(headerMap['Referrer-Policy'], 'strict-origin-when-cross-origin');
  });
});

describe('Authentication API: HTTP 503 and Error Handling', () => {
  it('Login with HTTP 503 displays the friendly message', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => {
        return {
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          json: async () => ({ detail: 'Authentication is currently disabled for production safety...' }),
        } as Response;
      }) as typeof fetch;

      await assert.rejects(
        async () => {
          await authLogin({ email: 'analyst@sentriq.io', password: 'Password123!' });
        },
        {
          name: 'Error',
          message: 'Authentication is temporarily unavailable. Please try again later.',
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('Registration with HTTP 503 displays the friendly message', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => {
        return {
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          json: async () => ({ detail: 'Authentication is currently disabled for production safety...' }),
        } as Response;
      }) as typeof fetch;

      await assert.rejects(
        async () => {
          await authRegister({ email: 'newuser@sentriq.io', password: 'Password123!' });
        },
        {
          name: 'Error',
          message: 'Authentication is temporarily unavailable. Please try again later.',
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('Preserves backend error details for other HTTP errors (e.g. 401 Unauthorized)', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => {
        return {
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          json: async () => ({ detail: 'Invalid email or password.' }),
        } as Response;
      }) as typeof fetch;

      await assert.rejects(
        async () => {
          await authLogin({ email: 'analyst@sentriq.io', password: 'wrongpassword' });
        },
        {
          name: 'Error',
          message: 'Invalid email or password.',
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('Preserves backend error details for validation errors (e.g. 400 Bad Request)', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => {
        return {
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          json: async () => ({ detail: 'Password must be at least 10 characters.' }),
        } as Response;
      }) as typeof fetch;

      await assert.rejects(
        async () => {
          await authRegister({ email: 'invalid@sentriq.io', password: 'short' });
        },
        {
          name: 'Error',
          message: 'Password must be at least 10 characters.',
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('Successful login returns user and CSRF token', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            id: 'user-123',
            email: 'analyst@sentriq.io',
            full_name: 'Security Analyst',
            is_active: true,
            is_verified: true,
            is_superuser: false,
            created_at: '2026-01-01T00:00:00Z',
            csrf_token: 'csrf-secret-token-xyz',
          }),
        } as Response;
      }) as typeof fetch;

      const user = await authLogin({ email: 'analyst@sentriq.io', password: 'ValidPassword123!' });
      assert.equal(user.id, 'user-123');
      assert.equal(user.email, 'analyst@sentriq.io');
      assert.equal(user.csrf_token, 'csrf-secret-token-xyz');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
