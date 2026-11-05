import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApiUrl } from './api.ts';

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
