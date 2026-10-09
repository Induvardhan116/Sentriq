import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildApiUrl } from './api.ts';

describe('API URL Construction: buildApiUrl', () => {
  it('returns path as-is for empty local development base', () => {
    assert.equal(buildApiUrl('', '/api/projects'), '/api/projects');
    assert.equal(buildApiUrl('', '/api/scans/scan-123'), '/api/scans/scan-123');
  });

  it('ensures leading slash if missing with empty base', () => {
    assert.equal(buildApiUrl('', 'api/system/health'), '/api/system/health');
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
