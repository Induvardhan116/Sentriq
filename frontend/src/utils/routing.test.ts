import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseRoute, routeToHash } from './routing.ts';

describe('Routing Helper: parseRoute', () => {
  it('parses empty or root hash as overview', () => {
    assert.deepEqual(parseRoute(''), { view: 'overview' });
    assert.deepEqual(parseRoute('#'), { view: 'overview' });
    assert.deepEqual(parseRoute('#/'), { view: 'overview' });
    assert.deepEqual(parseRoute('#/overview'), { view: 'overview' });
    assert.deepEqual(parseRoute('#/dashboard'), { view: 'overview' });
  });

  it('parses projects list route', () => {
    assert.deepEqual(parseRoute('#/projects'), { view: 'projects' });
    assert.deepEqual(parseRoute('#/projects/'), { view: 'projects' });
  });

  it('parses findings hub route with and without finding parameter', () => {
    assert.deepEqual(parseRoute('#/findings'), {
      view: 'findings',
      findingId: undefined,
    });
    assert.deepEqual(parseRoute('#/findings/'), {
      view: 'findings',
      findingId: undefined,
    });
    assert.deepEqual(parseRoute('#/findings/find-abc-123'), {
      view: 'findings',
      findingId: 'find-abc-123',
    });
    assert.deepEqual(parseRoute('#/findings?finding=find-xyz-789'), {
      view: 'findings',
      findingId: 'find-xyz-789',
    });
  });

  it('parses analytics and risk routes', () => {
    assert.deepEqual(parseRoute('#/analytics'), { view: 'analytics' });
    assert.deepEqual(parseRoute('#/analytics/'), { view: 'analytics' });
    assert.deepEqual(parseRoute('#/risk'), { view: 'analytics' });
    assert.deepEqual(parseRoute('#/risk/'), { view: 'analytics' });
  });

  it('parses valid scan routes with and without query params', () => {
    assert.deepEqual(parseRoute('#/scan/scan-123'), {
      view: 'scan',
      scanId: 'scan-123',
      findingId: undefined,
    });
    assert.deepEqual(parseRoute('#/scans/scan-abc-456'), {
      view: 'scan',
      scanId: 'scan-abc-456',
      findingId: undefined,
    });
    assert.deepEqual(parseRoute('#/scan/scan-123?finding=find-999'), {
      view: 'scan',
      scanId: 'scan-123',
      findingId: 'find-999',
    });
  });

  it('detects missing scan ID without falling back to overview', () => {
    const missing1 = parseRoute('#/scan');
    assert.equal(missing1.view, 'error');
    if (missing1.view === 'error') {
      assert.equal(missing1.message, 'Missing Scan ID');
    }

    const missing2 = parseRoute('#/scan/');
    assert.equal(missing2.view, 'error');
    if (missing2.view === 'error') {
      assert.equal(missing2.message, 'Missing Scan ID');
    }

    const missing3 = parseRoute('#/scans');
    assert.equal(missing3.view, 'error');
    if (missing3.view === 'error') {
      assert.equal(missing3.message, 'Missing Scan ID');
    }
  });

  it('parses valid project detail routes', () => {
    assert.deepEqual(parseRoute('#/project/proj-123'), {
      view: 'project',
      projectId: 'proj-123',
    });
    assert.deepEqual(parseRoute('#/projects/proj-456'), {
      view: 'project',
      projectId: 'proj-456',
    });
  });

  it('detects missing project ID without falling back to overview', () => {
    const missingProj1 = parseRoute('#/project');
    assert.equal(missingProj1.view, 'error');
    if (missingProj1.view === 'error') {
      assert.equal(missingProj1.message, 'Missing Project ID');
    }

    const missingProj2 = parseRoute('#/project/');
    assert.equal(missingProj2.view, 'error');
    if (missingProj2.view === 'error') {
      assert.equal(missingProj2.message, 'Missing Project ID');
    }
  });

  it('falls back to pathname when hash is empty', () => {
    assert.deepEqual(parseRoute('', '/projects'), { view: 'projects' });
    assert.deepEqual(parseRoute('', '/scan/abc-123'), {
      view: 'scan',
      scanId: 'abc-123',
      findingId: undefined,
    });
  });

  it('parses authentication routes (login and register)', () => {
    assert.deepEqual(parseRoute('#/login'), { view: 'login' });
    assert.deepEqual(parseRoute('#/login/'), { view: 'login' });
    assert.deepEqual(parseRoute('#/register'), { view: 'register' });
    assert.deepEqual(parseRoute('#/signup'), { view: 'register' });
  });

  it('parses password recovery and verification routes with and without tokens', () => {
    assert.deepEqual(parseRoute('#/forgot-password'), { view: 'forgot-password' });
    assert.deepEqual(parseRoute('#/forgot'), { view: 'forgot-password' });

    assert.deepEqual(parseRoute('#/reset-password'), {
      view: 'reset-password',
      token: undefined,
    });
    assert.deepEqual(parseRoute('#/reset-password?token=abc123xyz'), {
      view: 'reset-password',
      token: 'abc123xyz',
    });
    assert.deepEqual(parseRoute('#/reset?token=abc123xyz'), {
      view: 'reset-password',
      token: 'abc123xyz',
    });

    assert.deepEqual(parseRoute('#/verify-email'), {
      view: 'verify-email',
      token: undefined,
    });
    assert.deepEqual(parseRoute('#/verify-email?token=ver-456-tok'), {
      view: 'verify-email',
      token: 'ver-456-tok',
    });
    assert.deepEqual(parseRoute('#/verify?token=ver-456-tok'), {
      view: 'verify-email',
      token: 'ver-456-tok',
    });
  });
});

describe('Routing Helper: routeToHash', () => {
  it('formats overview', () => {
    assert.equal(routeToHash({ view: 'overview' }), '#/overview');
  });

  it('formats projects', () => {
    assert.equal(routeToHash({ view: 'projects' }), '#/projects');
  });

  it('formats findings hub route with and without finding parameter', () => {
    assert.equal(routeToHash({ view: 'findings' }), '#/findings');
    assert.equal(
      routeToHash({ view: 'findings', findingId: 'find-123' }),
      '#/findings?finding=find-123'
    );
  });

  it('formats analytics route', () => {
    assert.equal(routeToHash({ view: 'analytics' }), '#/analytics');
  });

  it('formats project detail', () => {
    assert.equal(routeToHash({ view: 'project', projectId: 'p-1' }), '#/project/p-1');
  });

  it('formats scan detail', () => {
    assert.equal(routeToHash({ view: 'scan', scanId: 's-1' }), '#/scan/s-1');
    assert.equal(
      routeToHash({ view: 'scan', scanId: 's-1', findingId: 'f-1' }),
      '#/scan/s-1?finding=f-1'
    );
  });

  it('formats auth views', () => {
    assert.equal(routeToHash({ view: 'login' }), '#/login');
    assert.equal(routeToHash({ view: 'register' }), '#/register');
    assert.equal(routeToHash({ view: 'forgot-password' }), '#/forgot-password');
    assert.equal(routeToHash({ view: 'reset-password' }), '#/reset-password');
    assert.equal(
      routeToHash({ view: 'reset-password', token: 'tok-123' }),
      '#/reset-password?token=tok-123'
    );
    assert.equal(routeToHash({ view: 'verify-email' }), '#/verify-email');
    assert.equal(
      routeToHash({ view: 'verify-email', token: 'ver-tok-456' }),
      '#/verify-email?token=ver-tok-456'
    );
  });
});
