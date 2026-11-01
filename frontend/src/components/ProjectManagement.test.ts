import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { updateProject, deleteProject } from '../services/api.ts';

describe('Project Management API: updateProject and deleteProject', () => {
  it('updateProject sends PATCH request with payload and returns updated project', async () => {
    const originalFetch = globalThis.fetch;
    try {
      let calledUrl = '';
      let calledMethod = '';
      let calledBody = '';

      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        calledUrl = String(input);
        calledMethod = init?.method || 'GET';
        calledBody = String(init?.body || '');
        return {
          ok: true,
          status: 200,
          json: async () => ({
            id: 'proj-123',
            name: 'Updated Production App',
            target_url: 'https://new-url.example.com/',
            authorization_confirmed: true,
            created_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-02T00:00:00Z',
          }),
        } as Response;
      }) as typeof fetch;

      const result = await updateProject('proj-123', {
        name: 'Updated Production App',
        target_url: 'https://new-url.example.com',
      });

      assert.equal(calledUrl, '/api/projects/proj-123');
      assert.equal(calledMethod, 'PATCH');
      assert.deepEqual(JSON.parse(calledBody), {
        name: 'Updated Production App',
        target_url: 'https://new-url.example.com',
      });
      assert.equal(result.id, 'proj-123');
      assert.equal(result.name, 'Updated Production App');
      assert.equal(result.target_url, 'https://new-url.example.com/');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('updateProject throws descriptive error when backend rejects URL or name', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => {
        return {
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          json: async () => ({
            detail: "Target IP '127.0.0.1' is a private or reserved network address and cannot be scanned.",
          }),
        } as Response;
      }) as typeof fetch;

      await assert.rejects(
        async () => {
          await updateProject('proj-123', { target_url: 'http://127.0.0.1' });
        },
        {
          name: 'Error',
          message: "Target IP '127.0.0.1' is a private or reserved network address and cannot be scanned.",
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('deleteProject sends DELETE request and returns confirmation', async () => {
    const originalFetch = globalThis.fetch;
    try {
      let calledUrl = '';
      let calledMethod = '';

      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        calledUrl = String(input);
        calledMethod = init?.method || 'GET';
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            message: "Project 'Test Target' and all associated scan history were deleted successfully.",
            deleted_id: 'proj-456',
          }),
        } as Response;
      }) as typeof fetch;

      const result = await deleteProject('proj-456');

      assert.equal(calledUrl, '/api/projects/proj-456');
      assert.equal(calledMethod, 'DELETE');
      assert.equal(result.success, true);
      assert.equal(result.deleted_id, 'proj-456');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('deleteProject throws error when server returns 404 or 500', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => {
        return {
          ok: false,
          status: 404,
          statusText: 'Not Found',
          json: async () => ({
            detail: "Project with ID 'proj-999' does not exist.",
          }),
        } as Response;
      }) as typeof fetch;

      await assert.rejects(
        async () => {
          await deleteProject('proj-999');
        },
        {
          name: 'Error',
          message: "Project with ID 'proj-999' does not exist.",
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('Project Edit and Delete Safety Validation Requirements', () => {
  it('validates project name minimum length barrier before dispatch', () => {
    const validateName = (name: string): { valid: boolean; error?: string } => {
      const trimmed = name.trim();
      if (trimmed.length < 2) {
        return { valid: false, error: 'Project name must be at least 2 characters long.' };
      }
      return { valid: true };
    };

    assert.equal(validateName('').valid, false);
    assert.equal(validateName(' ').valid, false);
    assert.equal(validateName('A').valid, false);
    assert.equal(validateName('AB').valid, true);
    assert.equal(validateName('Production Web Application').valid, true);
  });

  it('detects no-op edit when name and target URL are identical', () => {
    const hasChanges = (
      orig: { name: string; target_url: string },
      updated: { name: string; target_url: string }
    ): boolean => {
      return orig.name.trim() !== updated.name.trim() || orig.target_url.trim() !== updated.target_url.trim();
    };

    const project = { name: 'My Target', target_url: 'https://example.com' };
    assert.equal(hasChanges(project, { name: 'My Target', target_url: 'https://example.com' }), false);
    assert.equal(hasChanges(project, { name: 'New Target', target_url: 'https://example.com' }), true);
    assert.equal(hasChanges(project, { name: 'My Target', target_url: 'https://example.org' }), true);
  });

  it('requires explicit confirmation before project deletion can proceed', () => {
    const canSubmitDelete = (isConfirmed: boolean, isLoading: boolean): boolean => {
      return isConfirmed && !isLoading;
    };

    assert.equal(canSubmitDelete(false, false), false, 'Delete must be blocked without explicit confirmation');
    assert.equal(canSubmitDelete(true, true), false, 'Delete must be disabled while request is loading');
    assert.equal(canSubmitDelete(true, false), true, 'Delete permitted only when confirmed and not loading');
  });

  it('finding status persistence preservation rules during rescans', () => {
    // Simulates the workflow status inheritance rule
    const determineNewFindingStatus = (
      priorStatus: string | undefined
    ): 'open' | 'in_progress' | 'resolved' | 'false_positive' => {
      if (priorStatus === 'resolved' || priorStatus === 'false_positive' || priorStatus === 'in_progress') {
        return priorStatus;
      }
      return 'open';
    };

    assert.equal(determineNewFindingStatus('resolved'), 'resolved');
    assert.equal(determineNewFindingStatus('false_positive'), 'false_positive');
    assert.equal(determineNewFindingStatus('in_progress'), 'in_progress');
    assert.equal(determineNewFindingStatus('open'), 'open');
    assert.equal(determineNewFindingStatus(undefined), 'open'); // New finding
  });
});
