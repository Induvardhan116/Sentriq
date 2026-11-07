import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { User, LoginPayload, RegisterPayload } from '../types/auth.ts';

// Simulated state store mimicking AuthContext without triggering full React DOM render
class AuthContextStateMock {
  user: User | null = null;
  isLoading = true; // Initial session restoration begins as loading = true
  csrfToken: string | null = null;

  async refreshUser(mockGetMe: () => Promise<User>) {
    try {
      const currentUser = await mockGetMe();
      this.user = currentUser;
      this.csrfToken = currentUser.csrf_token || null;
    } catch {
      this.user = null;
      this.csrfToken = null;
    } finally {
      this.isLoading = false;
    }
  }

  // Updated login method without global setIsLoading(true)
  async login(credentials: LoginPayload, mockLoginApi: (c: LoginPayload) => Promise<User>) {
    const response = await mockLoginApi(credentials);
    this.user = response;
    this.csrfToken = response.csrf_token || null;
  }

  // Updated register method without global setIsLoading(true)
  async register(payload: RegisterPayload, mockRegisterApi: (p: RegisterPayload) => Promise<User>) {
    const response = await mockRegisterApi(payload);
    this.user = response;
    this.csrfToken = response.csrf_token || null;
  }

  // Logout method sets isLoading=true while network request is in flight to shield protected dashboard
  async logout(mockLogoutApi: () => Promise<void>) {
    this.isLoading = true;
    try {
      await mockLogoutApi();
    } catch {
      // Ignore network errors on logout to ensure local state clears
    } finally {
      this.user = null;
      this.csrfToken = null;
      this.isLoading = false;
    }
  }
}

// Simulated LoginPage component state mimicking local form lifecycle
class LoginPageStateMock {
  authContext: AuthContextStateMock;
  email = '';
  password = '';
  loading = false;
  error: string | null = null;
  isMounted = true;
  submittedAttempts = 0;

  constructor(authContext: AuthContextStateMock) {
    this.authContext = authContext;
  }

  async handleSubmit(mockLoginApi: (c: LoginPayload) => Promise<User>) {
    if (this.loading) {
      // Button disabled / prevent double submission while loading
      return;
    }
    this.error = null;
    this.loading = true;
    this.submittedAttempts++;

    try {
      await this.authContext.login(
        { email: this.email, password: this.password },
        mockLoginApi
      );
    } catch (err: unknown) {
      // In the fixed version, because authContext.isLoading was not touched,
      // this component remains mounted and the error is preserved!
      this.error = err instanceof Error ? err.message : 'Invalid email or password.';
    } finally {
      this.loading = false;
    }
  }
}

describe('AuthContext and LoginPage State Lifecycle', () => {
  it('Initial session restoration displays loading screen and resolves', async () => {
    const auth = new AuthContextStateMock();
    assert.equal(auth.isLoading, true, 'Initial app load starts with isLoading = true');

    await auth.refreshUser(async () => {
      throw new Error('401 Unauthorized / No active session');
    });

    assert.equal(auth.isLoading, false, 'After initial check, isLoading transitions to false');
    assert.equal(auth.user, null);
  });

  it('Login failure does not toggle global isLoading, keeping LoginPage mounted', async () => {
    const auth = new AuthContextStateMock();
    auth.isLoading = false; // Post-initial restoration

    const page = new LoginPageStateMock(auth);
    page.email = 'analyst@sentriq.io';
    page.password = 'badpassword';

    assert.equal(page.isMounted, true);
    assert.equal(auth.isLoading, false);

    await page.handleSubmit(async () => {
      // During submission, verify global isLoading is still FALSE
      assert.equal(
        auth.isLoading,
        false,
        'Global isLoading must NOT become true during login (would unmount page)'
      );
      throw new Error('Authentication is temporarily unavailable. Please try again later.');
    });

    // Verification:
    // 1. Error is preserved on the page
    assert.equal(page.error, 'Authentication is temporarily unavailable. Please try again later.');
    // 2. Component is still mounted
    assert.equal(page.isMounted, true);
    // 3. Local loading reset
    assert.equal(page.loading, false);
    // 4. Global auth isLoading never changed
    assert.equal(auth.isLoading, false);
  });

  it('Local loading state prevents repeated submissions while request is in flight', async () => {
    const auth = new AuthContextStateMock();
    auth.isLoading = false;

    const page = new LoginPageStateMock(auth);
    page.loading = true; // In-flight

    await page.handleSubmit(async () => {
      throw new Error('Should not be called');
    });

    assert.equal(page.submittedAttempts, 0, 'Must ignore submit while loading is true');
  });

  it('Successful login updates authentication user state and csrf token', async () => {
    const auth = new AuthContextStateMock();
    auth.isLoading = false;

    const page = new LoginPageStateMock(auth);
    page.email = 'analyst@sentriq.io';
    page.password = 'CorrectPassword123!';

    await page.handleSubmit(async (c) => ({
      id: 'usr-999',
      email: c.email,
      full_name: 'Lead Analyst',
      is_active: true,
      is_verified: true,
      is_superuser: false,
      created_at: '2026-01-01T00:00:00Z',
      csrf_token: 'valid-csrf-token',
    }));

    assert.equal(page.error, null);
    assert.equal(page.loading, false);
    assert.ok(auth.user);
    assert.equal(auth.user?.id, 'usr-999');
    assert.equal(auth.user?.email, 'analyst@sentriq.io');
    assert.equal(auth.csrfToken, 'valid-csrf-token');
    assert.equal(auth.isLoading, false, 'isLoading remains false on successful login');
  });

  it('Logout sets isLoading=true in flight to shield dashboard, then clears user and csrfToken', async () => {
    const auth = new AuthContextStateMock();
    auth.isLoading = false;
    auth.user = {
      id: 'usr-active',
      email: 'active@sentriq.io',
      is_active: true,
      is_verified: true,
      is_superuser: false,
      created_at: '2026-01-01T00:00:00Z',
    };
    auth.csrfToken = 'active-csrf-token';

    let wasLoadingInFlight = false;
    await auth.logout(async () => {
      wasLoadingInFlight = auth.isLoading;
    });

    assert.equal(wasLoadingInFlight, true, 'Logout must shield dashboard with isLoading=true while request runs');
    assert.equal(auth.user, null, 'User state must be cleared on logout');
    assert.equal(auth.csrfToken, null, 'CSRF token state must be cleared on logout');
    assert.equal(auth.isLoading, false, 'isLoading must be reset to false after logout completes');
  });

  it('Logout failure still clears authentication state and resets loading', async () => {
    const auth = new AuthContextStateMock();
    auth.isLoading = false;
    auth.user = {
      id: 'usr-active',
      email: 'active@sentriq.io',
      is_active: true,
      is_verified: true,
      is_superuser: false,
      created_at: '2026-01-01T00:00:00Z',
    };
    auth.csrfToken = 'active-csrf-token';

    let wasLoadingInFlight = false;
    await auth.logout(async () => {
      wasLoadingInFlight = auth.isLoading;
      throw new Error('Network error during logout');
    });

    assert.equal(wasLoadingInFlight, true);
    assert.equal(auth.user, null, 'User must be cleared even if logout API call failed');
    assert.equal(auth.csrfToken, null, 'CSRF token must be cleared even if logout API call failed');
    assert.equal(auth.isLoading, false, 'isLoading must be reset to false even if logout API call failed');
  });
});
