import React, { useState, useEffect } from 'react';
import { Shield, Lock, Mail, AlertCircle, ArrowRight, Github } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { apiUrl } from '../services/api';

export const LoginPage: React.FC = () => {
  const { login, isAuthenticated } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Parse any OAuth error from query string
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash;
      if (hash.includes('?')) {
        const queryPart = hash.split('?')[1];
        const params = new URLSearchParams(queryPart);
        const errParam = params.get('error');
        if (errParam === 'account_link_required') {
          setError(
            'An account with this email already exists. Please sign in with your password first to link your GitHub account.'
          );
        } else if (errParam === 'invalid_oauth_state' || errParam === 'oauth_state_already_used') {
          setError('GitHub authentication session expired or invalid. Please try again.');
        } else if (errParam === 'oauth_state_expired') {
          setError('GitHub authentication timed out. Please try again.');
        } else if (errParam === 'access_denied') {
          setError('GitHub sign-in was cancelled.');
        } else if (errParam === 'oauth_no_verified_email') {
          setError('Your GitHub account does not have a verified primary email. Please verify your email on GitHub and try again.');
        } else if (errParam === 'oauth_account_conflict') {
          setError('This GitHub account is already associated with another Sentriq profile.');
        } else if (errParam === 'oauth_token_exchange_failed' || errParam === 'oauth_communication_error') {
          setError('Failed to communicate with GitHub. Please try again later.');
        } else if (errParam === 'account_deactivated') {
          setError('Your Sentriq account has been deactivated. Please contact support.');
        } else if (errParam) {
          setError(`Authentication error: ${errParam.replace(/_/g, ' ')}`);
        }
      }
    }
  }, []);

  // If already authenticated, redirect to overview
  useEffect(() => {
    if (isAuthenticated) {
      window.location.hash = '#/overview';
    }
  }, [isAuthenticated]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login({ email: email.trim(), password });
      window.location.hash = '#/overview';
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid email or password.');
    } finally {
      setLoading(false);
    }
  };

  const handleGitHubOAuth = () => {
    window.location.href = apiUrl('/api/auth/github');
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'var(--bg-canvas)',
        padding: '20px',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '440px',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '16px',
          padding: '36px 32px',
          boxShadow: '0 20px 40px -15px rgba(0, 0, 0, 0.7)',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              backgroundColor: 'var(--accent-cyan-subtle)',
              color: 'var(--accent-cyan)',
              marginBottom: '14px',
            }}
          >
            <Shield size={26} />
          </div>
          <h1 style={{ fontSize: '1.45rem', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '6px' }}>
            Sign In to Sentriq
          </h1>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Application Security Intelligence Platform
          </p>
        </div>

        {error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              padding: '12px 14px',
              backgroundColor: 'var(--accent-rose-subtle)',
              border: '1px solid var(--accent-rose)',
              borderRadius: '8px',
              color: '#fda4af',
              fontSize: '0.8rem',
              marginBottom: '20px',
              lineHeight: 1.4,
            }}
          >
            <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '18px' }}>
            <label
              htmlFor="login-email"
              style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}
            >
              Email Address
            </label>
            <div style={{ position: 'relative' }}>
              <Mail
                size={16}
                style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
              />
              <input
                id="login-email"
                type="email"
                required
                autoComplete="email"
                placeholder="analyst@sentriq.io"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px 14px 10px 38px',
                  backgroundColor: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  outline: 'none',
                }}
              />
            </div>
          </div>

          <div style={{ marginBottom: '22px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label
                htmlFor="login-password"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                Password
              </label>
              <a
                href="#/forgot-password"
                style={{ fontSize: '0.74rem', color: 'var(--accent-cyan)', textDecoration: 'none', fontWeight: 500 }}
              >
                Forgot password?
              </a>
            </div>
            <div style={{ position: 'relative' }}>
              <Lock
                size={16}
                style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
              />
              <input
                id="login-password"
                type="password"
                required
                autoComplete="current-password"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px 14px 10px 38px',
                  backgroundColor: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  outline: 'none',
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary"
            style={{
              width: '100%',
              padding: '11px',
              fontSize: '0.88rem',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            margin: '22px 0',
            color: 'var(--text-muted)',
            fontSize: '0.75rem',
          }}
        >
          <div style={{ flex: 1, height: '1px', backgroundColor: 'var(--border-subtle)' }} />
          <span style={{ padding: '0 10px' }}>OR</span>
          <div style={{ flex: 1, height: '1px', backgroundColor: 'var(--border-subtle)' }} />
        </div>

        <button
          onClick={handleGitHubOAuth}
          type="button"
          className="btn-secondary"
          style={{
            width: '100%',
            padding: '10px',
            fontSize: '0.84rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            backgroundColor: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid var(--border-muted)',
          }}
        >
          <Github size={16} />
          Continue with GitHub
        </button>

        <div style={{ marginTop: '24px', textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          Don't have an account?{' '}
          <a
            href="#/register"
            style={{ color: 'var(--accent-cyan)', fontWeight: 600, textDecoration: 'none' }}
          >
            Sign up
          </a>
        </div>
      </div>
    </div>
  );
};
