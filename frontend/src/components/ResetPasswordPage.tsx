import React, { useState } from 'react';
import { Shield, Lock, ArrowRight, CheckCircle2, AlertCircle, Check, X } from 'lucide-react';
import { authConfirmPasswordReset } from '../services/api';

interface ResetPasswordPageProps {
  token?: string;
}

export const ResetPasswordPage: React.FC<ResetPasswordPageProps> = ({ token }) => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Real-time password rules
  const hasLength = password.length >= 10;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasSpecial = /[0-9\W_]/.test(password);
  const isMatch = password === confirmPassword && password.length > 0;
  const isValid = hasLength && hasUpper && hasLower && hasSpecial && isMatch;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      setError('Password reset token is missing from the URL.');
      return;
    }
    if (!isValid) {
      setError('Please fulfill all password requirements before proceeding.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      await authConfirmPasswordReset(token, password);
      setSuccess(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset password.');
    } finally {
      setLoading(false);
    }
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
          maxWidth: '460px',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '16px',
          padding: '36px 32px',
          boxShadow: '0 20px 40px -15px rgba(0, 0, 0, 0.7)',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
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
            Set New Password
          </h1>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Choose a strong, unique password for your account.
          </p>
        </div>

        {!token ? (
          <div style={{ textAlign: 'center' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '10px',
                padding: '14px',
                backgroundColor: 'var(--accent-rose-subtle)',
                border: '1px solid var(--accent-rose)',
                borderRadius: '8px',
                color: '#fda4af',
                fontSize: '0.82rem',
                marginBottom: '20px',
                textAlign: 'left',
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
              <span>Missing recovery token. Please request a new recovery link.</span>
            </div>
            <a href="#/forgot-password" className="btn-primary" style={{ textDecoration: 'none' }}>
              Request New Link
            </a>
          </div>
        ) : success ? (
          <div style={{ textAlign: 'center' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '10px',
                padding: '14px',
                backgroundColor: 'var(--accent-emerald-subtle)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                borderRadius: '8px',
                color: '#6ee7b7',
                fontSize: '0.84rem',
                marginBottom: '24px',
                textAlign: 'left',
              }}
            >
              <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: '2px', color: 'var(--accent-emerald)' }} />
              <span>Your password has been reset successfully. All previous sessions have been securely terminated.</span>
            </div>
            <a
              href="#/login"
              className="btn-primary"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                textDecoration: 'none',
                padding: '10px 20px',
              }}
            >
              Sign In with New Password <ArrowRight size={16} />
            </a>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
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
                  marginBottom: '18px',
                  lineHeight: 1.4,
                }}
              >
                <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
                <span>{error}</span>
              </div>
            )}

            <div style={{ marginBottom: '16px' }}>
              <label
                htmlFor="new-password"
                style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}
              >
                New Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock
                  size={16}
                  style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
                />
                <input
                  id="new-password"
                  type="password"
                  required
                  autoComplete="new-password"
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

            <div style={{ marginBottom: '18px' }}>
              <label
                htmlFor="confirm-password"
                style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}
              >
                Confirm New Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock
                  size={16}
                  style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
                />
                <input
                  id="confirm-password"
                  type="password"
                  required
                  autoComplete="new-password"
                  placeholder="••••••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
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

            {/* Validation Checklist */}
            <div
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '12px 14px',
                marginBottom: '20px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
              }}
            >
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                Password Security Checklist
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: hasLength ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                {hasLength ? <Check size={14} /> : <X size={14} />} At least 10 characters
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: hasUpper ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                {hasUpper ? <Check size={14} /> : <X size={14} />} At least one uppercase letter
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: hasLower ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                {hasLower ? <Check size={14} /> : <X size={14} />} At least one lowercase letter
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: hasSpecial ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                {hasSpecial ? <Check size={14} /> : <X size={14} />} At least one number or symbol
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.76rem', color: isMatch ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                {isMatch ? <Check size={14} /> : <X size={14} />} Passwords match
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !isValid}
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
                cursor: loading || !isValid ? 'not-allowed' : 'pointer',
                opacity: loading || !isValid ? 0.6 : 1,
              }}
            >
              {loading ? 'Updating Password...' : 'Reset Password'}
              {!loading && <ArrowRight size={16} />}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

