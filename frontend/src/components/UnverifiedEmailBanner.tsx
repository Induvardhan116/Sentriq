import React, { useState, useEffect } from 'react';
import { Mail, AlertTriangle, CheckCircle2, RefreshCw } from 'lucide-react';
import { authRequestEmailVerification } from '../services/api';

interface UnverifiedEmailBannerProps {
  email: string;
}

export const UnverifiedEmailBanner: React.FC<UnverifiedEmailBannerProps> = ({ email }) => {
  const [loading, setLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState<number>(0);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => {
      setCooldown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  const handleResend = async () => {
    if (cooldown > 0 || loading) return;
    setLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await authRequestEmailVerification(email);
      setSuccessMessage(res.message || 'Verification link sent! Please check your inbox.');
      setCooldown(120);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to send verification email. Please try again.';
      setErrorMessage(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        backgroundColor: 'rgba(245, 158, 11, 0.1)',
        borderBottom: '1px solid rgba(245, 158, 11, 0.3)',
        padding: '10px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
        fontSize: '0.82rem',
        color: '#fbbf24',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <AlertTriangle size={18} style={{ flexShrink: 0, color: '#f59e0b' }} />
        <span>
          <strong>Email not verified:</strong> A verification link was sent to{' '}
          <strong style={{ color: '#fff' }}>{email}</strong>. Please verify your email to unlock all account capabilities.
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {successMessage && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--accent-emerald)', fontSize: '0.78rem' }}>
            <CheckCircle2 size={14} />
            {successMessage}
          </span>
        )}
        {errorMessage && (
          <span style={{ color: 'var(--accent-rose)', fontSize: '0.78rem' }}>
            {errorMessage}
          </span>
        )}
        <button
          onClick={handleResend}
          disabled={loading || cooldown > 0}
          className="btn-secondary"
          style={{
            padding: '4px 12px',
            fontSize: '0.78rem',
            borderColor: 'rgba(245, 158, 11, 0.4)',
            color: '#fbbf24',
            cursor: loading || cooldown > 0 ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? (
            <>
              <RefreshCw size={12} style={{ animation: 'spin 1s linear infinite' }} /> Sending...
            </>
          ) : cooldown > 0 ? (
            `Resend in ${cooldown}s`
          ) : (
            <>
              <Mail size={12} /> Resend verification link
            </>
          )}
        </button>
      </div>
    </div>
  );
};

