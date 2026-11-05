import React, { useState, useEffect, useRef } from 'react';
import { Shield, CheckCircle2, AlertCircle, ArrowRight, RefreshCw } from 'lucide-react';
import { authConfirmEmailVerification, authRequestEmailVerification } from '../services/api';
import { useAuth } from '../context/AuthContext';

interface VerifyEmailPageProps {
  token?: string;
}

export const VerifyEmailPage: React.FC<VerifyEmailPageProps> = ({ token }) => {
  const { user, refreshUser } = useAuth();
  const [verifying, setVerifying] = useState<boolean>(Boolean(token));
  const [success, setSuccess] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [resending, setResending] = useState<boolean>(false);
  const [resendStatus, setResendStatus] = useState<string | null>(null);
  const attemptedRef = useRef<boolean>(false);

  useEffect(() => {
    if (token && !attemptedRef.current) {
      attemptedRef.current = true;
      setVerifying(true);
      setError(null);
      authConfirmEmailVerification(token)
        .then(() => {
          setSuccess(true);
          setVerifying(false);
          refreshUser().catch(() => {});
        })
        .catch((err: unknown) => {
          setError(err instanceof Error ? err.message : 'Failed to verify email address.');
          setVerifying(false);
        });
    }
  }, [token, refreshUser]);

  const handleResend = async () => {
    setResending(true);
    setResendStatus(null);
    setError(null);
    try {
      const res = await authRequestEmailVerification(user?.email);
      setResendStatus(res.message);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to request verification email.');
    } finally {
      setResending(false);
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
          textAlign: 'center',
        }}
      >
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
            marginBottom: '16px',
          }}
        >
          <Shield size={26} />
        </div>

        <h1 style={{ fontSize: '1.45rem', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '8px' }}>
          Email Verification
        </h1>

        {verifying ? (
          <div style={{ padding: '24px 0' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                border: '3px solid var(--border-subtle)',
                borderTopColor: 'var(--accent-cyan)',
                borderRadius: '50%',
                margin: '0 auto 16px',
                animation: 'spin 0.8s linear infinite',
              }}
            />
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
              Verifying your security credentials...
            </p>
          </div>
        ) : success ? (
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '14px',
                backgroundColor: 'var(--accent-emerald-subtle)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                borderRadius: '8px',
                color: '#6ee7b7',
                fontSize: '0.84rem',
                margin: '18px 0 24px',
                textAlign: 'left',
              }}
            >
              <CheckCircle2 size={18} style={{ flexShrink: 0, color: 'var(--accent-emerald)' }} />
              <span>Your email address has been verified successfully. Your account is fully active.</span>
            </div>
            <a
              href="#/overview"
              className="btn-primary"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                textDecoration: 'none',
                padding: '10px 22px',
              }}
            >
              Go to Dashboard <ArrowRight size={16} />
            </a>
          </div>
        ) : (
          <div>
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
                  margin: '16px 0 20px',
                  textAlign: 'left',
                  lineHeight: 1.4,
                }}
              >
                <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
                <span>{error}</span>
              </div>
            )}

            {resendStatus && (
              <div
                style={{
                  padding: '12px 14px',
                  backgroundColor: 'var(--accent-cyan-subtle)',
                  border: '1px solid rgba(6, 182, 212, 0.4)',
                  borderRadius: '8px',
                  color: 'var(--accent-cyan)',
                  fontSize: '0.8rem',
                  margin: '16px 0 20px',
                  textAlign: 'left',
                }}
              >
                {resendStatus}
              </div>
            )}

            <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', marginBottom: '20px', lineHeight: 1.5 }}>
              {!token
                ? 'Please check your email for the verification link that was sent to your account.'
                : 'The verification link may have expired or was already used.'}
            </p>

            <button
              onClick={handleResend}
              disabled={resending}
              className="btn-secondary"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 18px',
                fontSize: '0.84rem',
                marginRight: '10px',
              }}
            >
              <RefreshCw size={14} className={resending ? 'spin' : ''} />
              {resending ? 'Sending...' : 'Resend Verification Link'}
            </button>

            <a
              href="#/overview"
              className="btn-primary"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                textDecoration: 'none',
                padding: '10px 18px',
                fontSize: '0.84rem',
              }}
            >
              Dashboard
            </a>
          </div>
        )}
      </div>
    </div>
  );
};
