'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth';

export default function LoginPage() {
  const router = useRouter();
  const { login, user, loading: authLoading } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Redirect to dashboard if already authenticated
  useEffect(() => {
    if (!authLoading && user) {
      router.push('/');
    }
  }, [user, authLoading, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(email, password, rememberMe);
      router.push('/');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-koba-bg flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        {/* Back to landing */}
        <div className="mb-6">
          <Link href="/landing" className="inline-flex items-center gap-2 text-koba-text-secondary hover:text-koba-text transition-colors text-sm group">
            <svg className="w-4 h-4 group-hover:-translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to home
          </Link>
        </div>

        {/* Logo and Title */}
        <div className="text-center mb-8">
          <Link href="/landing" className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-koba-accent via-purple-500 to-pink-500 rounded-2xl mb-4 shadow-glow transition-shadow hover:shadow-glow">
            <svg className="w-9 h-9 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </Link>
          <h1 className="text-3xl font-bold text-koba-text">Koba</h1>
          <p className="text-koba-text-secondary mt-2">AI Governance Platform</p>
        </div>

        {/* Login Form */}
        <div className="koba-card">
          <h2 className="text-xl font-semibold text-koba-text mb-6">Sign in to your account</h2>

          {error && (
            <div className="bg-koba-danger-muted border border-koba-danger/30 rounded-xl p-4 mb-6 flex items-start gap-3" role="alert" aria-live="polite">
              <svg className="w-5 h-5 text-koba-danger flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-koba-danger text-sm">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label htmlFor="email" className="koba-label">
                Email or Username
              </label>
              <input
                type="text"
                id="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="koba-input"
                placeholder="admin@koba.local"
                required
                autoComplete="username"
              />
            </div>

            <div>
              <label htmlFor="password" className="koba-label">
                Password
              </label>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="koba-input"
                placeholder="Enter your password"
                required
                autoComplete="current-password"
              />
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-4 h-4 rounded border-koba-border bg-koba-card text-koba-accent focus:ring-koba-accent focus:ring-offset-0 focus:ring-2 cursor-pointer"
                />
                <span className="text-sm text-koba-text-secondary group-hover:text-koba-text transition-colors">
                  Remember me for 30 days
                </span>
              </label>
            </div>

            <button
              type="submit"
              disabled={!email || !password || loading}
              className="koba-btn koba-btn-primary w-full py-3 text-base disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Signing in...
                </span>
              ) : (
                'Sign in'
              )}
            </button>
          </form>

          <div className="mt-4 p-3 bg-koba-accent/5 border border-koba-accent/20 rounded-xl">
            <p className="text-koba-text-secondary text-xs">
              <strong className="text-koba-text">First time?</strong>{' '}
              Use <code className="px-1.5 py-0.5 bg-koba-bg-elevated rounded text-koba-accent font-mono text-xs">admin@koba.local</code>
              {' '}/{' '}
              <code className="px-1.5 py-0.5 bg-koba-bg-elevated rounded text-koba-accent font-mono text-xs">admin123</code>
            </p>
          </div>

          <div className="mt-4 text-center">
            <p className="text-koba-text-secondary text-sm">
              Don't have an account?{' '}
              <Link href="/register" className="text-koba-accent hover:text-koba-accent-hover font-medium transition-colors">
                Create one
              </Link>
            </p>
          </div>

        </div>

        {/* Features */}
        <div className="mt-8 grid grid-cols-3 gap-4 text-center">
          <div className="p-4">
            <div className="w-10 h-10 mx-auto mb-2 bg-koba-success-muted rounded-xl flex items-center justify-center">
              <svg className="w-5 h-5 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <p className="text-koba-text-secondary text-xs">Action Receipts</p>
          </div>
          <div className="p-4">
            <div className="w-10 h-10 mx-auto mb-2 bg-koba-accent-muted rounded-xl flex items-center justify-center">
              <svg className="w-5 h-5 text-koba-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <p className="text-koba-text-secondary text-xs">Policy Enforcement</p>
          </div>
          <div className="p-4">
            <div className="w-10 h-10 mx-auto mb-2 bg-koba-warning-muted rounded-xl flex items-center justify-center">
              <svg className="w-5 h-5 text-koba-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
            </div>
            <p className="text-koba-text-secondary text-xs">Audit Trail</p>
          </div>
        </div>
      </div>
    </div>
  );
}
