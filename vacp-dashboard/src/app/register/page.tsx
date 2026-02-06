'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth';

function getPasswordStrength(password: string): { level: string; color: string; bgColor: string; width: string } {
  if (!password) return { level: '', color: '', bgColor: '', width: '0%' };

  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const hasMixedCaseOrNumbers = (hasUpperCase && hasLowerCase) || hasNumbers;

  if (password.length >= 12 && hasUpperCase && hasLowerCase && hasNumbers && hasSpecial) {
    return { level: 'Strong', color: 'text-koba-success', bgColor: 'bg-koba-success', width: '100%' };
  }
  if (password.length >= 8 && hasMixedCaseOrNumbers) {
    return { level: 'Good', color: 'text-koba-success', bgColor: 'bg-koba-success', width: '75%' };
  }
  if (password.length >= 6) {
    return { level: 'Fair', color: 'text-koba-warning', bgColor: 'bg-koba-warning', width: '50%' };
  }
  return { level: 'Weak', color: 'text-koba-danger', bgColor: 'bg-koba-danger', width: '25%' };
}

export default function RegisterPage() {
  const router = useRouter();
  const { register } = useAuth();
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }

    setLoading(true);

    try {
      await register(email, username, password);
      router.push('/');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
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
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </Link>
          <h1 className="text-3xl font-bold text-koba-text">Koba</h1>
          <p className="text-koba-text-secondary mt-2">Create your account</p>
        </div>

        {/* Register Form */}
        <div className="koba-card">
          <h2 className="text-xl font-semibold text-koba-text mb-6">Sign up</h2>

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
                Email
              </label>
              <input
                type="email"
                id="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="koba-input"
                placeholder="you@example.com"
                required
                autoComplete="email"
              />
            </div>

            <div>
              <label htmlFor="username" className="koba-label">
                Username
              </label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="koba-input"
                placeholder="johndoe"
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
                placeholder="At least 6 characters"
                required
                autoComplete="new-password"
                minLength={6}
              />
              {password && (() => {
                const strength = getPasswordStrength(password);
                return (
                  <div className="mt-2">
                    <div className="h-1.5 bg-koba-bg-elevated rounded-full overflow-hidden">
                      <div
                        className={`h-full ${strength.bgColor} rounded-full transition-all duration-300`}
                        style={{ width: strength.width }}
                      />
                    </div>
                    <p className={`text-xs mt-1 ${strength.color}`}>{strength.level}</p>
                  </div>
                );
              })()}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="koba-label">
                Confirm Password
              </label>
              <input
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="koba-input"
                placeholder="Repeat your password"
                required
                autoComplete="new-password"
                minLength={6}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="koba-btn koba-btn-primary w-full py-3 text-base"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Creating account...
                </span>
              ) : (
                'Create account'
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-koba-text-secondary text-sm">
              Already have an account?{' '}
              <Link href="/login" className="text-koba-accent hover:text-koba-accent-hover font-medium transition-colors">
                Sign in
              </Link>
            </p>
          </div>
        </div>

        <p className="mt-6 text-center text-koba-text-muted text-xs">
          By creating an account, you agree to the Terms of Service and Privacy Policy.
        </p>
      </div>
    </div>
  );
}
