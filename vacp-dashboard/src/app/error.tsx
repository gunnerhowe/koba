'use client';

import { useEffect } from 'react';
import Link from 'next/link';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service
    console.error('Application error:', error);
  }, [error]);

  return (
    <div className="min-h-screen bg-koba-bg flex items-center justify-center px-4">
      <div className="max-w-md w-full text-center">
        {/* Error Illustration */}
        <div className="mb-8">
          <div className="w-24 h-24 mx-auto bg-koba-danger-muted rounded-2xl flex items-center justify-center">
            <svg className="w-12 h-12 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
        </div>

        {/* Message */}
        <h1 className="text-3xl font-bold text-koba-text mb-3">
          Something went wrong
        </h1>
        <p className="text-koba-text-secondary mb-6">
          An unexpected error occurred. Our governance systems detected an issue
          and kept everything safe.
        </p>

        {/* Error Details (in development) */}
        {process.env.NODE_ENV === 'development' && error?.message && (
          <div className="mb-6 p-4 bg-koba-bg-card border border-koba-border rounded-xl text-left">
            <p className="text-koba-danger font-mono text-sm break-all">
              {error.message}
            </p>
            {error.digest && (
              <p className="text-koba-text-muted text-xs mt-2">
                Error ID: {error.digest}
              </p>
            )}
          </div>
        )}

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <button
            onClick={reset}
            className="koba-btn koba-btn-primary px-6 py-3"
          >
            Try Again
          </button>
          <Link
            href="/"
            className="koba-btn koba-btn-secondary px-6 py-3"
          >
            Go to Dashboard
          </Link>
        </div>

        {/* Security Note */}
        <div className="mt-8 p-4 bg-koba-info-muted border border-koba-info/30 rounded-xl">
          <div className="flex items-center justify-center gap-2 text-koba-info text-sm">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <span>Error logged securely. Your data is protected.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
