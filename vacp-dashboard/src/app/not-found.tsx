import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-koba-bg flex items-center justify-center px-4">
      <div className="max-w-md w-full text-center">
        {/* 404 Illustration */}
        <div className="mb-8">
          <div className="relative inline-block">
            <div className="w-32 h-32 mx-auto bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-full flex items-center justify-center">
              <div className="w-24 h-24 bg-gradient-to-br from-blue-500/30 to-purple-500/30 rounded-full flex items-center justify-center">
                <svg className="w-12 h-12 text-koba-text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
            {/* Floating elements */}
            <div className="absolute -top-2 -left-2 w-4 h-4 bg-blue-500/50 rounded-full animate-pulse" />
            <div className="absolute -bottom-1 -right-3 w-3 h-3 bg-purple-500/50 rounded-full animate-pulse delay-150" />
            <div className="absolute top-1/2 -right-6 w-2 h-2 bg-pink-500/50 rounded-full animate-pulse delay-300" />
          </div>
        </div>

        {/* Error Code */}
        <h1 className="text-8xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-400 mb-4">
          404
        </h1>

        {/* Message */}
        <h2 className="text-2xl font-semibold text-koba-text mb-3">
          Page Not Found
        </h2>
        <p className="text-koba-text-secondary mb-8">
          The page you're looking for doesn't exist or has been moved.
          Don't worry, even the best AI agents take wrong turns sometimes.
        </p>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            href="/"
            className="px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-500 text-white font-medium rounded-lg hover:from-blue-600 hover:to-purple-600 transition-all shadow-lg shadow-blue-500/25"
          >
            Go to Dashboard
          </Link>
          <Link
            href="/login"
            className="px-6 py-3 bg-koba-accent text-white font-medium rounded-lg hover:bg-koba-accent/90 transition-colors"
          >
            Sign In
          </Link>
          <Link
            href="/landing"
            className="px-6 py-3 bg-koba-bg-card text-koba-text font-medium rounded-lg hover:bg-koba-bg-card/80 transition-colors border border-koba-border"
          >
            View Landing Page
          </Link>
        </div>

        {/* Help Links */}
        <div className="mt-12 pt-8 border-t border-koba-border">
          <p className="text-koba-text-secondary text-sm mb-4">Looking for something specific?</p>
          <div className="flex flex-wrap justify-center gap-4 text-sm">
            <Link href="/developers" className="text-koba-accent hover:text-koba-accent/80 transition-colors">
              Documentation
            </Link>
            <span className="text-koba-border">|</span>
            <Link href="/demo" className="text-koba-accent hover:text-koba-accent/80 transition-colors">
              Live Demo
            </Link>
            <span className="text-koba-border">|</span>
            <Link href="/setup" className="text-koba-accent hover:text-koba-accent/80 transition-colors">
              Setup Wizard
            </Link>
            <span className="text-koba-border">|</span>
            <Link href="/pitch" className="text-koba-accent hover:text-koba-accent/80 transition-colors">
              Pitch Deck
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
