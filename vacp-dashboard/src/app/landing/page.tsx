'use client';

import Link from 'next/link';
import { useState, useEffect } from 'react';

export default function LandingPage() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <div className="min-h-screen bg-koba-bg">
      {/* Navigation */}
      <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${scrolled ? 'bg-koba-bg/95 backdrop-blur-md border-b border-koba-border' : ''}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16 sm:h-20">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-koba-accent via-purple-500 to-pink-500 flex items-center justify-center">
                <svg className="w-6 h-6 text-koba-text" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <span className="text-xl font-bold text-koba-text">Koba</span>
            </div>
            <div className="hidden md:flex items-center gap-8">
              <a href="#features" className="text-koba-text-secondary hover:text-koba-text transition-colors">Features</a>
              <a href="#how-it-works" className="text-koba-text-secondary hover:text-koba-text transition-colors">How It Works</a>
              <a href="#security" className="text-koba-text-secondary hover:text-koba-text transition-colors">Security</a>
              <Link href="/developers" className="text-koba-text-secondary hover:text-koba-text transition-colors">Developers</Link>
            </div>
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden text-koba-text-secondary hover:text-koba-text"
              aria-label="Toggle menu"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={mobileMenuOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16M4 18h16"} />
              </svg>
            </button>
            <div className="hidden md:flex items-center gap-3">
              <Link
                href="/login"
                className="text-koba-text-secondary hover:text-koba-text px-4 py-2 transition-colors"
              >
                Sign In
              </Link>
              <Link
                href="/register"
                className="bg-gradient-to-r from-koba-accent to-koba-accent-hover text-koba-text px-5 py-2.5 rounded-lg font-medium hover:from-koba-accent-hover hover:to-purple-600 transition-all shadow-lg shadow-koba-accent/25"
              >
                Get Started
              </Link>
            </div>
          </div>
        </div>
        {mobileMenuOpen && (
          <div className="md:hidden absolute top-full left-0 right-0 bg-koba-bg-secondary border-b border-koba-border p-4 space-y-3">
            <a href="#features" onClick={() => setMobileMenuOpen(false)} className="block text-koba-text-secondary hover:text-koba-text">Features</a>
            <a href="#how-it-works" onClick={() => setMobileMenuOpen(false)} className="block text-koba-text-secondary hover:text-koba-text">How It Works</a>
            <a href="/login" onClick={() => setMobileMenuOpen(false)} className="block text-koba-text-secondary hover:text-koba-text">Login</a>
            <a href="/register" onClick={() => setMobileMenuOpen(false)} className="block px-4 py-2 bg-koba-accent text-koba-text rounded-lg text-center">Get Started</a>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 sm:pt-40 sm:pb-32 overflow-hidden">
        {/* Background Effects */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-1/4 -left-1/4 w-96 h-96 bg-koba-accent/20 rounded-full blur-3xl" />
          <div className="absolute top-1/3 -right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 left-1/3 w-64 h-64 bg-pink-500/10 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-4xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-koba-accent-muted border border-koba-accent/30 rounded-full text-koba-accent text-sm font-medium mb-8">
              <span className="w-2 h-2 bg-koba-accent rounded-full animate-pulse" />
              Enterprise AI Governance Platform
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-7xl font-bold text-koba-text leading-tight mb-6">
              Your AI, your rules,
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-koba-accent via-purple-400 to-pink-400">
                your peace of mind.
              </span>
            </h1>

            <p className="text-xl sm:text-2xl text-koba-text-secondary max-w-3xl mx-auto mb-10">
              Governance that works for you, not against your AI. Every action verified,
              every decision auditable, every record yours to keep.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/register"
                className="w-full sm:w-auto bg-gradient-to-r from-koba-accent to-koba-accent-hover text-koba-text px-8 py-4 rounded-xl font-semibold text-lg hover:from-koba-accent-hover hover:to-purple-600 transition-all shadow-xl shadow-koba-accent/30 flex items-center justify-center gap-2"
              >
                Start Free Trial
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                </svg>
              </Link>
              <Link
                href="/demo"
                className="w-full sm:w-auto bg-koba-bg-elevated text-koba-text px-8 py-4 rounded-xl font-semibold text-lg hover:bg-koba-bg-elevated/80 transition-all border border-koba-border-light flex items-center justify-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Watch Demo
              </Link>
            </div>

            {/* Trust indicators */}
            <div className="mt-16 flex flex-wrap items-center justify-center gap-x-12 gap-y-6 text-koba-text-secondary">
              <div className="flex items-center gap-2">
                <svg className="w-5 h-5 text-koba-success" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span>SOC 2 In Progress</span>
              </div>
              <div className="flex items-center gap-2">
                <svg className="w-5 h-5 text-koba-success" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span>Blockchain Anchored</span>
              </div>
              <div className="flex items-center gap-2">
                <svg className="w-5 h-5 text-koba-success" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span>Open Source</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Value Proposition Section */}
      <section className="py-20 border-t border-koba-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 lg:gap-20 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold text-koba-text mb-6">
                You're building with AI.
                <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-koba-accent to-koba-accent-hover">You deserve to know what it's doing.</span>
              </h2>
              <p className="text-lg text-koba-text-secondary mb-8">
                Your AI agents are powerful tools — and like any powerful tool, you should have
                full visibility into how they operate. Koba gives you ownership over your AI's
                actions, so you can deploy with confidence.
              </p>
              <ul className="space-y-4">
                {[
                  'Cryptographic proof of every action, for your records',
                  'Your policies, enforced automatically across all agents',
                  'Complete audit history, tamper-proof and always available',
                  'Instant oversight when you need it most',
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-3 text-koba-text-secondary">
                    <svg className="w-5 h-5 text-koba-accent mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-br from-koba-accent/10 to-koba-accent-hover/10 rounded-3xl blur-xl" />
              <div className="relative bg-koba-bg-secondary border border-koba-border rounded-2xl p-8">
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500" />
                  <div className="w-3 h-3 rounded-full bg-koba-success" />
                </div>
                <pre className="text-sm text-koba-text-secondary font-mono overflow-x-auto">
{`// AI Agent with Koba
async function executeTask(task) {
  // Your policies, enforced automatically
  // Signed receipt for your records
  // Full audit trail you own
  // Oversight when you need it

  await koba.execute(task); // ✅

  // You know exactly what happened.
  // You have the proof.
}`}
                </pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-koba-bg-secondary/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-koba-text mb-4">
              Your governance toolkit
            </h2>
            <p className="text-lg text-koba-text-secondary">
              Everything you need to deploy AI agents with confidence
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8">
            {[
              {
                icon: (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                ),
                title: 'Cryptographic Verification',
                description: 'Ed25519 signed receipts for every action — proof that belongs to you. Know exactly what happened, when, and why.',
                color: 'blue',
              },
              {
                icon: (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                ),
                title: 'Tamper-Proof History',
                description: 'Your complete audit trail, protected by Merkle tree transparency logs. Your history, cryptographically yours.',
                color: 'purple',
              },
              {
                icon: (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                ),
                title: 'Capability Tokens',
                description: 'Your permissions, your way. Time-limited, cryptographically bound tokens give each agent exactly the access you choose.',
                color: 'pink',
              },
              {
                icon: (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                ),
                title: 'Policy Engine',
                description: 'Your rules, enforced automatically. Declarative policies let you define exactly what each agent can do.',
                color: 'yellow',
              },
              {
                icon: (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                ),
                title: 'Blockchain Anchoring',
                description: 'Hedera Consensus Service integration for immutable, timestamped proof of all agent actions.',
                color: 'green',
              },
              {
                icon: (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                ),
                title: 'AI Safeguarding',
                description: 'Emergency oversight controls, behavior monitoring, and commit-reveal schemes to keep you in charge.',
                color: 'blue',
              },
            ].map((feature, i) => {
              const colorClasses = {
                blue: 'from-koba-accent to-koba-accent-hover',
                purple: 'from-koba-accent-hover to-koba-accent-light',
                pink: 'from-koba-danger to-rose-400',
                yellow: 'from-koba-warning to-amber-400',
                green: 'from-koba-success to-emerald-400',
                red: 'from-koba-danger to-red-400',
              }[feature.color];

              return (
                <div key={i} className="bg-koba-bg-elevated/50 border border-koba-border-light rounded-2xl p-6 lg:p-8 hover:border-koba-border transition-colors">
                  <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${colorClasses} flex items-center justify-center mb-5`}>
                    <svg className="w-6 h-6 text-koba-text" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      {feature.icon}
                    </svg>
                  </div>
                  <h3 className="text-xl font-semibold text-koba-text mb-3">{feature.title}</h3>
                  <p className="text-koba-text-secondary">{feature.description}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-20 border-t border-koba-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-koba-text mb-4">
              Deploy in minutes, not months
            </h2>
            <p className="text-lg text-koba-text-secondary">
              Three simple steps to take ownership of your AI governance
            </p>
          </div>

          <div className="grid lg:grid-cols-3 gap-8">
            {[
              {
                step: '01',
                title: 'Integrate SDK',
                description: 'One line of code wraps your agent. All tool calls automatically route through Koba.',
                code: `from koba import Koba

koba = Koba(agent_id="my-agent")

# That's it! All tools now verified.
@koba.tool
def send_email(to, subject, body):
    ...`,
              },
              {
                step: '02',
                title: 'Define Policies',
                description: 'Declarative YAML policies define what each agent can do. Your boundaries, enforced by default.',
                code: `# policy.yaml
rules:
  - match: "*.read"
    action: allow

  - match: "email.send"
    action: require_approval

  - match: "*.delete"
    action: deny`,
              },
              {
                step: '03',
                title: 'Visibility & Oversight',
                description: 'Real-time dashboard shows all agent actions. Approve requests, review patterns, and stay in charge.',
                code: `# Real-time visibility
{
  "agent": "sales-bot",
  "action": "email.send",
  "status": "pending_approval",
  "receipt": "koba:1:a3f2...",
  "merkle_proof": "verified"
}`,
              },
            ].map((item, i) => (
              <div key={i} className="relative">
                <div className="absolute -top-4 -left-4 w-16 h-16 rounded-full bg-gradient-to-br from-koba-accent to-koba-accent-hover flex items-center justify-center text-2xl font-bold text-koba-text">
                  {item.step}
                </div>
                <div className="bg-koba-bg-elevated/50 border border-koba-border-light rounded-2xl pt-16 pb-8 px-8">
                  <h3 className="text-xl font-semibold text-koba-text mb-3">{item.title}</h3>
                  <p className="text-koba-text-secondary mb-6">{item.description}</p>
                  <div className="bg-koba-bg-secondary rounded-xl p-4 overflow-x-auto">
                    <pre className="text-sm text-koba-text-secondary font-mono">{item.code}</pre>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Section */}
      <section id="security" className="py-20 bg-koba-bg-secondary/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 lg:gap-20 items-center">
            <div className="order-2 lg:order-1">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-br from-koba-accent/10 to-koba-accent-hover/10 rounded-3xl blur-xl" />
                <div className="relative bg-koba-bg-secondary border border-koba-border rounded-2xl p-8">
                  <div className="space-y-6">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-koba-success-muted flex items-center justify-center">
                        <svg className="w-6 h-6 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <div>
                        <p className="text-koba-text font-medium">Action Verified</p>
                        <p className="text-koba-text-secondary text-sm">Ed25519 signature valid</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-koba-success-muted flex items-center justify-center">
                        <svg className="w-6 h-6 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <div>
                        <p className="text-koba-text font-medium">Policy Evaluated</p>
                        <p className="text-koba-text-secondary text-sm">Action: allow (rule: *.read)</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-koba-success-muted flex items-center justify-center">
                        <svg className="w-6 h-6 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <div>
                        <p className="text-koba-text font-medium">Audit Logged</p>
                        <p className="text-koba-text-secondary text-sm">Merkle root: a3f2c8...</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-koba-accent/20 flex items-center justify-center">
                        <svg className="w-6 h-6 text-koba-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                        </svg>
                      </div>
                      <div>
                        <p className="text-koba-text font-medium">Blockchain Anchored</p>
                        <p className="text-koba-text-secondary text-sm">Hedera tx: 0.0.12345@1234567890</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="order-1 lg:order-2">
              <h2 className="text-3xl sm:text-4xl font-bold text-koba-text mb-6">
                Security that's
                <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-koba-accent to-koba-accent-hover">mathematically guaranteed</span>
              </h2>
              <p className="text-lg text-koba-text-secondary mb-8">
                Unlike traditional access control, Koba uses cryptographic proofs to guarantee security.
                Even a compromised system can't forge action receipts or tamper with the audit log.
              </p>
              <ul className="space-y-4">
                {[
                  'Ed25519 signatures for every action',
                  'Merkle trees prevent history tampering',
                  'Capability tokens with cryptographic binding',
                  'Blockchain anchoring for immutable proof',
                  'Privacy-preserving audit with minimal data exposure',
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-3 text-koba-text-secondary">
                    <svg className="w-5 h-5 text-koba-accent flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials / Use Cases */}
      <section className="py-20 border-t border-koba-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-koba-text mb-4">
              Built for the AI era
            </h2>
            <p className="text-lg text-koba-text-secondary">
              Whether you're running one agent or thousands, Koba scales with you
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                icon: '🏦',
                title: 'Financial Services',
                description: 'Deploy AI trading bots and keep immutable proof of every action. Your compliance records, cryptographically guaranteed.',
              },
              {
                icon: '🏥',
                title: 'Healthcare',
                description: 'Give your AI assistants the access they need with the boundaries you set. HIPAA compliance built into every interaction.',
              },
              {
                icon: '🔬',
                title: 'Research Labs',
                description: 'Empower AI research assistants with full capabilities and full visibility. Experiment boldly, with complete records.',
              },
            ].map((item, i) => (
              <div key={i} className="bg-koba-bg-elevated/30 border border-koba-border-light rounded-2xl p-8 text-center">
                <div className="text-5xl mb-4">{item.icon}</div>
                <h3 className="text-xl font-semibold text-koba-text mb-3">{item.title}</h3>
                <p className="text-koba-text-secondary">{item.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-br from-koba-accent/10 via-purple-500/10 to-pink-500/10">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl sm:text-4xl font-bold text-koba-text mb-6">
            Ready to own your AI governance?
          </h2>
          <p className="text-xl text-koba-text-secondary mb-10">
            Start your free trial today. Your agents, your rules, your records.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/register"
              className="w-full sm:w-auto bg-white text-gray-900 px-8 py-4 rounded-xl font-semibold text-lg hover:bg-gray-100 transition-all shadow-xl flex items-center justify-center gap-2"
            >
              Get Started Free
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </Link>
            <Link
              href="/pitch"
              className="w-full sm:w-auto text-koba-text px-8 py-4 rounded-xl font-semibold text-lg border border-koba-border-light hover:border-koba-border transition-all flex items-center justify-center gap-2"
            >
              View Pitch Deck
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-koba-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-koba-accent via-purple-500 to-pink-500 flex items-center justify-center">
                  <svg className="w-6 h-6 text-koba-text" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <span className="text-xl font-bold text-koba-text">Koba</span>
              </div>
              <p className="text-koba-text-secondary text-sm">
                Cryptographic AI governance — protection for you, not from your AI.
              </p>
            </div>
            <div>
              <h4 className="text-koba-text font-semibold mb-4">Product</h4>
              <ul className="space-y-2">
                <li><a href="#features" className="text-koba-text-secondary hover:text-koba-text transition-colors">Features</a></li>
                <li><Link href="/developers" className="text-koba-text-secondary hover:text-koba-text transition-colors">Documentation</Link></li>
                <li><Link href="/pitch" className="text-koba-text-secondary hover:text-koba-text transition-colors">Pitch Deck</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-koba-text font-semibold mb-4">Resources</h4>
              <ul className="space-y-2">
                <li><a href="https://github.com/koba-security/koba" target="_blank" rel="noopener noreferrer" className="text-koba-text-secondary hover:text-koba-text transition-colors">GitHub</a></li>
                <li><Link href="/demo" className="text-koba-text-secondary hover:text-koba-text transition-colors">Live Demo</Link></li>
                <li><Link href="/developers" className="text-koba-text-secondary hover:text-koba-text transition-colors">API Reference</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-koba-text font-semibold mb-4">Company</h4>
              <ul className="space-y-2">
                <li><Link href="/blog" className="text-koba-text-secondary hover:text-koba-text transition-colors">Blog</Link></li>
                <li><a href="mailto:support@koba.ai" className="text-koba-text-secondary hover:text-koba-text transition-colors">Contact</a></li>
              </ul>
            </div>
          </div>
          <div className="mt-12 pt-8 border-t border-koba-border flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="text-koba-text-secondary text-sm">
              &copy; {new Date().getFullYear()} Koba Security. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              <Link href="/privacy" className="text-koba-text-secondary hover:text-koba-text transition-colors text-sm">Privacy Policy</Link>
              <Link href="/terms" className="text-koba-text-secondary hover:text-koba-text transition-colors text-sm">Terms of Service</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
