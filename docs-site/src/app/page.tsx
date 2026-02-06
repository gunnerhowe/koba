import Image from "next/image";

const GITHUB_URL = "https://github.com/gunnerhowe/koba";
const WHITEPAPER_URL =
  "https://github.com/gunnerhowe/koba/blob/main/docs/whitepaper.md";

/* ------------------------------------------------------------------ */
/*  SVG Icons (inline, no external deps)                              */
/* ------------------------------------------------------------------ */

function IconReceipt() {
  return (
    <svg
      className="w-8 h-8 text-blue-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
      />
    </svg>
  );
}

function IconShield() {
  return (
    <svg
      className="w-8 h-8 text-blue-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
      />
    </svg>
  );
}

function IconTree() {
  return (
    <svg
      className="w-8 h-8 text-blue-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M4 6h16M4 12h8m-8 6h16M16 12l4 4m0-8l-4 4"
      />
    </svg>
  );
}

function IconSandbox() {
  return (
    <svg
      className="w-8 h-8 text-blue-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
      />
    </svg>
  );
}

function IconAlert() {
  return (
    <svg
      className="w-8 h-8 text-blue-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 9v2m0 4h.01M10.29 3.86l-8.58 14.86A1 1 0 002.58 20h18.84a1 1 0 00.87-1.28L13.71 3.86a1 1 0 00-1.42 0z"
      />
    </svg>
  );
}

function IconKey() {
  return (
    <svg
      className="w-8 h-8 text-blue-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M15 7a4 4 0 11-8 0 4 4 0 018 0zm-4 4v6m-3-3h6"
      />
    </svg>
  );
}

function IconGitHub({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 24 24">
      <path
        fillRule="evenodd"
        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
        clipRule="evenodd"
      />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Data                                                              */
/* ------------------------------------------------------------------ */

const LAYERS = [
  {
    num: 5,
    name: "Human Governance",
    basis: "Social-based",
    desc: "Distributed key holders, multi-party authorization",
    current: false,
  },
  {
    num: 4,
    name: "Software",
    basis: "Current",
    desc: "Policy engine, tool gateway, tripwires",
    current: true,
  },
  {
    num: 3,
    name: "Distributed Ledger",
    basis: "Consensus-based",
    desc: "Blockchain-anchored receipts, tamper evidence",
    current: false,
  },
  {
    num: 2,
    name: "Cryptographic",
    basis: "Math-based",
    desc: "Post-quantum signatures, VDFs",
    current: false,
  },
  {
    num: 1,
    name: "Hardware",
    basis: "Physics-based",
    desc: "TEEs, HSMs, physical kill switches",
    current: false,
  },
];

const FEATURES = [
  {
    icon: <IconReceipt />,
    title: "Signed Action Receipts",
    desc: "Ed25519 signatures on every action. Request/response hashes, policy version tracking, and full audit provenance for every AI agent operation.",
  },
  {
    icon: <IconShield />,
    title: "Policy Engine",
    desc: "Default-deny semantics that block everything not explicitly allowed. Pattern matching, rate limiting, and multi-party approval workflows.",
  },
  {
    icon: <IconTree />,
    title: "Merkle Transparency Log",
    desc: "Append-only audit log with O(log n) inclusion proofs. Blockchain anchoring ensures no receipt can be silently deleted or modified.",
  },
  {
    icon: <IconSandbox />,
    title: "Sandbox Execution",
    desc: "Process isolation with restricted network egress, filesystem read-only mounts, and resource caps. Actions run in contained environments.",
  },
  {
    icon: <IconAlert />,
    title: "Anomaly Tripwire",
    desc: "ESN-based anomaly detection monitoring rate anomalies, privilege escalation patterns, and behavioral drift. Automatic alerts and shutdown.",
  },
  {
    icon: <IconKey />,
    title: "JIT Token Minting",
    desc: "Short-lived, narrowly scoped credentials minted just-in-time for each action. Automatic revocation on expiry or policy violation.",
  },
];

const COMPARISON = [
  { label: "Third-party credibility", koba: true, internal: false },
  { label: "No conflict of interest", koba: true, internal: false },
  { label: "Regulator acceptance", koba: true, internal: false },
  { label: "Can't be bypassed internally", koba: true, internal: false },
  { label: "Works across AI providers", koba: true, internal: false },
  { label: "Hardware attestation roadmap", koba: true, internal: false },
];

/* ------------------------------------------------------------------ */
/*  Page                                                              */
/* ------------------------------------------------------------------ */

export default function Home() {
  return (
    <div className="min-h-screen">
      {/* ============ NAV ============ */}
      <nav className="sticky top-0 z-50 border-b border-gray-800/60 bg-gray-950/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3 sm:px-6">
          <a href="#" className="flex items-center gap-2">
            <Image
              src="/koba-logo.png"
              alt="Koba logo"
              width={32}
              height={32}
              className="rounded"
            />
            <span className="text-lg font-semibold tracking-tight">Koba</span>
          </a>

          <div className="hidden items-center gap-6 text-sm text-gray-400 sm:flex">
            <a href="#features" className="transition hover:text-white">
              Features
            </a>
            <a href="#quickstart" className="transition hover:text-white">
              Quick Start
            </a>
            <a href={WHITEPAPER_URL} className="transition hover:text-white" target="_blank" rel="noopener noreferrer">
              Whitepaper
            </a>
          </div>

          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-900 px-4 py-2 text-sm font-medium transition hover:border-gray-600 hover:bg-gray-800"
          >
            <IconGitHub />
            GitHub
          </a>
        </div>
      </nav>

      {/* ============ HERO ============ */}
      <section className="relative overflow-hidden px-4 pb-20 pt-24 sm:px-6 sm:pt-32">
        {/* Subtle gradient glow */}
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="h-[500px] w-[700px] rounded-full bg-blue-500/5 blur-3xl" />
        </div>

        <div className="relative mx-auto max-w-4xl text-center">
          <Image
            src="/koba-logo.png"
            alt="Koba"
            width={160}
            height={160}
            className="mx-auto mb-8 rounded-2xl"
            priority
          />

          <h1 className="text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
            Independent AI Oversight{" "}
            <span className="bg-gradient-to-r from-blue-400 to-blue-600 bg-clip-text text-transparent">
              Infrastructure
            </span>
          </h1>

          <p className="mx-auto mt-6 max-w-2xl text-lg text-gray-400 sm:text-xl">
            Cryptographic Containment for Current AI, AGI, and ASI
          </p>

          <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-6 py-3 font-semibold text-white transition hover:bg-blue-500"
            >
              <IconGitHub />
              Get Started
            </a>
            <a
              href={WHITEPAPER_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-6 py-3 font-semibold transition hover:border-gray-500 hover:bg-gray-900"
            >
              Read the Whitepaper
            </a>
          </div>

          <p className="mt-12 text-base italic text-gray-500">
            &ldquo;Cognition can be wild; action cannot.&rdquo;
          </p>
        </div>
      </section>

      {/* ============ PROBLEM ============ */}
      <section className="bg-gray-900/50 px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-center text-3xl font-bold tracking-tight sm:text-4xl">
            The Problem
          </h2>
          <p className="mx-auto mt-6 max-w-3xl text-center text-gray-400 leading-relaxed">
            Today, AI companies police themselves. There is no independent
            verification that safety promises are being kept. Internal oversight
            teams face inherent conflicts of interest -- the same organizations
            that profit from deploying AI are tasked with restraining it. No
            external auditor can verify what an AI agent actually did, because
            there are no tamper-proof records. Regulators have no technical
            mechanism to inspect, constrain, or halt AI operations in real time.
          </p>
          <div className="mx-auto mt-10 grid max-w-3xl gap-6 sm:grid-cols-3">
            {[
              {
                title: "Self-Policing",
                text: "AI companies mark their own homework with no independent verification.",
              },
              {
                title: "No Audit Trail",
                text: "No tamper-proof records of what AI agents actually do in production.",
              },
              {
                title: "Profit vs Safety",
                text: "The entities deploying AI have direct financial incentives to cut corners.",
              },
            ].map((item) => (
              <div
                key={item.title}
                className="rounded-xl border border-gray-800 bg-gray-900 p-6"
              >
                <h3 className="font-semibold text-white">{item.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-gray-400">
                  {item.text}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ============ FIVE-LAYER ARCHITECTURE ============ */}
      <section className="px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-center text-3xl font-bold tracking-tight sm:text-4xl">
            Five-Layer Architecture
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-center text-gray-400">
            Defense in depth -- from physics to social governance. The software
            layer is fully implemented today; the remaining layers define the
            roadmap.
          </p>

          <div className="mx-auto mt-12 max-w-2xl space-y-3">
            {LAYERS.map((layer) => (
              <div
                key={layer.num}
                className={`relative flex items-start gap-4 rounded-xl border p-5 transition ${
                  layer.current
                    ? "border-green-500/60 bg-green-950/30 shadow-lg shadow-green-500/5"
                    : "border-gray-800 bg-gray-900/60"
                }`}
              >
                <div
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg font-bold ${
                    layer.current
                      ? "bg-green-500/20 text-green-400"
                      : "bg-gray-800 text-gray-400"
                  }`}
                >
                  {layer.num}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-white">{layer.name}</h3>
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                        layer.current
                          ? "bg-green-500/20 text-green-400"
                          : "bg-gray-800 text-gray-500"
                      }`}
                    >
                      {layer.basis}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-gray-400">{layer.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ============ FEATURES ============ */}
      <section id="features" className="bg-gray-900/50 px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-6xl">
          <h2 className="text-center text-3xl font-bold tracking-tight sm:text-4xl">
            Core Capabilities
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-center text-gray-400">
            Every layer of Koba is designed for cryptographic verifiability and
            zero-trust enforcement.
          </p>

          <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f) => (
              <div
                key={f.title}
                className="rounded-xl border border-gray-800 bg-gray-900 p-6 transition hover:border-gray-700"
              >
                <div className="mb-4">{f.icon}</div>
                <h3 className="text-lg font-semibold text-white">{f.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-gray-400">
                  {f.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ============ QUICK START ============ */}
      <section id="quickstart" className="px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-center text-3xl font-bold tracking-tight sm:text-4xl">
            Quick Start
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-center text-gray-400">
            Get Koba running locally in under a minute.
          </p>

          <div className="mt-10 overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
            <div className="flex items-center gap-2 border-b border-gray-800 px-4 py-3">
              <span className="h-3 w-3 rounded-full bg-red-500/70" />
              <span className="h-3 w-3 rounded-full bg-yellow-500/70" />
              <span className="h-3 w-3 rounded-full bg-green-500/70" />
              <span className="ml-2 text-xs text-gray-500">terminal</span>
            </div>
            <pre className="overflow-x-auto p-6 font-mono text-sm leading-relaxed text-gray-300">
              <code>{`git clone https://github.com/gunnerhowe/koba.git
cd koba/vacp
pip install -e ".[all]"
python -m vacp.api.server`}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* ============ COMPARISON TABLE ============ */}
      <section id="whitepaper" className="bg-gray-900/50 px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-center text-3xl font-bold tracking-tight sm:text-4xl">
            Why Third-Party Oversight?
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-center text-gray-400">
            Independent infrastructure changes the trust model entirely.
          </p>

          <div className="mt-10 overflow-hidden rounded-xl border border-gray-800">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-gray-800 bg-gray-900">
                  <th className="px-6 py-4 font-semibold text-gray-300">
                    Capability
                  </th>
                  <th className="px-6 py-4 text-center font-semibold text-blue-400">
                    Koba
                  </th>
                  <th className="px-6 py-4 text-center font-semibold text-gray-400">
                    Internal Solutions
                  </th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON.map((row, i) => (
                  <tr
                    key={row.label}
                    className={`border-b border-gray-800/60 ${
                      i % 2 === 0 ? "bg-gray-950/50" : "bg-gray-900/30"
                    }`}
                  >
                    <td className="px-6 py-4 text-gray-300">{row.label}</td>
                    <td className="px-6 py-4 text-center">
                      {row.koba ? (
                        <span className="text-lg text-green-400">&#10003;</span>
                      ) : (
                        <span className="text-lg text-red-400">&#10007;</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-center">
                      {row.internal ? (
                        <span className="text-lg text-green-400">&#10003;</span>
                      ) : (
                        <span className="text-lg text-red-400">&#10007;</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* ============ CTA ============ */}
      <section className="px-4 py-24 sm:px-6">
        <div className="mx-auto max-w-3xl text-center">
          <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
            Ready to bring independent oversight to your AI?
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-gray-400">
            Koba is open source and MIT licensed. Start integrating
            cryptographic governance into your AI agent pipeline today.
          </p>
          <div className="mt-10">
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-8 py-4 text-lg font-semibold text-white transition hover:bg-blue-500"
            >
              <IconGitHub className="w-6 h-6" />
              View on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* ============ FOOTER ============ */}
      <footer className="border-t border-gray-800/60 px-4 py-10 sm:px-6">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 text-sm text-gray-500 sm:flex-row">
          <div className="flex items-center gap-4">
            <Image
              src="/koba-logo.png"
              alt="Koba"
              width={24}
              height={24}
              className="rounded"
            />
            <span>&copy; 2025&ndash;2026 Koba Contributors</span>
          </div>
          <div className="flex items-center gap-6">
            <span>MIT License</span>
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="transition hover:text-white"
            >
              GitHub
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
