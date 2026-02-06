# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-02-06

### Added
- Core policy engine with default-deny semantics and pattern-based rules
- Signed Action Receipts (SARs) with Ed25519 signatures
- Merkle transparency log with inclusion and consistency proofs
- Tool gateway with intercepted execution and receipt generation
- JIT token minting with scoped, short-lived credentials
- Anomaly tripwire with ESN-based sequence detection
- Multi-party kill switch
- HTTP API (FastAPI) with full CRUD endpoints
- Authentication system with JWT tokens and role-based access control
- Multi-tenant support
- Dashboard UI (Next.js) with monitoring, receipts, approvals, and audit views
- Desktop application (Electron) wrapping backend and dashboard
- Docker Compose setup for local development and production
- Blockchain anchoring support (Hedera Consensus Service)
- Security testing harness with adversarial test suite
- Comprehensive test suite (unit, integration, adversarial, e2e, fuzz)

### Security
- Default-deny policy prevents unauthorized tool execution
- Cryptographic receipt chain provides tamper-evident audit trail
- Sandbox execution isolates tool operations
- Rate limiting and budget enforcement

[0.1.0-alpha]: https://github.com/gunnerhowe/koba/releases/tag/v0.1.0-alpha
