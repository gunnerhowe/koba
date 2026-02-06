# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Koba, please report it responsibly:

### How to Report

1. **Email**: Send a detailed report to **koba-security@proton.me**
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Status update**: Within 7 days with an assessment
- **Resolution**: We aim to patch critical vulnerabilities within 14 days

### Scope

The following are in scope:
- Backend API (`vacp/`)
- Cryptographic operations (receipts, signatures, Merkle proofs)
- Policy engine bypass vulnerabilities
- Authentication and authorization flaws
- Dashboard XSS or CSRF vulnerabilities

### Out of Scope

- Social engineering attacks
- Denial of service (unless trivially exploitable)
- Issues in third-party dependencies (report upstream)

### Recognition

We will credit reporters in our CHANGELOG (unless you prefer to remain anonymous).

## Security Design

Koba is designed with security as a core principle:
- Default-deny policy engine
- Ed25519 signed action receipts
- Merkle transparency log for tamper evidence
- Process-isolated sandbox execution
- JIT token minting (credentials never embedded in prompts)

For architecture details, see the [whitepaper](WHITEPAPER_KOBA_ASI_CONTAINMENT.md).
