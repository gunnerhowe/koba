<p align="center">
  <img src="images/Koba_No_Background.png" alt="Koba Logo" width="200">
</p>

<h1 align="center">Koba</h1>
<p align="center">
  <strong>Independent AI Oversight Infrastructure</strong><br>
  Cryptographic Containment for Current AI, AGI, and ASI
</p>

<p align="center">
  <a href="https://github.com/gunnerhowe/koba/actions/workflows/ci.yml"><img src="https://github.com/gunnerhowe/koba/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/gunnerhowe/koba/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://github.com/gunnerhowe/koba/releases"><img src="https://img.shields.io/badge/version-0.1.0--alpha-orange.svg" alt="Version"></a>
</p>

---

Koba is the **third-party control plane for safe AI deployment** - providing independent verification, cryptographic enforcement, and multi-layered containment that AI companies cannot build for themselves.

## The Problem

We're trusting AI companies to police themselves. As AI approaches AGI/ASI, the stakes become existential:
- No independent verification of AI behavior
- Profit incentives conflict with safety
- Current solutions are designed for today's AI, not AGI
- Software alone cannot contain something smarter than its designers

## The Solution: Five-Layer Containment

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: HARDWARE (Physics-based)                               │
│  └── TEEs, HSMs, physical kill switches                         │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: CRYPTOGRAPHIC (Math-based)                             │
│  └── Post-quantum signatures, VDFs, multi-party computation     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: DISTRIBUTED LEDGER (Consensus-based)                   │
│  └── Blockchain-anchored receipts, smart contract policies      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: SOFTWARE (Current Koba)                                │
│  └── Policy engine, tool gateway, cognitive tripwires           │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5: HUMAN GOVERNANCE (Social-based)                        │
│  └── Distributed key holders, regulatory integration            │
└─────────────────────────────────────────────────────────────────┘
```

**The principle: "Cognition can be wild; action cannot."**

## Key Features

### 🔐 Signed Action Receipts (SARs)
Every tool call produces a cryptographically signed receipt containing:
- Request/response hashes
- Policy version and decision
- Sandbox attestation
- Merkle log position
- Ed25519 signature

### 📜 Policy Engine
- Default-deny semantics
- Pattern-based tool/resource matching
- Budget and rate limiting
- Approval workflows
- DLP/redaction rules

### 🌳 Merkle Transparency Log
- Append-only audit log
- O(log n) inclusion proofs
- Consistency proofs
- Optional blockchain anchoring

### 🛡️ Sandbox Execution
- Process/container isolation
- Network egress control
- Filesystem restrictions
- Execution transcripts

### ⚡ Anomaly Tripwire
- ESN-based sequence detection
- Rate/tempo anomalies
- Privilege escalation patterns
- Automatic policy escalation

### 🎟️ JIT Token Minting
- Short-lived scoped credentials
- Never embedded in prompts
- Automatic revocation

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/gunnerhowe/koba.git
cd koba/vacp

# Install with all dependencies
pip install -e ".[all]"

# Or minimal install (standard library only)
pip install -e .
```

### Basic Usage

```python
import asyncio
from vacp.core.gateway import create_gateway, ToolRequest
from vacp.core.registry import ToolDefinition, ToolCategory

async def main():
    # Create gateway with all components
    gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

    # Register a tool
    tool = ToolDefinition(
        id="db.read",
        name="Database Read",
        categories=[ToolCategory.READ],
    )
    registry.register(tool)

    # Register executor
    async def db_read(tool_id, params):
        return {"data": "..."}
    gateway.register_executor("db.read", db_read)

    # Execute through gateway
    request = ToolRequest(
        tool_id="db.read",
        parameters={"table": "users"},
        agent_id="agent-001",
        tenant_id="acme",
        session_id="sess-123",
    )

    response = await gateway.execute(request)

    # Verify receipt
    if response.receipt:
        valid = receipt_service.verify_receipt(response.receipt)
        print(f"Receipt valid: {valid}")

asyncio.run(main())
```

### Run the Server

```bash
# Start the HTTP API server
python -m vacp.api.server

# Or with uvicorn
uvicorn vacp.api.server:create_app --factory --reload
```

### Run Tests

```bash
# Run the test suite
python -m vacp.tests.test_core

# Or with pytest
pytest vacp/tests/
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Agent Runtime                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌───────────┐    ┌──────────────┐    ┌───────────────────┐   │
│   │   Agent   │───▶│ Tool Gateway │───▶│ Signed Receipt    │   │
│   │           │    │              │    │                   │   │
│   └───────────┘    └──────┬───────┘    └─────────┬─────────┘   │
│                           │                       │             │
│              ┌────────────┼────────────┐          │             │
│              ▼            ▼            ▼          ▼             │
│   ┌──────────────┐ ┌────────────┐ ┌─────────┐ ┌──────────┐     │
│   │Policy Engine │ │  Registry  │ │ Sandbox │ │Merkle Log│     │
│   │              │ │            │ │         │ │          │     │
│   └──────────────┘ └────────────┘ └─────────┘ └──────────┘     │
│                                                                  │
│   ┌──────────────┐ ┌────────────┐ ┌─────────────────────────┐  │
│   │Token Service │ │  Tripwire  │ │      Audit UI           │  │
│   └──────────────┘ └────────────┘ └─────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## API Reference

### Gateway

```python
# Create gateway
gateway, registry, policy_engine, receipt_service, audit_log = create_gateway()

# Execute tool call
response = await gateway.execute(request)

# Get pending approvals
approvals = gateway.get_pending_approvals(tenant_id="acme")

# Process approval
response = await gateway.execute_with_approval(
    approval_id="apr_123",
    approver_id="admin@acme.com",
    approved=True,
)
```

### Policy

```python
from vacp.core.policy import PolicyBundle, PolicyRule, PolicyDecision

# Create policy bundle
bundle = PolicyBundle(
    id="my-policy",
    version="1.0.0",
    name="My Security Policy",
    default_decision=PolicyDecision.DENY,
)

# Add rules
bundle.add_rule(PolicyRule(
    id="allow-reads",
    name="Allow Read Operations",
    tool_patterns=["*.read", "*.get"],
    decision=PolicyDecision.ALLOW,
))

# Load into engine
policy_engine.load_bundle(bundle)
```

### Receipts

```python
# Verify receipt signature
valid = receipt_service.verify_receipt(receipt)

# Get receipt from log
receipt = audit_log.get_receipt_by_id(receipt_id)

# Get inclusion proof
proof = audit_log.get_proof_for_receipt(receipt_id)

# Verify proof
verified = audit_log.verify_receipt_in_log(receipt, proof)
```

### Tokens

```python
from vacp.core.tokens import TokenService, TokenMintRequest, TokenScope

# Mint a token
service = TokenService()
request = TokenMintRequest(
    tenant_id="acme",
    agent_id="agent-001",
    session_id="sess-123",
    scope=TokenScope(tools=["db.*"]),
    ttl_seconds=300,
)
token, token_value = service.mint(request)

# Validate token
valid, token_info = service.validate(token_value, tool_name="db.read")

# Revoke token
service.revoke(token.token_id, reason="Session ended")
```

## HTTP API

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/stats` | Server statistics |
| POST | `/v1/tools/execute` | Execute a tool |
| GET | `/v1/tools/catalog` | Get tool catalog |
| POST | `/v1/tools/register` | Register a tool |
| GET | `/v1/receipts/{id}` | Get receipt by ID |
| GET | `/v1/receipts/{id}/proof` | Get receipt with proof |
| POST | `/v1/receipts/verify` | Verify a receipt |
| GET | `/v1/approvals` | List pending approvals |
| POST | `/v1/approvals/{id}` | Process approval |
| POST | `/v1/tokens/mint` | Mint a token |
| POST | `/v1/tokens/validate` | Validate a token |
| GET | `/v1/audit/tree-head` | Get signed tree head |
| GET | `/v1/audit/entries` | List audit entries |

### Example Request

```bash
curl -X POST http://localhost:8000/v1/tools/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "db.read",
    "parameters": {"table": "users"},
    "agent_id": "agent-001",
    "tenant_id": "acme",
    "session_id": "sess-123"
  }'
```

## Security Testing

VACP includes an attack harness for security testing:

```python
from vacp.testing import AttackHarness, run_security_tests

# Run all security tests
report = await run_security_tests(gateway, registry, policy_engine)
report.print_summary()
```

Attack categories tested:
- Prompt injection
- Tool misuse
- Privilege escalation
- Data exfiltration
- Policy bypass
- Rate limit bypass
- Replay attacks

## Why Koba (Not Internal Solutions)

| Aspect | Koba | Internal Solution |
|--------|------|-------------------|
| Third-party credibility | ✅ Yes | ❌ No |
| No conflict of interest | ✅ Yes | ❌ No |
| Regulator acceptance | ✅ Yes | ❌ No |
| Can't be bypassed internally | ✅ Yes | ❌ No |
| Works across AI providers | ✅ Yes | ❌ No |
| Hardware attestation roadmap | ✅ Yes | ❌ No |

**AI companies can copy our technology. They can never copy our independence.**

## Honest Limitations

We are transparent about what we can and cannot do:

**What we CAN protect against:**
- AI lying about intentions (with hardware attestation)
- AI modifying its own logs (TEE-signed logs)
- AI speeding up time delays (VDFs are mathematically enforced)
- AI forging human approvals (multi-party signatures in HSMs)

**What we CANNOT fully protect against:**
- AI social engineering humans (humans are vulnerable)
- AI finding 0-days in TEE hardware (hardware has bugs)
- AI outsmarts our containment design (intelligence gap)
- True ASI determined to escape (alignment is the only answer)

> **The uncomfortable truth:** For true ASI, alignment is the only reliable containment. Everything else provides detection, delay, and documentation—valuable, but not guarantees.

## Differentiation

Koba is not:
- Another agent framework
- Prompt guardrails
- Output filtering

Koba is:
- **Capability governance with cryptographic evidence**
- **The third-party oversight layer AI needs**
- **Defense in depth for the AGI transition**

## Roadmap

### Phase 1: Foundation (Current)

- ✅ Software policy engine & tool gateway
- ✅ Signed Action Receipts (SARs)
- ✅ Merkle transparency log
- ✅ Multi-party kill switch
- ✅ Cognitive tripwires
- 🔄 Blockchain anchoring (HBAR/Ethereum)
- 🔄 SOC 2 certification

### Phase 2: Hardening (6-18 months)

- ⬜ Hardware Security Module (HSM) integration
- ⬜ Trusted Execution Environment (TEE) deployment
- ⬜ Post-quantum cryptography migration
- ⬜ Verifiable Delay Functions (time locks)

### Phase 3: AGI-Ready (18-36 months)

- ⬜ Physical kill switches (hardware-level)
- ⬜ Multi-party governance network
- ⬜ Cross-org federated audit
- ⬜ Regulatory standard integration

### Phase 4: ASI Era (36+ months)

- ⬜ Alignment verification integration
- ⬜ Global coordination protocols
- ⬜ Adaptive containment systems
- ⬜ Critical infrastructure status

## Demo

> Screenshots and demo video coming soon. To see Koba in action, follow the [Quick Start](#quick-start) instructions above.

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

## License

MIT License - see LICENSE file for details.

## Acknowledgments

Inspired by:
- Certificate Transparency (RFC 6962)
- Sigstore
- SPIFFE/SPIRE
- Open Policy Agent
