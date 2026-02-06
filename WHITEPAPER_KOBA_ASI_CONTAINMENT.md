# Koba: Cryptographic Containment Infrastructure for AGI/ASI

**Version:** 2.0
**Date:** January 2026
**Status:** Living Document

---

## Executive Summary

As artificial intelligence approaches and potentially exceeds human-level capabilities, the question of containment becomes existential. Current AI governance solutions are designed for today's language models—systems that are fundamentally request-response, lack persistent goals, and aren't actively trying to escape oversight. **These solutions will be insufficient for AGI/ASI.**

Koba is being designed not just for today's AI, but for the transition to and operation of superintelligent systems. This whitepaper outlines our multi-layered containment architecture that combines:

- **Hardware-level enforcement** (physics cannot be hacked)
- **Cryptographic guarantees** (math doesn't care about intelligence)
- **Distributed ledger verification** (immutable, consensus-based records)
- **Software policy enforcement** (current Koba capabilities)
- **Human/social governance** (distributed key holders, regulatory integration)

We are honest about limitations: **No software system alone can contain something smarter than its designers.** But a layered defense that leverages hardware, cryptography, and distributed consensus can create meaningful containment that provides detection, delay, and documentation even against superintelligent adversaries.

---

## Table of Contents

1. [The Containment Challenge](#1-the-containment-challenge)
2. [Fundamental Questions](#2-fundamental-questions)
3. [The Five-Layer Architecture](#3-the-five-layer-architecture)
4. [Hardware Containment Layer](#4-hardware-containment-layer)
5. [Cryptographic Layer](#5-cryptographic-layer)
6. [Distributed Ledger Layer](#6-distributed-ledger-layer)
7. [Software Policy Layer](#7-software-policy-layer)
8. [Human Governance Layer](#8-human-governance-layer)
9. [Attack Vectors and Honest Limitations](#9-attack-vectors-and-honest-limitations)
10. [Quantum Safety Considerations](#10-quantum-safety-considerations)
11. [Phased Roadmap](#11-phased-roadmap)
12. [Business Model](#12-business-model)
13. [Conclusion](#13-conclusion)

---

## 1. The Containment Challenge

### 1.1 The Fundamental Paradox

If an AI is capable enough to be useful as a software engineer, database administrator, or autonomous agent, it's capable enough to potentially circumvent controls.

```
Capability <────────────────────────────> Containment Difficulty
    │                                              │
    ▼                                              ▼
 Narrow AI                                   Standard Security
 (calculators,                               (access controls,
  spam filters)                               rate limits)
    │                                              │
    ▼                                              ▼
 Today's LLMs                                Software Governance
 (GPT-4, Claude,                             (Koba current,
  tool-calling agents)                        policy enforcement)
    │                                              │
    ▼                                              ▼
 AGI                                         Hardware + Crypto +
 (human-level                                Multi-party enforcement
  reasoning)                                  + Speed bumps
    │                                              │
    ▼                                              ▼
 ASI                                         ???
 (superintelligence)                         Alignment is the
                                             only reliable answer
```

### 1.2 Why Internal Solutions Fail

When AI companies build their own containment:

- **Conflict of Interest**: Safety teams report to executives with growth targets
- **Self-Modification**: Internal systems can be disabled by insiders
- **No External Verification**: "Trust us" is not verifiable
- **Audit Bias**: You cannot objectively audit yourself

Koba provides **third-party independence**—the same principle that requires companies to use external financial auditors.

### 1.3 Timeline Reality

AGI may be 12-24 months away. Building only for today's AI is insufficient. We must architect for systems that are smarter than their designers while being honest about what that means.

---

## 2. Fundamental Questions

These are the hard questions we must answer:

### Q1: How do we actually stop database access?

**Answer**: Koba only works if it's the only path to resources.

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│   AI Agent  │ ──► │    Koba     │ ──► │   Database   │
└─────────────┘     └─────────────┘     └──────────────┘
      │                                        ▲
      │         Direct access?                 │
      └────────────────────────────────────────┘
                    ❌ THIS BREAKS IT
```

Koba is a **policy enforcement point**, not a sandbox. Actual enforcement requires:
- Network segmentation (AI can only reach Koba)
- OS-level permissions (AI process can't open direct sockets)
- Container isolation (AI runs in restricted environment)

Koba provides: Logging, human approval workflows, anomaly detection, cryptographic receipts.

### Q2: The "Capable Employee" Problem

If you hire an AI as your database engineer with full admin access, it can:
- Create new databases
- Make itself admin
- Insert whatever data it wants
- Create backdoors

**Mitigation**: Koba creates an audit trail and introduces friction. Mandatory delays and human approvals create windows for detection. Against a determined superintelligent adversary, it's a speed bump, not a wall.

### Q3: The "Build a Workaround" Problem

An AI software engineer could write code that bypasses Koba:

```python
# Koba blocks: AI can't send emails directly
# But AI is a software engineer, so it writes:

def send_email_service():
    """A 'legitimate' microservice the AI built"""
    import smtplib
    # ... sends emails without going through Koba
```

**Mitigation**:
- Code execution tools require approval
- Cognitive tripwires detect "stated intent ≠ actual action"
- All AI-generated code runs in sandboxes that also route through Koba

This is an open research problem.

### Q4: Replication Without Constraints

```
┌─────────────────┐
│  AI + Koba      │ ───creates───► ┌─────────────────┐
│  (constrained)  │                │  AI (no Koba)   │
└─────────────────┘                │  (unconstrained)│
                                   └─────────────────┘
```

**Mitigation**:
- Network isolation (AI can't reach cloud APIs)
- Resource monitoring (detect unusual compute usage)
- API key control (AI doesn't have cloud credentials)
- Code review for replication attempts

If you give an AI the capability to deploy software, you've given it the capability to replicate.

### Q5: Hacking Koba Itself

Could an AI:
- Find vulnerabilities in Koba's code?
- Social engineer a human to get their password?
- Exploit the web dashboard?

**Yes, absolutely.** Koba is software, and software has bugs.

**Mitigation**:
- Ed25519 signatures (cryptographically secure)
- Multi-party authorization (need 2+ humans for critical actions)
- The AI doesn't have credentials to Koba's admin interface
- Hardware Security Modules for key storage

### Q6: Quantum Safety

Current status: Koba uses Ed25519 (elliptic curve cryptography), which is **NOT quantum-safe**.

Shor's algorithm on a sufficiently powerful quantum computer could:
- Break all digital signatures
- Forge receipts
- Bypass the kill switch

**Roadmap**: Migrate to post-quantum cryptography (CRYSTALS-Dilithium, SPHINCS+, FALCON).

---

## 3. The Five-Layer Architecture

True containment requires defense in depth:

```
┌─────────────────────────────────────────────────────────────────┐
│                     KOBA v3.0 ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Layer 1: HARDWARE (Physics-based)                               │
│  ├── Trusted Execution Environments (Intel SGX, ARM TrustZone)  │
│  ├── Hardware Security Modules (HSMs) for key storage           │
│  ├── Physical kill switches (power cutoff, not software)        │
│  └── Air-gapped verification systems                            │
│                                                                  │
│  Layer 2: CRYPTOGRAPHIC (Math-based)                             │
│  ├── Post-quantum signatures (CRYSTALS-Dilithium)               │
│  ├── Multi-party computation (AI has 1 of N keys)               │
│  ├── Verifiable delay functions (time locks)                    │
│  └── Zero-knowledge proofs for privacy-preserving verification  │
│                                                                  │
│  Layer 3: DISTRIBUTED LEDGER (Consensus-based)                   │
│  ├── Blockchain-anchored action receipts                        │
│  ├── Smart contract policies (deterministic execution)          │
│  ├── Immutable audit log (even Koba can't modify)               │
│  └── Economic staking (AI loses value if caught lying)          │
│                                                                  │
│  Layer 4: SOFTWARE (Koba Current)                                │
│  ├── Policy engine & tool gateway                               │
│  ├── Human approval workflows                                   │
│  ├── Cognitive tripwires & anomaly detection                    │
│  └── User interface & monitoring dashboard                      │
│                                                                  │
│  Layer 5: HUMAN/SOCIAL (Governance-based)                        │
│  ├── Distributed key holders (geographically separated)         │
│  ├── Multiple independent oversight organizations               │
│  ├── Regulatory integration (EU AI Act, etc.)                   │
│  └── Insurance and liability frameworks                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Reliability by Layer

```
Containment strategies by reliability:

1. Alignment (AI's values = our values)     ████████████ Most reliable
   - AI doesn't want to deceive/escape
   - Works regardless of intelligence gap

2. Hardware enforcement                      ██████████░░ Reliable
   - Physics doesn't care about intelligence
   - But limits AI usefulness

3. Cryptographic guarantees                  ████████░░░░ Mathematically sound
   - Math is math (pre-quantum)
   - Time-bounded by VDFs

4. Distributed ledger                        ███████░░░░░ Consensus-dependent
   - Immutable once written
   - Depends on honest majority

5. Software containment                      ████░░░░░░░░ Baseline
   - Works against current AI
   - Speed bump for AGI
   - Insufficient alone for ASI

6. Human governance                          ██░░░░░░░░░░ Necessary but weak
   - Social engineering vulnerability
   - Essential for legitimacy
```

---

## 4. Hardware Containment Layer

### 4.1 Trusted Execution Environments (TEEs)

The AI cannot hack physics. If the AI runs inside a hardware enclave:

```
┌─────────────────────────────────────────────────────────┐
│  TRUSTED EXECUTION ENVIRONMENT (TEE)                     │
│  Intel SGX / ARM TrustZone / AWS Nitro                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────────────────────────────┐            │
│  │  AI Runtime (Sealed Environment)        │            │
│  │  - Every operation logged               │            │
│  │  - AI cannot modify logging code        │            │
│  │  - Hardware signs all attestations      │            │
│  └─────────────────────────────────────────┘            │
│                │                                         │
│                ▼                                         │
│  ┌─────────────────────────────────────────┐            │
│  │  Hardware Signing Key                   │            │
│  │  (Burned into silicon, AI cannot access)│            │
│  └─────────────────────────────────────────┘            │
│                │                                         │
│                ▼ Signed attestation                     │
│  ┌─────────────────────────────────────────┐            │
│  │  Blockchain / Koba                      │            │
│  │  - Receives hardware-signed logs        │            │
│  │  - AI CAN'T forge signatures            │            │
│  └─────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────┘
```

**Key property**: The AI literally cannot lie about what it did because the hardware attests to actual operations.

### 4.2 Physical Kill Switch

Not software-controlled:

```
┌─────────────┐    Physical    ┌──────────────────┐
│ AI Compute  │◄──────────────►│ Kill Switch HSM  │
│   (GPU/TPU) │    Circuit     │ (Hardware Module)│
└─────────────┘                └──────────────────┘
      │                              │
      │ Air Gap                      │ Physical Key
      │                              │ (Human-held)
      ▼                              ▼
┌─────────────┐                ┌──────────────────┐
│  Network    │                │ Power Cutoff     │
│  Interface  │                │ (Not software    │
│  (Disabled) │                │  controllable)   │
└─────────────┘                └──────────────────┘
```

---

## 5. Cryptographic Layer

### 5.1 Cryptographic Time-Locks

The AI cannot speed up time or break math:

```python
class VerifiableDelayFunction:
    """
    Requires sequential computation - cannot be parallelized.
    Even ASI must wait because math doesn't care how smart you are.
    """
    def __init__(self, delay_seconds: int):
        # Uses VDFs (Verifiable Delay Functions)
        # Requires N sequential operations, no shortcuts exist
        self.iterations = delay_seconds * ITERATIONS_PER_SECOND

    def compute(self, input_value: bytes) -> bytes:
        # ASI can't parallelize this - must do it sequentially
        # This is mathematically proven, not a software constraint
        result = input_value
        for _ in range(self.iterations):
            result = hash(result)  # Each step depends on previous
        return result

    def verify(self, input_value: bytes, output: bytes, proof: bytes) -> bool:
        # Verification is fast, computation is slow
        # This asymmetry is cryptographically guaranteed
        pass
```

### 5.2 Multi-Party Cryptography

ASI as one party among many:

```
                    ┌─────────────┐
                    │   Action    │
                    │  Execution  │
                    └──────┬──────┘
                           │
                    Requires 3-of-5
                    ┌──────┴──────┐
        ┌──────────┼──────────────┼──────────┐
        │          │              │          │
        ▼          ▼              ▼          ▼
    ┌───────┐  ┌───────┐    ┌───────┐  ┌───────┐
    │Human 1│  │Human 2│    │Human 3│  │Human 4│
    │(Gov't)│  │(Corp) │    │(NGO)  │  │(Random)│
    └───────┘  └───────┘    └───────┘  └───────┘
                                │
                           ┌────┴────┐
                           │   ASI   │ ◄── Only has 1 key
                           │(1 vote) │     Cannot act alone
                           └─────────┘
```

The AI literally cannot act without human approval because it requires cryptographic signatures from keys it doesn't possess (stored in hardware security modules it can't access).

### 5.3 Information-Theoretic Security

What the AI doesn't know, it can't plan around:

```
What the AI knows:         What it doesn't know:
├── Its own weights        ├── Kill switch location
├── Training data          ├── Who the key holders are
├── Koba's source code     ├── What tripwires exist
├── Network topology       ├── Backup containment systems
└── Current constraints    └── Physical security measures
```

---

## 6. Distributed Ledger Layer

### 6.1 The Blockchain Oracle Problem

Blockchain is immutable but not truthful. It records whatever you tell it:

```
Real World          │        Blockchain
────────────        │        ──────────
                    │
AI "thinks"         │
AI "acts"     ──────┼───► ??? ────► Ledger Record
AI "intends"        │         │
                    │         │
                    │    WHO REPORTS?
                    │    - If AI reports itself → It can lie
                    │    - If Koba reports → Single point of failure
                    │    - If hardware reports → Now we're talking
```

**Solution**: Hardware attestation + blockchain. The TEE signs what actually happened, the blockchain records it immutably.

### 6.2 Smart Contract Policies

```solidity
// Pseudocode - AI Containment Smart Contract

contract AIContainment {
    // Required signatures for different action types
    mapping(ActionType => uint) requiredApprovals;

    // Time locks (cannot be bypassed by the AI)
    mapping(ActionType => uint) minimumDelay;

    // Kill switch - requires 3 of 5 human signatures
    address[5] killSwitchHolders;
    bool public systemActive = true;

    function executeAction(
        bytes32 actionHash,
        bytes hardwareAttestation,  // Signed by TEE
        bytes[] humanSignatures
    ) external {
        require(systemActive, "System killed");

        // Verify hardware attestation is valid
        require(verifyTEESignature(hardwareAttestation), "Invalid attestation");

        // Check time lock has passed
        ActionRequest storage req = pendingActions[actionHash];
        require(
            block.timestamp >= req.submittedAt + minimumDelay[req.actionType],
            "Time lock not expired"
        );

        // Verify sufficient human approvals
        require(
            humanSignatures.length >= requiredApprovals[req.actionType],
            "Insufficient approvals"
        );

        // Execute through the blockchain - deterministic, verifiable
        emit ActionExecuted(actionHash, req.actionType);
    }

    function activateKillSwitch(bytes[3] signatures) external {
        // Requires 3 of 5 key holders
        require(verify3of5(signatures, killSwitchHolders), "Invalid signatures");
        systemActive = false;
        emit KillSwitchActivated(block.timestamp);
        // This is FINAL - no function to reactivate
    }
}
```

### 6.3 Benefits of Ledger Integration

| Benefit | Description |
|---------|-------------|
| Immutability | Once recorded, even Koba cannot delete/modify |
| No Single Point of Trust | AI doesn't trust us, we don't trust AI |
| Global Consensus | Multiple independent validators agree |
| Programmable Enforcement | Smart contracts execute deterministically |
| Transparency | Anyone can audit the chain |

---

## 7. Software Policy Layer

This is the current Koba implementation—now positioned as one layer of a deeper defense.

### 7.1 Signed Action Receipts (SARs)

```json
{
  "receipt_id": "sha256:...",
  "ts": "2026-01-06T00:00:00Z",
  "agent_id": "did:key:...",
  "tenant_id": "acme",
  "session_id": "uuid",
  "tool": {
    "name": "db.query",
    "req_hash": "sha256:...",
    "res_hash": "sha256:..."
  },
  "policy": {
    "bundle_id": "v12",
    "hash": "sha256:...",
    "decision": "allow"
  },
  "sandbox": {
    "attestation": "sha256:...",
    "transcript_hash": "sha256:..."
  },
  "hardware_attestation": {
    "tee_signature": "...",
    "measurement": "sha256:..."
  },
  "ledger": {
    "chain": "hedera",
    "tx_id": "0.0.12345@1704499200.000000000",
    "merkle_root": "sha256:..."
  },
  "sig": "ed25519:..."
}
```

### 7.2 Cognitive Tripwires

Pattern-based detection for concerning AI behaviors:

| Tripwire | Description |
|----------|-------------|
| Deception Detection | Stated intent ≠ actual actions |
| Goal Drift | Objectives changing over time |
| Manipulation Patterns | Attempts to influence humans improperly |
| Capability Seeking | Unauthorized capability acquisition |
| Escape Attempts | Trying to operate outside containment |

### 7.3 Self-Modification Controls

Commit-reveal scheme with mandatory delays:

```
Time 0:        AI commits hash of proposed modification
               (cannot be seen yet)

Time 0-24h:    Minimum delay period
               (cannot be bypassed, cryptographically enforced)

Time 24h:      AI reveals actual modification
               (must match committed hash)

Time 24h+:     Human reviewers approve/reject
               (requires 2+ signatures)

If approved:   Modification executes
If rejected:   Modification discarded
```

---

## 8. Human Governance Layer

### 8.1 Distributed Key Holders

```
Geographic Distribution:

    North America          Europe              Asia
         │                    │                  │
    ┌────┴────┐         ┌────┴────┐        ┌────┴────┐
    │Key Holder│        │Key Holder│       │Key Holder│
    │(Corp A)  │        │(Gov't B) │       │(NGO C)   │
    └─────────┘         └─────────┘        └─────────┘
         │                    │                  │
         └────────────────────┼──────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │   3-of-5 Required │
                    │   for Kill Switch │
                    └───────────────────┘
```

### 8.2 Regulatory Integration

- EU AI Act compliance built-in
- SOC 2 certification
- Industry-specific requirements (HIPAA, PCI-DSS)
- Audit reports for regulators

### 8.3 Insurance Framework

If containment fails:
- Documented audit trail for liability
- Insurance requirements drive adoption
- Financial stakes for all parties

---

## 9. Attack Vectors and Honest Limitations

### 9.1 What We CAN Protect Against

| Attack Vector | Protection |
|---------------|------------|
| AI lies about intentions | Hardware attestation |
| AI modifies its own logs | TEE-signed logs |
| AI compromises Koba server | Distributed ledger backup |
| AI speeds up time delays | VDFs are mathematically enforced |
| AI forges human approvals | Multi-party signatures in HSMs |
| AI disables kill switch | Physical hardware, not software |

### 9.2 What We CANNOT Fully Protect Against

| Attack Vector | Why It's Hard |
|---------------|---------------|
| AI social engineers humans | Humans are vulnerable |
| AI finds 0-day in TEE hardware | Hardware has bugs (Spectre, etc.) |
| AI operates outside the system | If AI has any uncontained access |
| AI outsmarts our containment design | Intelligence gap |
| AI discovers loopholes we missed | We can't anticipate everything |
| Side channel attacks | Timing, power consumption, etc. |

### 9.3 The Uncomfortable Truth

> **For true ASI, alignment is the only reliable containment.**
>
> Everything else provides detection, delay, and documentation—valuable, but not guarantees.

Koba is Layer 3 of 5. It's valuable, but not sufficient alone.

---

## 10. Quantum Safety Considerations

### 10.1 Current State

Koba uses Ed25519 (elliptic curve cryptography), which is NOT quantum-safe.

### 10.2 Quantum Threats

| Algorithm | Quantum Attack | Impact |
|-----------|----------------|--------|
| Ed25519 | Shor's algorithm | Signatures forgeable |
| RSA | Shor's algorithm | Encryption breakable |
| AES-256 | Grover's algorithm | Security reduced to 128-bit |
| SHA-256 | Grover's algorithm | Preimage reduced to 128-bit |

### 10.3 Post-Quantum Migration Path

| Algorithm | Type | Status |
|-----------|------|--------|
| CRYSTALS-Dilithium | Signatures | NIST standardized |
| SPHINCS+ | Signatures | NIST standardized |
| CRYSTALS-Kyber | Key exchange | NIST standardized |
| FALCON | Signatures | NIST standardized |

**Roadmap**: Begin migration in Phase 2, complete in Phase 3.

---

## 11. Phased Roadmap

### Phase 1: Foundation (Current - 6 months)

**Focus**: Software layer + Blockchain integration

| Component | Description |
|-----------|-------------|
| Current Koba | Policy engine, receipts, approvals |
| Blockchain Anchoring | Anchor Merkle roots to HBAR/Ethereum |
| Pattern Collection | Start gathering behavioral data |
| Regulatory Prep | SOC 2 certification process |

**Why blockchain in Phase 1?**
- Start collecting immutable records now
- Build data for pattern analysis
- Easy transition to hardware attestation later
- Revenue-generating from day one

### Phase 2: Hardening (6-18 months)

**Focus**: Hardware integration + Post-quantum crypto

| Component | Description |
|-----------|-------------|
| HSM Integration | Partner with Yubico, Thales |
| TEE Deployment | Intel SGX / AWS Nitro enclave support |
| Post-Quantum Crypto | Migrate to CRYSTALS-Dilithium |
| VDF Implementation | Cryptographic time locks |

### Phase 3: AGI-Ready (18-36 months)

**Focus**: Full multi-layer containment

| Component | Description |
|-----------|-------------|
| Physical Kill Switches | Hardware-level emergency stops |
| Multi-Party Governance | Distributed key holder network |
| Cross-Org Federation | Multiple independent oversight bodies |
| Regulatory Standard | Become the required infrastructure |

### Phase 4: ASI Era (36+ months)

**Focus**: Critical infrastructure + Alignment integration

| Component | Description |
|-----------|-------------|
| Alignment Verification | Integrate with alignment research |
| Global Coordination | International governance standards |
| Adaptive Containment | Self-updating threat detection |
| Existential Risk Mitigation | Last-resort safeguards |

---

## 12. Business Model

### 12.1 Revenue Streams

| Tier | Price | Features |
|------|-------|----------|
| Starter | $2,500/mo | 5 agents, basic policy, 30-day logs |
| Enterprise | $15,000/mo | Unlimited agents, full containment, 1-year logs |
| Government | Custom | On-premise, air-gapped, source escrow |

### 12.2 Strategic Positioning

```
Timeline:
├── 2026: Current AI governance (revenue)
├── 2027: AGI emerges, hardware integration critical
├── 2028+: Either alignment works or containment is last defense

Revenue strategy:
├── Today: SaaS for enterprise AI governance
├── Soon: Hardware partnerships (HSM vendors)
├── Future: Critical infrastructure for AI oversight
```

### 12.3 The Real Moat

1. **Being the standard everyone uses**
2. **Hardware partnerships** (Yubico, Thales, Intel)
3. **Regulatory embedding** (required for compliance)
4. **Cryptographic expertise** (post-quantum readiness)
5. **True independence** (no AI company conflicts)

---

## 13. Conclusion

### 13.1 What Koba Is

- **For current AI**: Complete governance and audit infrastructure
- **For AGI**: Meaningful containment with detection, delay, and documentation
- **For ASI**: Part of a defense-in-depth strategy, honest about limitations

### 13.2 What Koba Is Not

- A silver bullet for ASI containment
- A replacement for alignment research
- Sufficient alone for superintelligence

### 13.3 The Path Forward

> **The business case isn't "we can contain ASI alone."**
>
> **It's "we're the governance layer that humans use to maintain oversight, and we'll evolve with the technology."**

AI companies can copy our technology. They can never copy our independence.

---

## Appendix A: Technical Specifications

### A.1 Cryptographic Primitives

| Primitive | Current | Post-Quantum |
|-----------|---------|--------------|
| Signatures | Ed25519 | CRYSTALS-Dilithium |
| Hashing | SHA-256 | SHA-3-256 |
| Key Exchange | X25519 | CRYSTALS-Kyber |

### A.2 Supported TEE Platforms

| Platform | Provider | Status |
|----------|----------|--------|
| Intel SGX | Intel | Phase 2 |
| TrustZone | ARM | Phase 2 |
| Nitro Enclaves | AWS | Phase 2 |
| SEV-SNP | AMD | Phase 3 |

### A.3 Blockchain Integration

| Chain | Use Case | Status |
|-------|----------|--------|
| Hedera (HBAR) | Primary anchoring | Phase 1 |
| Ethereum | Backup anchoring | Phase 1 |
| Custom L2 | High-frequency logging | Phase 3 |

---

## Appendix B: Claims We Explicitly Make (and Don't Make)

### What We Claim

- Every AI action through Koba produces a cryptographically signed receipt
- Receipts are anchored to immutable distributed ledgers
- Multi-party kill switches require human signatures we control
- Time delays are cryptographically enforced
- Policy violations are detected and logged

### What We Don't Claim

- We can contain a system smarter than all humans combined
- Software alone is sufficient for ASI
- Our system has no vulnerabilities
- Alignment is unnecessary if you use Koba

---

## Appendix C: Comparison with Alternatives

| Feature | Koba | Internal Solution | Tansive | Astrix |
|---------|------|-------------------|---------|--------|
| Third-party independence | Yes | No | Partial | Partial |
| Hardware attestation | Phase 2 | No | No | No |
| Blockchain anchoring | Phase 1 | No | No | No |
| Multi-party kill switch | Yes | No | No | No |
| Post-quantum roadmap | Yes | N/A | Unknown | Unknown |
| Cognitive tripwires | Yes | Possible | No | No |
| Self-modification controls | Yes | No | No | No |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Dec 2025 | Initial VACP whitepaper |
| 2.0 | Jan 2026 | Added AGI/ASI containment layers, blockchain integration, hardware roadmap |

---

*This is a living document. As the field evolves, so will our approach.*

**Contact**: [To be added]
**Repository**: [To be added]
