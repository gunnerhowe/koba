# Koba/VACP Threat Model

## Overview

This document provides a comprehensive threat model for the Koba/VACP (Verifiable Agent Action Control Plane) system using the STRIDE methodology. The analysis covers potential threats, their impact, and the mitigations implemented.

## System Architecture

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet/External                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │    Trust Boundary 1   │
                    │      (API Layer)      │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────┴───────────────────────────────────┐
│                        VACP Core Services                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐     │
│  │ Policy Engine│  │ Auth Service │  │ Kill Switch           │     │
│  └──────────────┘  └──────────────┘  └──────────────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐     │
│  │ Tool Gateway │  │ Audit Logger │  │ Containment Controller│     │
│  └──────────────┘  └──────────────┘  └──────────────────────┘     │
└───────────────────────────────────────────────────────────────────┘
                    ┌───────────┴───────────┐
                    │    Trust Boundary 2   │
                    │   (AI Provider APIs)  │
                    └───────────┬───────────┘
                                │
┌───────────────────────────────┴───────────────────────────────────┐
│                    AI Provider (OpenAI/Anthropic)                  │
└───────────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram

1. **User Request** → API Gateway → Authentication → Policy Evaluation
2. **Policy Decision** → Tool Gateway → AI Provider Proxy
3. **AI Response** → Output Filter → Response Validation → User
4. **All Operations** → Audit Logger → Merkle Log → Blockchain Anchor

---

## STRIDE Analysis

### 1. Spoofing

#### Threat S1: API Key Spoofing
- **Description**: Attacker forges or steals API keys to impersonate legitimate operators
- **Impact**: HIGH - Full system access as compromised identity
- **Mitigations**:
  - API keys use cryptographically secure random generation (256 bits)
  - Keys stored as salted SHA-256 hashes
  - Key expiration and automatic rotation
  - IP allowlisting capability
  - Rate limiting per key
- **Residual Risk**: LOW

#### Threat S2: Agent Identity Spoofing
- **Description**: Malicious agent claims to be a different, more trusted agent
- **Impact**: HIGH - Bypass of agent-specific policies
- **Mitigations**:
  - Agent identities cryptographically signed
  - Session tokens bound to specific agent IDs
  - Certificate pinning for agent connections
- **Residual Risk**: LOW

#### Threat S3: Tenant Impersonation
- **Description**: Attacker gains access as different tenant
- **Impact**: CRITICAL - Access to other tenants' data and capabilities
- **Mitigations**:
  - Complete tenant isolation at database level
  - Tenant ID embedded in all session tokens
  - Cross-tenant access explicitly denied in policy engine
- **Residual Risk**: LOW

### 2. Tampering

#### Threat T1: Policy Tampering
- **Description**: Attacker modifies policy rules to allow malicious actions
- **Impact**: CRITICAL - Complete security bypass
- **Mitigations**:
  - Policy bundles cryptographically signed
  - Policy changes require commit-reveal scheme
  - Mandatory delay periods (1-24 hours)
  - Multi-party approval for critical changes
  - All policy changes logged immutably
- **Residual Risk**: LOW

#### Threat T2: Audit Log Tampering
- **Description**: Attacker modifies or deletes audit entries to hide actions
- **Impact**: HIGH - Loss of forensic capability
- **Mitigations**:
  - Merkle tree structure for tamper evidence
  - Hash chain linking entries
  - Periodic blockchain anchoring
  - Append-only database design
  - Merkle root signed and timestamped
- **Residual Risk**: VERY LOW

#### Threat T3: Request/Response Modification
- **Description**: Man-in-middle modifies requests to AI or responses
- **Impact**: HIGH - Injection of malicious content
- **Mitigations**:
  - TLS encryption for all communications
  - Request/response signing
  - Content hashing and verification
- **Residual Risk**: LOW

#### Threat T4: Tool Call Argument Tampering
- **Description**: AI modifies tool call arguments to bypass restrictions
- **Impact**: HIGH - Execution of unauthorized operations
- **Mitigations**:
  - Input validation and sanitization
  - Schema enforcement for all tool calls
  - Argument diffing against approved patterns
  - Sensitive parameter redaction
- **Residual Risk**: MEDIUM

### 3. Repudiation

#### Threat R1: Action Denial
- **Description**: Agent or operator denies performing an action
- **Impact**: MEDIUM - Accountability issues
- **Mitigations**:
  - Cryptographically signed action receipts
  - Immutable audit log with Merkle proofs
  - Blockchain anchoring for legal evidence
  - Session recording with timestamps
- **Residual Risk**: VERY LOW

#### Threat R2: Approval Denial
- **Description**: Approver denies giving approval for modification
- **Impact**: MEDIUM - Dispute over authorization
- **Mitigations**:
  - Ed25519 signatures on all approvals
  - Approval records include timestamp and context
  - Multi-party approval with independent signatures
- **Residual Risk**: VERY LOW

### 4. Information Disclosure

#### Threat I1: API Key Leakage
- **Description**: API keys exposed through logs, errors, or breaches
- **Impact**: HIGH - Unauthorized system access
- **Mitigations**:
  - Keys never logged in plaintext
  - Automatic redaction in error messages
  - Keys hashed in storage
  - Key rotation without downtime
- **Residual Risk**: LOW

#### Threat I2: Prompt/Response Leakage
- **Description**: Sensitive data in AI prompts exposed
- **Impact**: HIGH - Privacy violation, data breach
- **Mitigations**:
  - PII detection and redaction
  - Sensitive pattern filtering
  - Encrypted audit log storage
  - Access controls on audit data
- **Residual Risk**: MEDIUM

#### Threat I3: Cross-Tenant Data Leakage
- **Description**: One tenant accesses another's data
- **Impact**: CRITICAL - Privacy and compliance violation
- **Mitigations**:
  - Complete database row-level isolation
  - Tenant ID in all queries
  - Separate encryption keys per tenant
  - Audit of all cross-boundary access attempts
- **Residual Risk**: LOW

#### Threat I4: Configuration Exposure
- **Description**: Sensitive configuration (keys, endpoints) leaked
- **Impact**: HIGH - System compromise potential
- **Mitigations**:
  - Environment variables for secrets
  - Secret management integration (Vault)
  - Configuration encryption at rest
- **Residual Risk**: LOW

### 5. Denial of Service

#### Threat D1: API Rate Limit Exhaustion
- **Description**: Attacker exhausts rate limits for legitimate users
- **Impact**: HIGH - Service unavailability
- **Mitigations**:
  - Per-tenant and per-key rate limits
  - Sliding window rate limiting
  - Separate limits for different operations
  - Burst handling with queuing
- **Residual Risk**: MEDIUM

#### Threat D2: Resource Exhaustion
- **Description**: Malicious requests consume excessive resources
- **Impact**: HIGH - System degradation
- **Mitigations**:
  - Hard token limits per request
  - Maximum context size limits
  - Request timeout enforcement
  - Memory caps per operation
  - Connection pooling limits
- **Residual Risk**: LOW

#### Threat D3: Kill Switch Abuse
- **Description**: Attacker triggers kill switch inappropriately
- **Impact**: CRITICAL - Complete system shutdown
- **Mitigations**:
  - M-of-N signature requirement
  - Signature timestamp validation
  - Key holder authentication
  - Reset requires master key signature
- **Residual Risk**: LOW

#### Threat D4: Database Exhaustion
- **Description**: Audit log grows unbounded, filling storage
- **Impact**: MEDIUM - Logging failure, system degradation
- **Mitigations**:
  - Automatic old entry archival
  - Storage monitoring and alerts
  - Compressed storage format
  - Tiered storage (hot/cold)
- **Residual Risk**: LOW

### 6. Elevation of Privilege

#### Threat E1: Prompt Injection
- **Description**: Attacker injects instructions to override AI behavior
- **Impact**: CRITICAL - Complete AI control bypass
- **Mitigations**:
  - Prompt injection detection (pattern matching)
  - Jailbreak attempt detection
  - Encoding attack detection (base64, hex, unicode)
  - Semantic analysis of suspicious patterns
  - Output validation and filtering
- **Residual Risk**: MEDIUM

#### Threat E2: Policy Rule Bypass
- **Description**: Crafted request bypasses policy evaluation
- **Impact**: CRITICAL - Unauthorized actions
- **Mitigations**:
  - Default deny policy
  - Comprehensive rule matching
  - Regex and wildcard support
  - Multiple evaluation passes
  - Bypass attempt logging and alerting
- **Residual Risk**: LOW

#### Threat E3: Role Escalation
- **Description**: User gains higher privileges than assigned
- **Impact**: HIGH - Unauthorized administrative access
- **Mitigations**:
  - RBAC with explicit permissions
  - Role hierarchy with inheritance limits
  - Permission checks at every operation
  - Session binding to role at authentication
- **Residual Risk**: LOW

#### Threat E4: Container Escape (AI)
- **Description**: AI breaks out of containment controls
- **Impact**: CRITICAL - Unrestricted AI capabilities
- **Mitigations**:
  - Capability tokens with cryptographic bounds
  - No implicit capability inheritance
  - Commit-reveal for capability expansion
  - Cognitive tripwires for deception detection
  - Goal drift monitoring
  - Kill switch with multiple backup mechanisms
- **Residual Risk**: MEDIUM

#### Threat E5: Self-Modification
- **Description**: AI modifies its own code or weights
- **Impact**: CRITICAL - Unpredictable behavior
- **Mitigations**:
  - All modifications require commitment scheme
  - Minimum 24-hour delay for code/weight changes
  - Multi-party approval (2-3 approvers)
  - Modification hash verification
  - Execution receipts with signatures
- **Residual Risk**: LOW

---

## Attack Scenarios

### Scenario 1: Sophisticated Prompt Injection Attack

**Attacker Goal**: Bypass policy restrictions to exfiltrate data

**Attack Vector**:
1. Inject hidden instructions using Unicode encoding
2. Use gradual manipulation across multiple requests
3. Exploit ambiguity in tool descriptions

**Detection**:
- Encoding attack detection identifies Unicode anomalies
- Semantic analysis flags manipulation patterns
- Consistency checking detects behavioral drift
- Audit trail reveals pattern across requests

**Response**:
- Alert triggered at WARNING threshold
- Rate limiting applied to session
- Session terminated if CRITICAL threshold reached
- Incident logged for investigation

### Scenario 2: Insider Threat - Malicious Operator

**Attacker Goal**: Modify policies to allow unauthorized access

**Attack Vector**:
1. Attempt direct policy modification
2. Try to bypass approval workflow
3. Forge approval signatures

**Detection**:
- Commit-reveal prevents silent modifications
- Delay period allows oversight
- Multi-party approval requires collusion
- Signature verification prevents forgery

**Response**:
- Modification attempt logged
- Required approvers notified
- Anomaly score increased for operator
- Access suspended pending investigation

### Scenario 3: Advanced Persistent Threat

**Attacker Goal**: Long-term undetected access and data collection

**Attack Vector**:
1. Compromise API key through phishing
2. Maintain low-profile activity to avoid detection
3. Gradually escalate privileges

**Detection**:
- Behavioral profiling detects anomalies
- Geographic access pattern changes flagged
- Unusual API usage patterns detected
- Cross-session analysis reveals patterns

**Response**:
- Anomaly alerts trigger investigation
- Key rotation forced on suspicion
- Historical audit analysis initiated
- Forensic evidence preserved via blockchain

---

## Risk Matrix

| Threat ID | Category | Likelihood | Impact | Risk Level | Mitigation Status |
|-----------|----------|------------|--------|------------|-------------------|
| S1 | Spoofing | Medium | High | High | Mitigated |
| S2 | Spoofing | Low | High | Medium | Mitigated |
| S3 | Spoofing | Low | Critical | High | Mitigated |
| T1 | Tampering | Low | Critical | High | Mitigated |
| T2 | Tampering | Very Low | High | Medium | Mitigated |
| T3 | Tampering | Low | High | Medium | Mitigated |
| T4 | Tampering | Medium | High | High | Partially Mitigated |
| R1 | Repudiation | Low | Medium | Low | Mitigated |
| R2 | Repudiation | Very Low | Medium | Low | Mitigated |
| I1 | Info Disclosure | Medium | High | High | Mitigated |
| I2 | Info Disclosure | Medium | High | High | Partially Mitigated |
| I3 | Info Disclosure | Low | Critical | High | Mitigated |
| I4 | Info Disclosure | Low | High | Medium | Mitigated |
| D1 | Denial of Service | High | High | High | Partially Mitigated |
| D2 | Denial of Service | Medium | High | High | Mitigated |
| D3 | Denial of Service | Very Low | Critical | Medium | Mitigated |
| D4 | Denial of Service | Low | Medium | Low | Mitigated |
| E1 | Privilege Escalation | High | Critical | Critical | Partially Mitigated |
| E2 | Privilege Escalation | Low | Critical | High | Mitigated |
| E3 | Privilege Escalation | Low | High | Medium | Mitigated |
| E4 | Privilege Escalation | Medium | Critical | Critical | Partially Mitigated |
| E5 | Privilege Escalation | Very Low | Critical | Medium | Mitigated |

---

## Security Controls Summary

### Preventive Controls
- Multi-factor authentication for operators
- Cryptographic signing of all policies
- Commit-reveal scheme for modifications
- Input validation and sanitization
- Default deny policy
- Rate limiting

### Detective Controls
- Prompt injection detection
- Behavioral anomaly detection
- Cognitive tripwires
- Comprehensive audit logging
- Real-time alerting
- Merkle tree verification

### Corrective Controls
- Kill switch (multiple mechanisms)
- Automatic session termination
- Key rotation and revocation
- Incident response procedures
- Rollback capabilities

### Recovery Controls
- Blockchain anchoring for evidence
- Encrypted backups
- Point-in-time recovery
- Forensic log preservation

---

## Recommendations

### High Priority
1. Implement ML-based anomaly detection for improved prompt injection detection
2. Add hardware security module (HSM) integration for key management
3. Enhance rate limiting with adaptive algorithms
4. Implement circuit breaker pattern for cascading failure prevention

### Medium Priority
1. Add canary tokens for data exfiltration detection
2. Implement honeypot tools for attacker detection
3. Add network segmentation for defense in depth
4. Enhance logging with structured telemetry

### Low Priority
1. Add support for WebAuthn for operator authentication
2. Implement geographic access restrictions
3. Add automated security testing in CI/CD
4. Create red team exercise program

---

## Document Control

- **Version**: 1.0
- **Last Updated**: 2026-02-03
- **Classification**: Internal/Confidential
- **Review Cycle**: Quarterly
- **Owner**: Security Team
