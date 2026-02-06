# Koba/VACP Compliance Mapping

## Overview

This document maps Koba/VACP security controls to major compliance frameworks including SOC 2 Type II and HIPAA. The mapping demonstrates how VACP features support compliance requirements.

---

## SOC 2 Type II Mapping

### Trust Service Criteria

#### CC1: Control Environment

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC1.1 | Integrity and ethical values | Role-based access control | RBAC configuration, permission audit logs |
| CC1.2 | Board independence | Multi-party approval requirements | Approval workflow logs |
| CC1.3 | Management oversight | Kill switch with M-of-N signatures | Key holder registry, activation logs |
| CC1.4 | Competence | Operator authentication with MFA | Authentication logs, training records |
| CC1.5 | Accountability | Signed action receipts | Receipt chain with Merkle proofs |

#### CC2: Communication and Information

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC2.1 | Quality information | Structured audit logging | Log schemas, validation rules |
| CC2.2 | Internal communication | Alert notifications | Alert history, notification logs |
| CC2.3 | External communication | API documentation | OpenAPI specs, change logs |

#### CC3: Risk Assessment

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC3.1 | Risk identification | Threat model (STRIDE) | threat_model.md |
| CC3.2 | Risk from changes | Commit-reveal for modifications | Commitment logs, approval records |
| CC3.3 | Fraud risk | Cognitive tripwires, deception detection | Tripwire alerts, behavioral profiles |
| CC3.4 | Change impact | Policy evaluation before execution | Policy evaluation logs |

#### CC4: Monitoring Activities

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC4.1 | Ongoing monitoring | Real-time alerting, health checks | Metrics dashboards, alert history |
| CC4.2 | Deficiency evaluation | Anomaly detection, behavioral analysis | Anomaly scores, investigation records |

#### CC5: Control Activities

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC5.1 | Control selection | Default deny policy | Policy bundle configuration |
| CC5.2 | Technology controls | Cryptographic signing, encryption | Key management logs |
| CC5.3 | Policy deployment | Policy bundle versioning | Bundle history, deployment logs |

#### CC6: Logical Access

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC6.1 | Logical access security | API key management, session tokens | Key lifecycle logs |
| CC6.2 | Prior authorization | RBAC permissions | Permission grants, role assignments |
| CC6.3 | Credential issuance | Secure key generation | Key creation logs with metadata |
| CC6.4 | Credential removal | Key expiration, revocation | Revocation records |
| CC6.5 | Authentication | API key + session validation | Authentication logs |
| CC6.6 | Access restrictions | Tenant isolation, resource patterns | Policy rules, access logs |
| CC6.7 | Encryption in transit | TLS for all connections | Certificate records |
| CC6.8 | Encryption at rest | Database encryption | Encryption configuration |

#### CC7: System Operations

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC7.1 | Change management | Commit-reveal scheme | Commitment history |
| CC7.2 | System monitoring | Prometheus metrics, health checks | Monitoring dashboards |
| CC7.3 | Anomaly detection | Behavioral profiling, tripwires | Alert logs |
| CC7.4 | Incident response | Incident response procedures | incident_response.md |
| CC7.5 | Recovery procedures | Kill switch reset, backup restore | Recovery logs |

#### CC8: Change Management

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC8.1 | Change authorization | Multi-party approval | Approval records |

#### CC9: Risk Mitigation

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| CC9.1 | Vendor risk | AI provider monitoring | Provider health checks |
| CC9.2 | Business continuity | Kill switch, failover | Activation records |

---

### Additional Criteria for Confidentiality

| Criteria | Description | VACP Control | Evidence |
|----------|-------------|--------------|----------|
| C1.1 | Confidential information | Data classification, redaction | Redaction rules |
| C1.2 | Confidentiality commitment | Tenant isolation | Isolation configuration |

---

## HIPAA Mapping

### Administrative Safeguards (164.308)

| Requirement | Section | VACP Control | Implementation |
|-------------|---------|--------------|----------------|
| Security Management | 164.308(a)(1) | Risk analysis, threat model | threat_model.md |
| Risk Analysis | 164.308(a)(1)(ii)(A) | STRIDE analysis | Documented threats and mitigations |
| Risk Management | 164.308(a)(1)(ii)(B) | Policy engine, containment | Policy enforcement, kill switch |
| Sanction Policy | 164.308(a)(1)(ii)(C) | Operator suspension | Session termination capabilities |
| Activity Review | 164.308(a)(1)(ii)(D) | Audit logging | Comprehensive audit trail |
| Workforce Security | 164.308(a)(3) | RBAC, authentication | Role-based access control |
| Access Authorization | 164.308(a)(4) | Permission management | Explicit permission grants |
| Security Awareness | 164.308(a)(5) | Policy documentation | Policy bundle documentation |
| Security Incident | 164.308(a)(6) | Incident response | incident_response.md |
| Contingency Plan | 164.308(a)(7) | Kill switch, recovery | Documented procedures |
| Evaluation | 164.308(a)(8) | Security testing | Adversarial test suite |

### Physical Safeguards (164.310)

| Requirement | Section | VACP Control | Implementation |
|-------------|---------|--------------|----------------|
| Facility Access | 164.310(a)(1) | N/A (cloud-based) | Cloud provider responsibility |
| Workstation Use | 164.310(b) | Session management | Session timeout, termination |
| Workstation Security | 164.310(c) | MFA, key management | Authentication requirements |
| Device Controls | 164.310(d)(1) | Key lifecycle | Key expiration, rotation |

### Technical Safeguards (164.312)

| Requirement | Section | VACP Control | Implementation |
|-------------|---------|--------------|----------------|
| Access Control | 164.312(a)(1) | RBAC, policy engine | Permission-based access |
| Unique User ID | 164.312(a)(2)(i) | API keys, operator IDs | Unique identifiers for all entities |
| Emergency Access | 164.312(a)(2)(ii) | Kill switch reset | Master key recovery procedure |
| Automatic Logoff | 164.312(a)(2)(iii) | Session expiration | Configurable timeout |
| Encryption | 164.312(a)(2)(iv) | TLS, at-rest encryption | Cryptographic controls |
| Audit Controls | 164.312(b) | Merkle log, receipts | Immutable audit trail |
| Integrity Controls | 164.312(c)(1) | Hash chains, signatures | Cryptographic verification |
| Authentication | 164.312(d) | API key, session tokens | Multi-factor capability |
| Transmission Security | 164.312(e)(1) | TLS encryption | Certificate management |

### Organizational Requirements (164.314)

| Requirement | Section | VACP Control | Implementation |
|-------------|---------|--------------|----------------|
| Business Associate | 164.314(a)(1) | Tenant contracts | Tenant configuration |
| Group Health Plans | 164.314(b)(1) | N/A | Application specific |

### Policies and Procedures (164.316)

| Requirement | Section | VACP Control | Implementation |
|-------------|---------|--------------|----------------|
| Policies | 164.316(a) | Policy documentation | Policy bundle schemas |
| Documentation | 164.316(b)(1) | Version control | Bundle versioning |
| Updates | 164.316(b)(2)(iii) | Policy updates | Commit-reveal scheme |

---

## Control Mapping Summary

### Core VACP Features by Compliance Requirement

| VACP Feature | SOC 2 Controls | HIPAA Requirements |
|--------------|----------------|-------------------|
| Policy Engine | CC5.1, CC5.3 | 164.308(a)(1), 164.312(a)(1) |
| RBAC | CC6.2, CC6.6 | 164.308(a)(3), 164.308(a)(4) |
| Audit Logging | CC4.1, CC7.2 | 164.312(b), 164.316(b)(1) |
| Merkle Log | CC5.2 | 164.312(c)(1) |
| API Key Management | CC6.1, CC6.3, CC6.4 | 164.312(a)(2)(i), 164.312(d) |
| Session Management | CC6.5 | 164.312(a)(2)(iii), 164.312(d) |
| Kill Switch | CC7.5, CC9.2 | 164.308(a)(7), 164.312(a)(2)(ii) |
| Commit-Reveal | CC3.2, CC8.1 | 164.316(b)(2)(iii) |
| Behavioral Analysis | CC3.3, CC4.2 | 164.308(a)(1)(ii)(D) |
| Encryption | CC6.7, CC6.8 | 164.312(a)(2)(iv), 164.312(e)(1) |
| Multi-party Approval | CC1.3, CC8.1 | 164.308(a)(4) |
| Incident Response | CC7.4 | 164.308(a)(6) |
| Threat Modeling | CC3.1 | 164.308(a)(1)(ii)(A) |

---

## Audit Evidence Guide

### Required Documentation

| Document | SOC 2 | HIPAA | Location |
|----------|-------|-------|----------|
| Threat Model | CC3.1 | 164.308(a)(1)(ii)(A) | docs/threat_model.md |
| Incident Response | CC7.4 | 164.308(a)(6) | docs/incident_response.md |
| Policy Bundles | CC5.3 | 164.316(a) | config/policies/ |
| RBAC Configuration | CC6.2 | 164.308(a)(3) | config/rbac.yaml |
| API Documentation | CC2.3 | N/A | docs/api/ |

### Required Logs

| Log Type | Retention | SOC 2 | HIPAA |
|----------|-----------|-------|-------|
| Authentication | 1 year | CC6.5 | 164.312(d) |
| Authorization | 1 year | CC6.6 | 164.312(a)(1) |
| Policy Evaluation | 1 year | CC5.1 | 164.308(a)(1) |
| Audit Trail | 6 years | CC4.1 | 164.312(b) |
| Alerts | 1 year | CC4.2 | 164.308(a)(6) |
| Access Logs | 1 year | CC6.1 | 164.312(b) |

### Required Configurations

| Configuration | Purpose | Compliance |
|--------------|---------|------------|
| TLS Certificates | Encryption in transit | CC6.7, 164.312(e)(1) |
| Encryption Keys | Encryption at rest | CC6.8, 164.312(a)(2)(iv) |
| API Key Settings | Access control | CC6.1, 164.312(a)(2)(i) |
| Session Timeout | Automatic logoff | CC6.5, 164.312(a)(2)(iii) |
| Retention Policy | Log retention | CC4.1, 164.312(b) |

---

## Gap Analysis

### Current Gaps and Remediation

| Gap | Compliance Impact | Remediation | Priority |
|-----|-------------------|-------------|----------|
| HSM not integrated | CC6.1 (partial) | Integrate with HSM provider | High |
| No formal security awareness training | CC1.4, 164.308(a)(5) | Develop training program | Medium |
| Limited geographic restrictions | CC6.6 (enhancement) | Add IP geolocation | Low |
| No BAA template | 164.314(a)(1) | Create BAA template | High (HIPAA) |

### Planned Enhancements

| Enhancement | Target Date | Compliance Benefit |
|-------------|-------------|-------------------|
| HSM integration | Q2 2026 | Enhanced key security |
| WebAuthn support | Q3 2026 | Stronger authentication |
| Automated compliance reports | Q2 2026 | Audit efficiency |
| Geographic access controls | Q3 2026 | Enhanced access control |

---

## Certification Checklist

### SOC 2 Type II Readiness

- [x] Policy engine with default deny
- [x] Role-based access control
- [x] Comprehensive audit logging
- [x] Merkle tree for integrity
- [x] Multi-party approvals
- [x] Kill switch with signatures
- [x] Incident response procedures
- [x] Threat model documented
- [x] API key lifecycle management
- [x] Session management
- [x] Real-time monitoring
- [x] Anomaly detection
- [ ] HSM integration (planned)
- [ ] Automated compliance reporting (planned)

### HIPAA Readiness

- [x] Access controls
- [x] Audit controls
- [x] Integrity controls
- [x] Authentication
- [x] Transmission security
- [x] Emergency access procedure
- [x] Automatic logoff
- [x] Unique user identification
- [x] Incident response procedures
- [x] Risk analysis
- [ ] BAA template (in progress)
- [ ] Staff training program (planned)

---

## Auditor Resources

### Test Procedures

1. **Access Control Testing**
   ```bash
   # Verify RBAC enforcement
   vacp-cli test rbac --comprehensive

   # Test API key lifecycle
   vacp-cli test apikey-lifecycle
   ```

2. **Audit Trail Verification**
   ```bash
   # Verify Merkle chain integrity
   vacp-cli audit verify-chain --full

   # Export audit sample
   vacp-cli audit export --sample 1000
   ```

3. **Encryption Verification**
   ```bash
   # Verify TLS configuration
   vacp-cli test tls --endpoint api.example.com

   # Verify at-rest encryption
   vacp-cli test encryption-at-rest
   ```

### Evidence Collection

```bash
# Generate compliance evidence package
vacp-cli compliance export \
  --framework soc2 \
  --period "2024-01-01:2024-12-31" \
  --output compliance_evidence.zip
```

### Attestation Reports

| Report | Frequency | Audience |
|--------|-----------|----------|
| SOC 2 Type II | Annual | Customers, auditors |
| HIPAA Assessment | Annual | Covered entities |
| Penetration Test | Annual | Internal, regulators |
| Vulnerability Scan | Quarterly | Security team |

---

## Document Control

- **Version**: 1.0
- **Last Updated**: 2026-02-03
- **Classification**: Internal/Confidential
- **Review Cycle**: Quarterly
- **Owner**: Compliance Team
- **Approval**: {Compliance Officer signature}
