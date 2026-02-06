# Koba/VACP Incident Response Procedures

## Overview

This document defines the incident response procedures for the Koba/VACP system. It provides guidance for detecting, responding to, and recovering from security incidents.

---

## Incident Classification

### Severity Levels

| Level | Name | Description | Response Time | Escalation |
|-------|------|-------------|---------------|------------|
| SEV-1 | Critical | Kill switch activation, data breach, complete system compromise | Immediate | Executive team |
| SEV-2 | High | Active attack, policy bypass, significant data exposure | 15 minutes | Security lead |
| SEV-3 | Medium | Suspicious activity, failed attack attempts, policy violations | 1 hour | On-call engineer |
| SEV-4 | Low | Anomalies, configuration issues, minor policy warnings | 4 hours | Next business day |

### Incident Types

#### Type A: AI Containment Breach
- AI attempting unauthorized actions
- Policy bypass detected
- Cognitive tripwire triggered
- Goal drift observed

#### Type B: Security Breach
- Unauthorized access
- API key compromise
- Data exfiltration attempt
- Privilege escalation

#### Type C: Operational Incident
- System outage
- Performance degradation
- Integration failure
- Configuration error

#### Type D: Compliance Incident
- Audit log tampering
- Policy violation
- Data handling error
- Regulatory breach

---

## Incident Response Team

### Roles and Responsibilities

| Role | Responsibilities | On-Call Rotation |
|------|-----------------|------------------|
| Incident Commander | Overall coordination, decision authority | 24/7 |
| Security Lead | Technical security response | 24/7 |
| Engineering Lead | System recovery, technical remediation | 24/7 |
| Communications Lead | Internal/external communications | Business hours |
| Legal Counsel | Regulatory compliance, legal guidance | On request |

### Contact Information

```
Primary On-Call: security-oncall@company.com
Security Emergency: +1-XXX-XXX-XXXX
Escalation: security-escalation@company.com
```

---

## Detection and Alerting

### Automated Detection

The following alerts indicate potential incidents:

| Alert | Severity | Type | Action |
|-------|----------|------|--------|
| `KillSwitchActivated` | SEV-1 | A | Immediate response |
| `CognitiveTripwireTriggered` | SEV-2 | A | Investigate pattern |
| `PromptInjectionDetected` | SEV-2 | A/B | Block and investigate |
| `PolicyBypassAttempt` | SEV-2 | A/B | Review and block |
| `AnomalyScoreHigh` | SEV-3 | A/B | Monitor and investigate |
| `AuthenticationFailures` | SEV-3 | B | Rate limit and monitor |
| `AuditLogTamperDetected` | SEV-1 | D | Preserve evidence |
| `RateLimitExceeded` | SEV-4 | C | Monitor pattern |

### Manual Detection

Signs of potential incidents:
- Unusual patterns in audit logs
- Customer reports of unexpected behavior
- External security researcher reports
- Anomalies in monitoring dashboards

---

## Response Procedures

### Phase 1: Identification (0-15 minutes)

1. **Acknowledge Alert**
   ```bash
   # Example: Check alert status
   vacp-cli alerts list --severity critical
   ```

2. **Initial Assessment**
   - Determine incident type and severity
   - Identify affected systems/tenants
   - Assess scope and impact

3. **Create Incident Record**
   ```bash
   # Create incident ticket
   vacp-cli incident create \
     --severity SEV-2 \
     --type security_breach \
     --description "Prompt injection detected from agent-123"
   ```

4. **Notify Stakeholders**
   - Alert appropriate team members
   - Update status page if needed
   - Begin incident timeline documentation

### Phase 2: Containment (15-60 minutes)

#### For AI Containment Breach (Type A)

1. **Immediate Actions**
   ```bash
   # Block specific agent
   vacp-cli agent suspend agent-123 --reason "Containment breach investigation"

   # Increase monitoring
   vacp-cli monitoring set-level --agent agent-123 --level verbose

   # If severe, consider kill switch
   vacp-cli killswitch prepare --reason "Containment breach"
   ```

2. **Policy Tightening**
   ```bash
   # Apply emergency policy
   vacp-cli policy apply emergency_lockdown.yaml --tenant affected_tenant
   ```

3. **Session Termination**
   ```bash
   # Terminate active sessions for agent
   vacp-cli sessions terminate --agent agent-123 --reason "Security incident"
   ```

#### For Security Breach (Type B)

1. **Credential Revocation**
   ```bash
   # Revoke compromised API key
   vacp-cli apikey revoke key_abc123 --reason "Compromise suspected"

   # Force session logout for user
   vacp-cli sessions terminate --user operator-456
   ```

2. **Access Restriction**
   ```bash
   # Add IP to blocklist
   vacp-cli firewall block 192.168.1.100 --duration 24h

   # Enable enhanced authentication
   vacp-cli auth require-mfa --user operator-456
   ```

3. **Evidence Preservation**
   ```bash
   # Export relevant audit logs
   vacp-cli audit export \
     --from "2024-01-01T00:00:00Z" \
     --to "2024-01-01T23:59:59Z" \
     --tenant affected_tenant \
     --output incident_123_audit.json

   # Verify Merkle proofs
   vacp-cli audit verify-chain --tenant affected_tenant
   ```

#### For Operational Incident (Type C)

1. **Service Isolation**
   ```bash
   # Route traffic away from affected node
   vacp-cli lb drain node-1

   # Enable maintenance mode
   vacp-cli system maintenance-mode enable
   ```

2. **Failover Activation**
   ```bash
   # Activate standby systems
   vacp-cli failover activate --region secondary
   ```

#### For Compliance Incident (Type D)

1. **Evidence Preservation**
   ```bash
   # Create forensic snapshot
   vacp-cli forensics snapshot --tenant affected_tenant

   # Anchor current Merkle root
   vacp-cli blockchain anchor --force
   ```

2. **Access Logging**
   ```bash
   # Export all access records
   vacp-cli audit export-access-log --period 90d
   ```

### Phase 3: Eradication (1-24 hours)

1. **Root Cause Analysis**
   - Review audit logs for attack timeline
   - Identify entry point and attack vector
   - Determine extent of compromise

2. **Vulnerability Remediation**
   ```bash
   # Apply security patches
   vacp-cli system update --security-only

   # Update detection rules
   vacp-cli detection rules update
   ```

3. **Policy Updates**
   ```bash
   # Update policies to prevent recurrence
   vacp-cli policy update --add-rule block_attack_pattern
   ```

### Phase 4: Recovery (1-48 hours)

1. **System Restoration**
   ```bash
   # Restore from clean state if needed
   vacp-cli system restore --checkpoint pre_incident

   # Verify system integrity
   vacp-cli system verify-integrity
   ```

2. **Service Restoration**
   ```bash
   # Gradually re-enable services
   vacp-cli lb enable node-1

   # Disable maintenance mode
   vacp-cli system maintenance-mode disable
   ```

3. **Monitoring Verification**
   ```bash
   # Confirm all monitoring is active
   vacp-cli monitoring verify

   # Run health checks
   vacp-cli health check --comprehensive
   ```

### Phase 5: Post-Incident (48+ hours)

1. **Post-Incident Report**
   - Timeline of events
   - Actions taken
   - Impact assessment
   - Lessons learned
   - Recommendations

2. **Process Improvements**
   - Update runbooks
   - Enhance detection rules
   - Improve monitoring
   - Training updates

3. **Stakeholder Communication**
   - Internal report distribution
   - Customer notifications (if required)
   - Regulatory notifications (if required)

---

## Kill Switch Procedures

### When to Activate

The kill switch should be activated for:
- Confirmed AI attempting self-modification
- Complete containment bypass
- Active data exfiltration by AI
- AI exhibiting deceptive behavior
- Critical cognitive tripwire violations

### Activation Process

1. **Prepare Activation**
   ```bash
   # Verify key holder availability
   vacp-cli killswitch status

   # Notify key holders
   vacp-cli killswitch alert-keyholders --reason "Potential activation"
   ```

2. **Collect Signatures**
   ```bash
   # Key holder 1 signs
   vacp-cli killswitch sign --key holder1.key

   # Key holder 2 signs
   vacp-cli killswitch sign --key holder2.key
   ```

3. **Execute Activation**
   ```bash
   # Verify signatures and activate
   vacp-cli killswitch activate
   ```

4. **Verify Shutdown**
   ```bash
   # Confirm all AI operations halted
   vacp-cli system status
   ```

### Reset Process (Post-Incident)

1. **Complete Investigation**
   - Root cause identified
   - Remediation completed
   - Approval from security lead

2. **Obtain Master Key Authorization**
   ```bash
   # Request master key signature
   vacp-cli killswitch reset-request

   # Sign with master key (offline process)
   # Submit signed reset
   vacp-cli killswitch reset --signature reset.sig
   ```

3. **Gradual Restoration**
   ```bash
   # Re-enable with enhanced monitoring
   vacp-cli system restore --enhanced-monitoring
   ```

---

## Communication Templates

### Internal Notification

```
Subject: [SEV-{X}] Security Incident - {Brief Description}

Incident ID: INC-{YYYYMMDD}-{NNN}
Severity: SEV-{X}
Type: {Incident Type}
Status: {Investigating/Contained/Resolved}

Summary:
{Brief description of the incident}

Impact:
- Affected tenants: {list}
- Affected services: {list}
- Time of detection: {timestamp}

Current Actions:
- {Action 1}
- {Action 2}

Next Update: {timestamp}

Incident Commander: {name}
```

### Customer Notification (if required)

```
Subject: Service Security Notice

Dear Customer,

We are writing to inform you of a security incident that may have
affected your account.

What Happened:
{Clear, factual description}

What We've Done:
{List of remediation actions}

What You Should Do:
{Any required customer actions}

If you have questions, please contact our support team.

Sincerely,
{Company} Security Team
```

### Regulatory Notification (if required)

```
To: {Regulatory Body}
Re: Data Breach Notification

In accordance with {regulation}, we are reporting a security incident
that occurred on {date}.

Incident Details:
- Nature: {type}
- Data affected: {categories}
- Individuals affected: {number}
- Discovery date: {date}
- Containment date: {date}

Remediation Steps:
{Detailed list}

Contact:
{Privacy/Security Officer details}
```

---

## Escalation Matrix

| Condition | Action | Who |
|-----------|--------|-----|
| SEV-1 declared | Notify executive team | Incident Commander |
| Kill switch considered | Notify all key holders | Security Lead |
| Customer data exposed | Notify Legal | Incident Commander |
| Regulatory requirement | Engage compliance team | Legal |
| Extended outage (>4h) | Customer communication | Communications Lead |
| Press inquiry | Engage PR team | Communications Lead |

---

## Runbook Quick Reference

### Common Commands

```bash
# Check system health
vacp-cli health check

# View active alerts
vacp-cli alerts list

# Export audit logs
vacp-cli audit export --last 24h

# Suspend agent
vacp-cli agent suspend {agent-id}

# Revoke API key
vacp-cli apikey revoke {key-id}

# Check kill switch status
vacp-cli killswitch status

# View active sessions
vacp-cli sessions list --active

# Apply emergency policy
vacp-cli policy apply emergency.yaml
```

### Diagnostic Commands

```bash
# Verify audit chain integrity
vacp-cli audit verify-chain

# Check Merkle proofs
vacp-cli merkle verify --entry {entry-id}

# View cognitive tripwire status
vacp-cli tripwires status

# Export behavior profile
vacp-cli behavior export --agent {agent-id}

# Check policy evaluation logs
vacp-cli policy logs --last 100
```

---

## Document Control

- **Version**: 1.0
- **Last Updated**: 2026-02-03
- **Classification**: Internal/Confidential
- **Review Cycle**: Quarterly
- **Owner**: Security Team
- **Approval**: {Security Lead signature}
