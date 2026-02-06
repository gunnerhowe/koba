# HIPAA Business Associate Agreement Template

**IMPORTANT LEGAL NOTICE**: This template is provided for informational purposes only and does not constitute legal advice. Organizations should consult with qualified legal counsel before using this template. This document must be customized to meet specific organizational needs and comply with applicable laws and regulations.

---

## BUSINESS ASSOCIATE AGREEMENT

This Business Associate Agreement ("Agreement") is entered into as of [DATE] ("Effective Date")

**BETWEEN:**

**Covered Entity:**
[COVERED ENTITY NAME]
[ADDRESS]
("Covered Entity")

**AND**

**Business Associate:**
[BUSINESS ASSOCIATE NAME/VACP OPERATOR]
[ADDRESS]
("Business Associate")

(collectively, the "Parties")

---

## RECITALS

**WHEREAS**, Covered Entity is a covered entity as defined under the Health Insurance Portability and Accountability Act of 1996, as amended ("HIPAA"), and its implementing regulations at 45 C.F.R. Parts 160 and 164;

**WHEREAS**, Business Associate provides VACP (Verified AI Communication Protocol) services involving the processing of AI-generated communications that may include Protected Health Information ("PHI");

**WHEREAS**, the Parties wish to enter into this Agreement to comply with the requirements of HIPAA, the Health Information Technology for Economic and Clinical Health Act ("HITECH Act"), and applicable state privacy laws;

**NOW, THEREFORE**, in consideration of the mutual promises and covenants contained herein, and for other good and valuable consideration, the receipt and sufficiency of which are hereby acknowledged, the Parties agree as follows:

---

## ARTICLE 1: DEFINITIONS

**1.1** Terms used but not otherwise defined in this Agreement shall have the same meaning as those terms in the HIPAA Rules.

**1.2** "Breach" means the acquisition, access, use, or disclosure of PHI in a manner not permitted under HIPAA which compromises the security or privacy of the PHI.

**1.3** "Electronic Protected Health Information" or "ePHI" means PHI that is transmitted or maintained in electronic media.

**1.4** "PHI" means Protected Health Information as defined in 45 C.F.R. § 160.103.

**1.5** "Required by Law" means a mandate contained in law that compels an entity to make a use or disclosure of PHI.

**1.6** "Security Incident" means the attempted or successful unauthorized access, use, disclosure, modification, or destruction of information or interference with system operations in an information system.

**1.7** "VACP Services" means the Verified AI Communication Protocol services provided by Business Associate, including but not limited to:
- Cryptographic signing of AI-generated messages
- Audit logging and verification
- Blockchain anchoring of communications
- AI agent authentication and authorization

---

## ARTICLE 2: OBLIGATIONS OF BUSINESS ASSOCIATE

### 2.1 Permitted Uses and Disclosures

Business Associate agrees to:

(a) Use and disclose PHI only as permitted by this Agreement or as Required by Law;

(b) Not use or disclose PHI in a manner that would violate Subpart E of 45 C.F.R. Part 164 if done by Covered Entity;

(c) Use PHI only for the following purposes:
- Providing VACP Services to process and secure AI-generated communications containing PHI
- Maintaining audit logs and verification records
- Technical support and system maintenance
- As otherwise permitted under this Agreement

### 2.2 Safeguards

Business Associate agrees to:

(a) Implement administrative, physical, and technical safeguards that reasonably and appropriately protect the confidentiality, integrity, and availability of ePHI;

(b) Comply with the applicable requirements of 45 C.F.R. Part 164, Subpart C (Security Rule);

(c) Implement and maintain the following specific security measures:

**Administrative Safeguards:**
- Designated security officer responsible for HIPAA compliance
- Workforce security training and awareness programs
- Access authorization and termination procedures
- Security incident response and reporting procedures
- Regular risk assessments (at least annually)

**Physical Safeguards:**
- Facility access controls
- Workstation and device security policies
- Device and media controls

**Technical Safeguards:**
- Access controls (unique user identification, automatic logoff, encryption)
- Audit controls (comprehensive logging of all PHI access)
- Integrity controls (cryptographic verification of data)
- Transmission security (encryption in transit using TLS 1.3 or higher)

### 2.3 VACP-Specific Security Controls

Business Associate specifically agrees to implement and maintain:

(a) **Cryptographic Protections:**
- Ed25519 digital signatures for all messages containing PHI
- AES-256 encryption for PHI at rest
- HKDF-based key derivation with proper key hierarchy
- Secure key storage using hardware security modules (HSMs) where available

(b) **Audit Trail:**
- Immutable audit logs for all PHI access and processing
- Blockchain anchoring of audit records for tamper-evidence
- Minimum 6-year retention of audit logs per HIPAA requirements
- Cryptographic verification of audit log integrity

(c) **Access Controls:**
- Multi-factor authentication for administrative access
- Role-based access control (RBAC) with least privilege
- Automatic session termination after [15] minutes of inactivity
- Token-based authentication for AI agents with time-limited validity

(d) **Kill Switch Capability:**
- Emergency shutdown capability for all AI agent operations
- M-of-N multi-signature requirement for kill switch activation
- Dead man's switch for automatic shutdown if oversight fails

### 2.4 Subcontractors

Business Associate agrees to:

(a) Ensure that any subcontractors that create, receive, maintain, or transmit PHI on behalf of Business Associate agree to the same restrictions, conditions, and requirements that apply to Business Associate under this Agreement;

(b) Maintain a list of all subcontractors with access to PHI;

(c) Notify Covered Entity of any new subcontractor engagement involving PHI access;

(d) Current subcontractors with PHI access:
- Cloud infrastructure provider: [PROVIDER NAME]
- Blockchain anchoring service: [PROVIDER NAME]
- [Additional subcontractors as applicable]

### 2.5 Reporting

Business Associate agrees to:

(a) Report to Covered Entity any use or disclosure of PHI not permitted by this Agreement within [72 hours / as soon as reasonably practicable] of discovery;

(b) Report any Security Incident within [24 hours] of discovery;

(c) Report any Breach of Unsecured PHI within [24 hours] of discovery, including:
- Nature of the Breach
- Types of PHI involved
- Identification of individuals affected
- Steps being taken to mitigate harm
- Steps being taken to prevent future occurrences

(d) Provide Covered Entity with the following regular reports:
- Monthly security metrics summary
- Quarterly compliance assessment
- Annual risk assessment results

### 2.6 Access and Amendment

Business Associate agrees to:

(a) Make PHI available to Covered Entity as necessary to fulfill Covered Entity's obligations under 45 C.F.R. § 164.524 (individual right of access);

(b) Make PHI available for amendment and incorporate amendments as directed by Covered Entity pursuant to 45 C.F.R. § 164.526;

(c) Provide access to PHI within [30 days] of request;

(d) Maintain audit logs enabling identification of all disclosures of PHI.

### 2.7 Accounting of Disclosures

Business Associate agrees to:

(a) Document disclosures of PHI as would be required for Covered Entity to respond to a request for accounting of disclosures under 45 C.F.R. § 164.528;

(b) Maintain records of disclosures for a minimum of [6 years];

(c) Provide such information to Covered Entity within [30 days] of request.

### 2.8 Availability of Records

Business Associate agrees to make its internal practices, books, and records relating to the use and disclosure of PHI available to the Secretary of the Department of Health and Human Services for purposes of determining compliance.

---

## ARTICLE 3: OBLIGATIONS OF COVERED ENTITY

### 3.1 Covered Entity agrees to:

(a) Notify Business Associate of any limitations in its Notice of Privacy Practices that may affect Business Associate's use or disclosure of PHI;

(b) Notify Business Associate of any changes in, or revocation of, authorizations by individuals;

(c) Notify Business Associate of any restrictions on the use or disclosure of PHI that Covered Entity has agreed to;

(d) Not request Business Associate to use or disclose PHI in any manner that would not be permissible under HIPAA if done by Covered Entity.

---

## ARTICLE 4: TERM AND TERMINATION

### 4.1 Term

This Agreement shall be effective as of the Effective Date and shall remain in effect until terminated as provided herein.

### 4.2 Termination for Cause

Either Party may terminate this Agreement immediately if it determines that the other Party has violated a material term of this Agreement.

### 4.3 Effect of Termination

Upon termination of this Agreement:

(a) Business Associate shall return or destroy all PHI in its possession, if feasible;

(b) If return or destruction is not feasible, Business Associate shall:
- Extend the protections of this Agreement to such PHI
- Limit further uses and disclosures to those purposes that make return or destruction infeasible
- Continue to comply with all terms of this Agreement

(c) Business Associate shall retain audit logs as required by HIPAA (minimum 6 years);

(d) Business Associate shall provide certification of destruction if requested.

---

## ARTICLE 5: MISCELLANEOUS

### 5.1 Amendment

This Agreement may not be modified except by written agreement signed by both Parties. The Parties agree to amend this Agreement as necessary to comply with changes in HIPAA.

### 5.2 Survival

The obligations of Business Associate under Article 4.3 shall survive termination of this Agreement.

### 5.3 Interpretation

Any ambiguity in this Agreement shall be resolved in favor of a meaning that permits the Parties to comply with HIPAA.

### 5.4 No Third-Party Beneficiaries

Nothing in this Agreement shall confer upon any person other than the Parties and their respective successors or assigns any rights, remedies, obligations, or liabilities whatsoever.

### 5.5 Governing Law

This Agreement shall be governed by and construed in accordance with the laws of [STATE], without regard to its conflict of laws principles.

### 5.6 Entire Agreement

This Agreement, together with any exhibits, constitutes the entire agreement between the Parties with respect to the subject matter hereof.

### 5.7 Notices

All notices under this Agreement shall be in writing and sent to:

**For Covered Entity:**
[NAME]
[TITLE]
[ADDRESS]
[EMAIL]

**For Business Associate:**
[NAME]
[TITLE]
[ADDRESS]
[EMAIL]

---

## SIGNATURES

**COVERED ENTITY:**

By: _________________________________

Name: _______________________________

Title: _______________________________

Date: _______________________________


**BUSINESS ASSOCIATE:**

By: _________________________________

Name: _______________________________

Title: _______________________________

Date: _______________________________

---

## EXHIBIT A: VACP TECHNICAL SPECIFICATIONS

### A.1 Security Architecture

The VACP system implements the following security architecture:

1. **Message Security**
   - All messages containing PHI are cryptographically signed using Ed25519
   - Message integrity is verified before processing
   - Messages are encrypted in transit using TLS 1.3

2. **Key Management**
   - Master keys are stored in HSM or vault
   - Tenant-specific keys are derived using HKDF
   - Key rotation is performed automatically

3. **Audit Logging**
   - All PHI access is logged with timestamps
   - Logs are cryptographically signed
   - Logs are anchored to blockchain for immutability

### A.2 Data Retention Schedule

| Data Type | Retention Period | Destruction Method |
|-----------|-----------------|-------------------|
| Audit Logs | 6 years minimum | Secure deletion |
| Message Content | Per agreement | Cryptographic erasure |
| Access Logs | 6 years minimum | Secure deletion |
| Configuration | Duration of service | Secure deletion |

### A.3 Incident Response

1. **Detection** (0-1 hour): Automated monitoring and alerting
2. **Analysis** (1-4 hours): Security team assessment
3. **Containment** (4-8 hours): Isolation and mitigation
4. **Notification** (24 hours): Covered Entity notification
5. **Recovery** (As needed): System restoration
6. **Post-Incident** (30 days): Review and improvements

---

## EXHIBIT B: COMPLIANCE ATTESTATIONS

### B.1 Annual Attestation

Business Associate shall provide Covered Entity with an annual attestation certifying:

- [ ] Implementation of required safeguards
- [ ] Completion of workforce training
- [ ] Completion of annual risk assessment
- [ ] No unreported security incidents
- [ ] Subcontractor compliance verification
- [ ] Audit log integrity verification

### B.2 Certification Date: _______________

Certified By: _________________________

Title: _______________________________

---

*Document Version: 1.0*
*Last Updated: [DATE]*
*Review Schedule: Annual*
