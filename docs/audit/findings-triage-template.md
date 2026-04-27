# Audit Findings Triage

**Audit firm:** [TBD]  
**Audit window:** [TBD]  
**Triage reviewed by:** [maintainer], [auditor]  
**Status:** Template — to be populated after audit report is received

---

## Severity Classification

Severity is assigned per CVSS v3.1 base score:

| Severity | CVSS range | SLA |
|---|---|---|
| Critical | 9.0–10.0 | Fix + re-review before GA tag |
| High | 7.0–8.9 | Fix + re-review before GA tag |
| Medium | 4.0–6.9 | Fix before GA; tracked issue |
| Low | 0.1–3.9 | Tracked issue; fix in next minor |
| Informational | N/A | Noted; no mandatory fix |

---

## Attack Class Taxonomy

Each finding must be assigned one attack class:

- `off-path`: Attacker cannot observe DNS traffic (cache poisoning, spoofing).
- `on-path`: Attacker is a network adversary (MitM, traffic interception).
- `upstream-peer`: Attacker controls an upstream resolver or authoritative server.
- `adversarial-zone-operator`: Attacker controls a DNS zone served by Heimdall.
- `volumetric-dos`: Attacker sends high query volumes (amplification, RRL bypass).
- `local-privilege`: Attacker has code execution on the same host.
- `supply-chain`: Attacker compromises a dependency or build artefact.

---

## Findings

<!-- Template for one finding entry — copy for each finding -->

### FINDING-001: [Title]

| Field | Value |
|---|---|
| ID | FINDING-001 |
| Severity | [Critical / High / Medium / Low / Informational] |
| CVSS v3.1 | [score] / [vector string] |
| CWE | [CWE-NNN: Name] |
| Attack class | [see taxonomy above] |
| THREAT-* anchor | [THREAT-NNN] |
| Status | [Open / Fix in progress / Fixed / Accepted risk] |
| Fix PR | [#NNN or TBD] |

**Description:**  
[Full description of the vulnerability, affected code paths, and conditions under which
it is exploitable.]

**Reproduction steps:**  
1. [Step 1]
2. [Step 2]

**Proposed mitigation:**  
[Recommended fix, with references to relevant RFCs or prior art.]

**Assigned to:** [GitHub handle]  
**Target fix release:** [vX.Y.Z or sprint milestone]

---

<!-- Add additional FINDING-NNN entries as the audit report is received -->

---

## Summary Table

| ID | Title | Severity | Status | Fix PR |
|---|---|---|---|---|
| FINDING-001 | [TBD] | [TBD] | Open | TBD |
