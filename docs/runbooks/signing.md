# Signing Key Management Runbook

**References:** THREAT-013, ENG-073  
**Owner:** Release engineering  
**Review cadence:** Annual, or immediately after any key incident

---

## 1. Overview

Every Heimdall release artefact (binary, container image, SBOM) must be signed with a
project-controlled key so that downstream consumers can verify authenticity and integrity.
This runbook describes the full key lifecycle: generation, storage, signing, rotation, and
revocation.

The signing tool is [cosign](https://github.com/sigstore/cosign) (Sigstore).  
Long-term keys are backed by a hardware security module (HSM) or a cloud KMS where
available; software keys are used only in environments that cannot support hardware roots.

---

## 2. Key Types and Roles

| Key type | Tool | Storage | Purpose |
|---|---|---|---|
| Release signing key | cosign (ECDSA P-256) | Cloud KMS or HSM | Sign release binaries and container images |
| SBOM signing key | cosign (ECDSA P-256) | Same KMS slot | Sign CycloneDX SBOM artefacts |
| Transparency log | Sigstore Rekor | Public Rekor instance | Append-only audit trail of signing events |

A single KMS key may cover both release and SBOM signing; splitting them is recommended
when the release pipeline is operated by different personnel than the SBOM pipeline.

---

## 3. Key Generation

### 3.1 Hardware-backed (preferred)

```sh
# Generate a key in the cloud KMS provider (example: GCP Cloud KMS)
gcloud kms keyrings create heimdall-release --location global
gcloud kms keys create signing \
  --location global \
  --keyring heimdall-release \
  --purpose asymmetric-signing \
  --default-algorithm ec-sign-p256-sha256 \
  --protection-level hsm

# Export the public key for verification bundles
gcloud kms keys versions get-public-key 1 \
  --location global \
  --keyring heimdall-release \
  --key signing \
  --output-file heimdall-release.pub
```

The private key material never leaves the KMS; cosign uses the KMS API for every
signing operation.

### 3.2 Software key (fallback)

Use only when a KMS is unavailable (e.g., air-gapped staging environment).

```sh
cosign generate-key-pair
# Produces: cosign.key (encrypted) + cosign.pub
# Store cosign.key in a secrets manager (Vault, AWS Secrets Manager, etc.)
# Commit cosign.pub to the repository for verification
```

The passphrase protecting `cosign.key` must be stored separately from the key file, in a
different secrets manager or vault.

---

## 4. Storage Requirements

| Asset | Storage location | Access control |
|---|---|---|
| KMS private key | Cloud KMS / HSM | IAM role restricted to CI release pipeline service account |
| Software key file | Secrets manager | Read-only for release pipeline; no human read access |
| Passphrase | Separate secrets manager path | Break-glass access only; dual-authorisation required |
| Public key (`cosign.pub`) | Repository root + release page | Public |

All access to private key material must be logged and audited.  
No private key material may appear in CI logs, artefact archives, or container images.

---

## 5. Signing a Release

The signing step runs as part of the Tier 4 release pipeline, after all Tier 3 checks pass.

### 5.1 Binary signing

```sh
# KMS-backed (preferred)
cosign sign-blob \
  --key gcpkms://projects/PROJECT/locations/global/keyRings/heimdall-release/cryptoKeys/signing \
  --output-signature heimdall-linux-amd64.sig \
  heimdall-linux-amd64

# Software key (fallback)
cosign sign-blob \
  --key cosign.key \
  --output-signature heimdall-linux-amd64.sig \
  heimdall-linux-amd64
```

### 5.2 Container image signing

```sh
cosign sign \
  --key gcpkms://projects/PROJECT/locations/global/keyRings/heimdall-release/cryptoKeys/signing \
  ghcr.io/flaviocfoliveira/heimdall:VERSION
```

### 5.3 SBOM signing

```sh
cosign attest \
  --key gcpkms://projects/PROJECT/locations/global/keyRings/heimdall-release/cryptoKeys/signing \
  --type cyclonedx \
  --predicate heimdall-VERSION.cdx.json \
  ghcr.io/flaviocfoliveira/heimdall:VERSION
```

### 5.4 Verification (downstream consumer)

```sh
cosign verify-blob \
  --key cosign.pub \
  --signature heimdall-linux-amd64.sig \
  heimdall-linux-amd64

cosign verify \
  --key cosign.pub \
  ghcr.io/flaviocfoliveira/heimdall:VERSION
```

---

## 6. Rotation

Rotate the signing key:

- **Annually** as a scheduled event.
- **Immediately** if any of the following occur:
  - Evidence or suspicion of private key compromise.
  - Departure of any maintainer with historical access to the key material.
  - A security advisory affecting the signing algorithm or tool.

### 6.1 Rotation procedure

1. Generate a new key pair following §3 (new KMS version or new software key).
2. Publish the new public key in the repository alongside the old one.
3. Sign the transition announcement with the old key and the new key.
4. Update the CI pipeline to use the new key for all subsequent releases.
5. Retain the old public key for verification of historical releases for at least 2 years.
6. Schedule revocation of the old key after the retention period (§7).
7. Update the `cosign.pub` symlink or canonical path to point to the new public key.
8. Perform a dry-run signing of a staging artefact with the new key and verify it.
9. Record the rotation in the project changelog and SECURITY.md.

### 6.2 Dry-run test

Before every rotation goes live, execute:

```sh
# Sign a test artefact with the new key
echo "heimdall rotation test $(date -u +%Y-%m-%dT%H:%M:%SZ)" > rotation-test.txt
cosign sign-blob --key <new-key> --output-signature rotation-test.sig rotation-test.txt

# Verify with the new public key
cosign verify-blob --key <new-pub> --signature rotation-test.sig rotation-test.txt
echo "Rotation dry-run: PASS"
```

This must succeed before the new key is promoted to production use.

---

## 7. Revocation

Sigstore does not support traditional CRL-style revocation.  Revocation is handled by:

1. **Removing the public key** from the canonical path in the repository.
2. **Publishing a signed revocation notice** (signed with the new key if the old key is
   still accessible, or by a quorum of maintainers otherwise) in SECURITY.md.
3. **Notifying downstream consumers** via the project's security mailing list and
   GitHub Security Advisory.
4. **Expiring the KMS key version** (cloud KMS providers support disabling or destroying
   key versions).

There is no automated mechanism to invalidate past signatures on Rekor; the revocation
notice is the authoritative signal.

---

## 8. Audit and Monitoring

- All Rekor entries for the project's signing key are indexed by the Sigstore transparency
  log and can be queried with `rekor-cli search --email maintainer@example.com`.
- The CI pipeline must log the Rekor entry URL for every signing operation.
- A monthly audit of Rekor entries must be performed to detect unexpected signing events.
- Any unexpected entry triggers the incident response procedure in SECURITY.md.

---

## 9. Contacts and Escalation

| Role | Responsibility |
|---|---|
| Release engineer on duty | Executes routine signing and dry-runs |
| Lead maintainer | Approves rotations, reviews Rekor audit |
| Security team | Incident response for suspected compromise |

For key compromise incidents, follow the incident response checklist in SECURITY.md §Incident-Response.
