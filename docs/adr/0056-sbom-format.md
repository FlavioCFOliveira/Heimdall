# ADR-0056: SBOM Format — CycloneDX JSON

**Status:** Accepted  
**Date:** 2026-04-27  
**References:** THREAT-014, ENG-071, ENG-074  
**Deciders:** Lead maintainer

---

## Context

THREAT-014 mandates a Software Bill of Materials (SBOM) for every Heimdall release.
ENG-071 wires SBOM generation into the Tier 3 nightly pipeline with delta-reporting;
ENG-074 wires SBOM publication into the Tier 4 release pipeline.

Two mature SBOM standards exist:

- **CycloneDX** (OWASP): JSON and XML formats; native support in the Rust ecosystem via
  `cargo cyclonedx`; strong tooling for supply-chain analysis (Dependency-Track, OWASP
  DefectDojo, Grype).
- **SPDX** (Linux Foundation): wider adoption in Linux distributions; native support via
  `cargo spdx`; preferred in the SBOM-sharing ecosystem (NTIA, EU CRA).

The choice affects:

1. Tooling available for generation from `Cargo.lock`.
2. Tooling for delta-reporting between releases.
3. Tooling for signing and attestation (cosign `--type`).
4. Downstream consumer expectations.

---

## Decision

**Use CycloneDX JSON** as the canonical SBOM format for Heimdall releases.

### Generation

```sh
# Install the cargo plugin
cargo install cargo-cyclonedx

# Generate SBOM for the workspace
cargo cyclonedx --format json --output-pattern heimdall-{package}-{version}.cdx.json
```

The output is a CycloneDX 1.6 JSON document describing all direct and transitive
dependencies, their versions, PURL identifiers, and licence expressions.

### Delta Reporting (Tier 3)

At Tier 3 nightly, the pipeline:

1. Generates the current SBOM.
2. Downloads the SBOM from the most recent published release (stored in the release assets).
3. Computes the diff using [`cyclonedx-cli diff`](https://github.com/CycloneDX/cyclonedx-cli):

```sh
cyclonedx-cli diff \
  --from-file heimdall-previous.cdx.json \
  --to-file heimdall-current.cdx.json \
  --output-format json \
  > sbom-delta.json
```

4. Attaches `sbom-delta.json` to the nightly run summary.
5. Fails the run if any new dependency with a known vulnerability appears in the delta.

### Signing (Tier 4)

```sh
cosign attest \
  --key gcpkms://... \
  --type cyclonedx \
  --predicate heimdall-VERSION.cdx.json \
  ghcr.io/flaviocfoliveira/heimdall:VERSION
```

### Publication (Tier 4)

The signed SBOM is published as a release asset alongside the binary artefacts:

```
heimdall-VERSION-linux-amd64.cdx.json
heimdall-VERSION-linux-amd64.cdx.json.sig
```

---

## Consequences

### Positive

- `cargo cyclonedx` is a mature, well-maintained tool with direct `Cargo.lock` support.
- CycloneDX has native cosign attestation support (`--type cyclonedx`).
- `cyclonedx-cli diff` provides structured delta reports suitable for CI integration.
- Dependency-Track and Grype can ingest CycloneDX JSON directly for vulnerability tracking.

### Negative

- SPDX is preferred by some Linux distribution maintainers (Fedora, Debian); consumers
  expecting SPDX will need to convert. The `cyclonedx-cli convert` command handles
  CycloneDX → SPDX conversion if required.
- CycloneDX 1.6 is not yet universally supported; older tools may require CycloneDX 1.4.
  Mitigation: pin `--spec-version 1.4` until tooling matures, then upgrade.

### Neutral

- Both formats meet the NTIA minimum elements for SBOM.
- SPDX support can be added as a secondary export format in a future sprint if downstream
  demand materialises.

---

## Alternatives Rejected

| Alternative | Reason for rejection |
|---|---|
| SPDX JSON | `cargo spdx` is less mature; cosign lacks native `--type spdx`; delta tooling is less capable |
| CycloneDX XML | JSON is more amenable to programmatic diff and CI tooling; XML adds no value here |
| No SBOM | Violates THREAT-014 and upcoming EU CRA requirements |
