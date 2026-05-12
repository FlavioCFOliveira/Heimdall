# Native package signing — operator procedure

> Status: required configuration — operator action.
> Anchors: THREAT-013, ENV-025/026; Sprint 67 task #681.

Every Heimdall release ships a signed `.deb` (release-deb.yml) and a signed
`.rpm` (release-rpm.yml) **in addition to** the cosign keyless signature
applied to every binary by release.yml. The two layers exist for different
verification audiences:

| Layer | Verifier | Tool | What it proves |
|-------|----------|------|----------------|
| cosign keyless (sigstore) | Anyone | `cosign verify-blob` | The binary was built by this repo at this tag, recorded in a transparency log |
| debsigs origin | Debian/Ubuntu users | `dpkg-sig --verify`, `debsig-verify` | The .deb was signed by the project maintainer's GPG key |
| rpmsign | RHEL/Fedora/openSUSE users | `rpm -K`, `rpm --checksig` | The .rpm was signed by the project maintainer's GPG key |

The cosign layer is automatic and keyless. The debsigs+rpmsign layer needs
operator action to provision the signing key once.

## One-time key generation

Pick a strong RSA-4096 or Ed25519 GPG key, generate it offline, and store
the private material in an HSM or in a hardware token (YubiKey 5 series
supports OpenPGP cards). Do **not** keep the private key on the operator
workstation.

```sh
# Offline workstation
gpg --quick-generate-key "Heimdall release signing <release@heimdall.example>" rsa4096 sign,cert 5y

# Export the ASCII-armoured private key for GitHub Actions ingestion.
gpg --armor --export-secret-keys release@heimdall.example > heimdall-release-signing.asc

# Export the long fingerprint.
gpg --list-secret-keys --keyid-format=long \
  release@heimdall.example | awk '/^      / {print $1; exit}'
```

## Configure the GitHub repository secrets

Required (one-time):

- `PACKAGE_SIGNING_KEY` — paste the **contents** of `heimdall-release-signing.asc`
  into the secret (Settings → Secrets and variables → Actions → New
  repository secret).
- `PACKAGE_SIGNING_KEY_ID` — the long fingerprint (40 hex chars, no spaces).

Optional:

- `PACKAGE_SIGNING_KEY_PASSPHRASE` — only required if the GPG private key
  was generated with a passphrase. Strongly recommended that the production
  signing key **does** carry a passphrase, so a leaked repository secret
  alone cannot sign artefacts.

Verify the secrets are accepted (settings UI shows them as "Updated").

## Publish the public key

```sh
gpg --armor --export release@heimdall.example > heimdall-release-signing.pub
```

Upload `heimdall-release-signing.pub` to:

1. The project's GitHub Releases assets as `heimdall-release-signing.pub`
   (re-attach to every release for archival).
2. The project documentation site so end users can fetch it via HTTPS.
3. (Optional) An OpenPGP keyserver such as `keys.openpgp.org`.

## End-user verification

### Debian / Ubuntu

```sh
# Fetch and import the maintainer key.
curl -fsSL https://heimdall.example/keys/release.pub | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/heimdall.gpg

# Or, for debsig-verify (in-archive signature verification):
sudo apt install debsig-verify
sudo gpg --dearmor < heimdall-release-signing.pub | \
  sudo tee /usr/share/debsig/keyrings/<KEY-FINGERPRINT>/debsig.gpg

# Verify
debsig-verify heimdall_v1.2.0_amd64.deb
```

### RHEL / Fedora / openSUSE

```sh
sudo rpm --import https://heimdall.example/keys/release.pub
rpm -K heimdall-v1.2.0-1.x86_64.rpm
# Expect: "Header V4 RSA/SHA256 Signature, key ID <…>: OK"
```

## Operational hygiene

- **Rotate the signing key every 2 years** at minimum. When you rotate,
  publish the new public key alongside the old; do not retire the old key
  until every supported LTS release has been re-signed under the new key.
- **Audit every CI signing event**: the release-deb / release-rpm workflows
  emit a log line `Signed <package> with key <fingerprint>` per artefact.
  Forward these to the project SIEM (see `docs/process/incident-response.md`).
- **A leaked private key triggers a security-incident response**: pull
  every release that was signed under the leaked key, publish a revocation
  certificate (generated and kept offline at key creation time), and
  re-sign the supported release set under the new key.
- **Tag protection prevents accidental release without signing**: the
  release.yml Tier 4 gate (see `docs/process/release-protection.md`) fails
  closed if Tier 1+2+3 are not green on the tagged commit. The debsigs +
  rpmsign steps emit `::warning::` (not `::error::`) when the secret is
  unset so the bootstrap path is unblocked; once the operator has
  provisioned the key, flip the steps to fail-closed by removing the
  early-return in `release-{deb,rpm}.yml`.

## Why both cosign and debsigs/rpmsign

cosign keyless covers the binary; debsigs/rpmsign covers the native
package. Distribution users typically verify the package signature at
install time via apt/dpkg or rpm, not the binary via cosign. Carrying
both layers means:

- A user who installs via `apt install ./heimdall_*.deb` sees `dpkg-sig`
  output that the package is signed by the maintainer.
- A security researcher who pulls the binary from a release asset has
  the cosign transparency-log proof of provenance.

The two layers protect against different threats: cosign protects against
a rogue release-builder; debsigs/rpmsign protects against an
infrastructure compromise that publishes an unsigned tarball into a
mirror.
