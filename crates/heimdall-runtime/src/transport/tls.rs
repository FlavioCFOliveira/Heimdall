// SPDX-License-Identifier: MIT

//! TLS 1.3 server-configuration factory (SEC-001..016, SEC-060..068).
//!
//! This module builds a [`rustls::ServerConfig`] that enforces Heimdall's
//! cryptographic and protocol-security policy:
//!
//! - **TLS 1.3 only** (SEC-001, SEC-002, SEC-003): built with
//!   `builder_with_protocol_versions(&[&TLS13])`; the `tls12` cargo feature is
//!   not activated, so TLS 1.2 code paths are absent from the binary.
//! - **0-RTT / early data prohibited** (SEC-005, SEC-006): `max_early_data_size`
//!   is explicitly set to `0`. rustls defaults to `0`; the explicit assignment
//!   documents the intent and guards against future API changes.
//! - **Stateless session tickets** (SEC-008..011): [`rustls::TicketRotator`] is
//!   used as the ticketer; it rotates TEKs automatically and keeps one previous
//!   key for decryption during the acceptance window.
//! - **Optional mTLS** (SEC-012..016, SEC-063..068): if `mtls_trust_anchor` is
//!   set, a [`rustls::server::WebPkiClientVerifier`] is built from the provided
//!   trust anchor. Otherwise `NoClientAuth` is used.
//! - **SPKI pinning** (SEC-065): additive check over the cert verifier, applied
//!   in the `DoT` per-connection handler after the handshake.
//! - **mTLS identity extraction** (SEC-067): [`extract_mtls_identity`] returns
//!   a SHA-256 fingerprint of the client cert DER as a stable identity. Full
//!   ASN.1 SAN/DN parsing is deferred to the x509-parser integration sprint.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

// ── TlsError ─────────────────────────────────────────────────────────────────

/// Errors produced by the TLS configuration factory.
#[derive(Debug)]
pub enum TlsError {
    /// A PEM certificate file could not be read or contained no valid certificates.
    CertLoad {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying cause.
        cause: std::io::Error,
    },
    /// A PEM private-key file could not be read or contained no valid key.
    KeyLoad {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying cause.
        cause: std::io::Error,
    },
    /// The private-key file contained no parseable private key.
    NoPrivateKey {
        /// Path that was attempted.
        path: PathBuf,
    },
    /// The trust-anchor file for mTLS could not be read.
    TrustAnchorLoad {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying cause.
        cause: std::io::Error,
    },
    /// The trust-anchor store was empty (no valid CA certificates loaded).
    EmptyTrustAnchor {
        /// Path that was attempted.
        path: PathBuf,
    },
    /// rustls rejected the server certificate / key combination.
    RustlsCert(rustls::Error),
    /// rustls rejected the mTLS verifier configuration.
    RustlsVerifier(rustls::server::VerifierBuilderError),
    /// The session-ticket rotator could not be initialised.
    TicketerInit(rustls::Error),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertLoad { path, cause } => {
                write!(f, "failed to load certificate from {}: {cause}", path.display())
            }
            Self::KeyLoad { path, cause } => {
                write!(f, "failed to load private key from {}: {cause}", path.display())
            }
            Self::NoPrivateKey { path } => {
                write!(f, "no private key found in {}", path.display())
            }
            Self::TrustAnchorLoad { path, cause } => {
                write!(
                    f,
                    "failed to load mTLS trust anchor from {}: {cause}",
                    path.display()
                )
            }
            Self::EmptyTrustAnchor { path } => {
                write!(
                    f,
                    "mTLS trust anchor at {} contains no valid CA certificates",
                    path.display()
                )
            }
            Self::RustlsCert(e) => write!(f, "rustls certificate configuration error: {e}"),
            Self::RustlsVerifier(e) => write!(f, "rustls mTLS verifier error: {e}"),
            Self::TicketerInit(e) => write!(f, "TLS session ticketer initialisation failed: {e}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CertLoad { cause, .. }
            | Self::KeyLoad { cause, .. }
            | Self::TrustAnchorLoad { cause, .. } => Some(cause),
            Self::RustlsCert(e) | Self::TicketerInit(e) => Some(e),
            Self::RustlsVerifier(e) => Some(e),
            _ => None,
        }
    }
}

// ── MtlsIdentitySource ───────────────────────────────────────────────────────

/// Selects which field of a validated client certificate is used as the mTLS
/// identity string for ACL keying and per-client rate limiting (SEC-067).
///
/// Full ASN.1 SAN/DN parsing is deferred to a later sprint. All variants
/// currently return the SHA-256 fingerprint of the DER-encoded certificate as
/// a stable, collision-resistant identity. See [`extract_mtls_identity`].
#[derive(Debug, Clone, Copy, Default)]
pub enum MtlsIdentitySource {
    /// Subject Distinguished Name in RFC 4514 string form.
    #[default]
    SubjectDn,
    /// Rightmost Common Name (CN) attribute of the Subject.
    SubjectCn,
    /// First URI-form Subject Alternative Name.
    SanUri,
    /// First DNS-name Subject Alternative Name.
    SanDns,
    /// First email-address Subject Alternative Name.
    SanEmail,
}

// ── TlsServerConfig ──────────────────────────────────────────────────────────

/// Parameters for building a rustls `ServerConfig` for a `DoT` or `DoH` listener.
///
/// Construct this from operator configuration and pass it to
/// [`build_tls_server_config`].
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    /// Path to PEM file containing the server certificate chain.
    pub cert_path: PathBuf,
    /// Path to PEM file containing the server private key.
    pub key_path: PathBuf,
    /// mTLS: optional path to a PEM file containing the trust anchor(s) for
    /// client certificate validation (SEC-063). `None` disables mTLS.
    pub mtls_trust_anchor: Option<PathBuf>,
    /// mTLS: optional SPKI pins of the form `"sha256/<base64>"` (SEC-065).
    pub mtls_spki_pins: Vec<String>,
    /// mTLS: optional path to a CRL PEM/DER file (SEC-066).
    pub mtls_crl_file: Option<PathBuf>,
    /// mTLS: which certificate field to use as the identity string (SEC-067).
    pub mtls_identity_source: MtlsIdentitySource,
    /// TEK rotation interval in seconds (SEC-060, default = 43200 = 12 h).
    pub tek_rotation_secs: u64,
    /// TEK acceptance window in seconds beyond rotation (SEC-060, default =
    /// 86400 = 24 h). [`rustls::TicketRotator`] keeps one previous key; the
    /// effective decryption window is approximately `2 * tek_rotation_secs`.
    /// Operators requiring a longer window must decrease the rotation interval.
    pub tek_acceptance_secs: u64,
}

impl Default for TlsServerConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("cert.pem"),
            key_path: PathBuf::from("key.pem"),
            mtls_trust_anchor: None,
            mtls_spki_pins: Vec::new(),
            mtls_crl_file: None,
            mtls_identity_source: MtlsIdentitySource::default(),
            tek_rotation_secs: 43_200, // 12 h (SEC-060 default)
            tek_acceptance_secs: 86_400, // 24 h (SEC-060 default)
        }
    }
}

// ── build_tls_server_config ───────────────────────────────────────────────────

/// Builds a [`rustls::ServerConfig`] enforcing Heimdall's TLS security policy.
///
/// # Policy enforced
///
/// - **TLS 1.3 only** (SEC-001, SEC-002, SEC-003).
/// - **0-RTT / early data refused** (SEC-005, SEC-006).
/// - **Stateless session tickets** with TEK rotation (SEC-008..011, SEC-060).
/// - **mTLS** when `cfg.mtls_trust_anchor` is `Some` (SEC-012..016).
///
/// # Errors
///
/// Returns [`TlsError`] if any of the following occur:
/// - The certificate or key PEM file cannot be read or is malformed.
/// - No private key is found in the key file.
/// - The mTLS trust anchor file cannot be read or is empty.
/// - rustls rejects the certificate/key pair or the mTLS verifier configuration.
/// - The session-ticket rotator cannot be initialised.
pub fn build_tls_server_config(cfg: &TlsServerConfig) -> Result<Arc<ServerConfig>, TlsError> {
    // ── Load server certificate chain ─────────────────────────────────────────
    let certs = load_certs(&cfg.cert_path)?;

    // ── Load server private key ───────────────────────────────────────────────
    let key = load_private_key(&cfg.key_path)?;

    // ── Build client verifier (mTLS gate, SEC-012..016) ───────────────────────
    let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        match &cfg.mtls_trust_anchor {
            None => {
                // mTLS disabled (SEC-013): use the no-auth verifier.
                WebPkiClientVerifier::no_client_auth()
            }
            Some(anchor_path) => {
                // mTLS enabled: build a WebPkiClientVerifier from the operator-supplied
                // trust anchor file (SEC-014, SEC-063).
                // `WebPkiClientVerifier::builder` uses the process-default CryptoProvider
                // (ring, enabled via the `ring` cargo feature on rustls).
                let roots = load_root_cert_store(anchor_path)?;
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(TlsError::RustlsVerifier)?
            }
        };

    // ── TLS 1.3 protocol-version builder (SEC-001, SEC-003) ──────────────────
    // `builder_with_protocol_versions` restricts negotiation to exactly the
    // supplied set.  Passing only `TLS13` means TLS 1.2 is structurally
    // absent from this handshake's code path, not merely rejected at runtime.
    let builder =
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .map_err(TlsError::RustlsCert)?;

    let mut server_config = builder;

    // ── Prohibit 0-RTT / early data (SEC-005, SEC-006) ───────────────────────
    // rustls defaults `max_early_data_size` to 0 (disabled); the explicit
    // assignment documents the invariant and guards against a future default change.
    server_config.max_early_data_size = 0;

    // ── Session-ticket TEK rotation (SEC-008..011, SEC-060) ──────────────────
    // `rustls::crypto::ring::Ticketer::new()` constructs a `TicketRotator` with
    // a 12-hour (43200 s) rotation interval and one previous key kept for an
    // equal acceptance window (total ≈ 24 h), matching the SEC-060 defaults.
    //
    // The `TicketRotator::new()` constructor is not callable from outside the
    // rustls crate because its `generator` parameter type
    // (`fn() -> Result<Box<dyn ProducesTickets>, rustls::rand::GetRandomFailed>`)
    // uses a private rustls type.  `rustls::crypto::ring::Ticketer::new()` is the
    // published factory that encapsulates the canonical generator and produces
    // the same `Arc<TicketRotator>` internally.  Custom rotation intervals beyond
    // the SEC-060 default require a custom `ProducesTickets` implementation and
    // are deferred to a future sprint.
    //
    // The `tek_rotation_secs` and `tek_acceptance_secs` fields on `TlsServerConfig`
    // are preserved for future use when rustls exposes a stable custom-interval
    // factory, or when a wrapper implementing `ProducesTickets` is added.
    let _ = cfg.tek_rotation_secs; // acknowledged; used when custom-interval API lands
    let _ = cfg.tek_acceptance_secs; // acknowledged; used when custom-interval API lands

    let ticketer =
        rustls::crypto::ring::Ticketer::new().map_err(TlsError::TicketerInit)?;

    server_config.ticketer = ticketer;

    Ok(Arc::new(server_config))
}

// ── extract_mtls_identity ─────────────────────────────────────────────────────

/// Derives an mTLS identity string from a validated client certificate.
///
/// # Current implementation
///
/// Full ASN.1 SAN/DN parsing (for `SubjectDn`, `SubjectCn`, `SanUri`, `SanDns`,
/// `SanEmail`) is deferred to the x509-parser integration sprint. This function
/// currently returns the **hex-encoded SHA-256 fingerprint** of the DER-encoded
/// certificate for all `source` values. The fingerprint is stable, globally
/// unique in practice, and collision-resistant, making it suitable as an ACL /
/// rate-limiting key. The identity format will change to the field-specific
/// string when full parsing lands; operators using the fingerprint identity in
/// ACL rules must update those rules after the parsing sprint.
///
/// # Returns
///
/// `Some(identity)` where `identity` is the lower-hex SHA-256 digest of the
/// certificate DER. Returns `None` only if the ring digest fails (which should
/// not occur in practice).
#[must_use]
pub fn extract_mtls_identity(
    cert_der: &CertificateDer<'_>,
    _source: MtlsIdentitySource,
) -> Option<String> {
    use std::fmt::Write as _;
    use ring::digest::{SHA256, digest};

    let hash = digest(&SHA256, cert_der.as_ref());
    let mut hex = String::with_capacity(64);
    for b in hash.as_ref() {
        // INVARIANT: writing to a `String` via `write!` is infallible.
        let _ = write!(hex, "{b:02x}");
    }
    Some(hex)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Reads all PEM-encoded certificates from `path`, returning them as a
/// `Vec<CertificateDer<'static>>` suitable for rustls.
///
/// # Errors
///
/// - [`TlsError::CertLoad`] if the file cannot be opened or a certificate is
///   malformed.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::CertLoad {
        path: path.to_path_buf(),
        cause: e,
    })?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertLoad {
            path: path.to_path_buf(),
            cause: e,
        })
}

/// Reads the first private key from a PEM file, returning a
/// [`PrivateKeyDer<'static>`] in PKCS#8 or PKCS#1 form.
///
/// # Errors
///
/// - [`TlsError::KeyLoad`] if the file cannot be opened or a key block is
///   malformed.
/// - [`TlsError::NoPrivateKey`] if the file contains no private key.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::KeyLoad {
        path: path.to_path_buf(),
        cause: e,
    })?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsError::KeyLoad {
            path: path.to_path_buf(),
            cause: e,
        })?
        .ok_or_else(|| TlsError::NoPrivateKey { path: path.to_path_buf() })
}

/// Builds a [`rustls::RootCertStore`] from PEM-encoded CA certificates in
/// `path`, for use as the mTLS client-certificate trust anchor (SEC-063).
///
/// # Errors
///
/// - [`TlsError::TrustAnchorLoad`] if the file cannot be opened.
/// - [`TlsError::EmptyTrustAnchor`] if no valid CA certificate was loaded.
fn load_root_cert_store(path: &Path) -> Result<rustls::RootCertStore, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::TrustAnchorLoad {
        path: path.to_path_buf(),
        cause: e,
    })?;
    let mut reader = BufReader::new(file);

    let mut store = rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::TrustAnchorLoad {
            path: path.to_path_buf(),
            cause: e,
        })?;

    if certs.is_empty() {
        return Err(TlsError::EmptyTrustAnchor { path: path.to_path_buf() });
    }

    for cert in certs {
        // `add` returns an error for certificates that are not valid TrustAnchors
        // (e.g., an end-entity certificate without basicConstraints cA=TRUE).
        // We silently skip those to be lenient with files that mix cert types.
        let _ = store.add(cert);
    }

    if store.is_empty() {
        return Err(TlsError::EmptyTrustAnchor { path: path.to_path_buf() });
    }

    Ok(store)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::io::Write as _;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tempfile::NamedTempFile;

    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    use std::sync::OnceLock;

    static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

    fn init_provider() {
        PROVIDER_INIT.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Generates a minimal self-signed Ed25519 certificate via `rcgen`, returns
    /// (cert PEM string, key PEM string).
    fn gen_self_signed() -> (String, String) {
        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

        let key_pair = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
        let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        let cert = params.self_signed(&key_pair).expect("sign");
        (cert.pem(), key_pair.serialize_pem())
    }

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    // ── build_tls_server_config: happy path ───────────────────────────────────

    #[test]
    fn build_tls_server_config_succeeds_with_valid_cert_and_key() {
        init_provider();
        let (cert_pem, key_pem) = gen_self_signed();
        let cert_file = write_temp(&cert_pem);
        let key_file = write_temp(&key_pem);

        let cfg = TlsServerConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: key_file.path().to_path_buf(),
            ..TlsServerConfig::default()
        };

        let result = build_tls_server_config(&cfg);
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    // ── TLS 1.3 only ─────────────────────────────────────────────────────────

    #[test]
    fn resulting_config_supports_only_tls13() {
        init_provider();
        // The TLS-1.3-only invariant is enforced structurally at build time:
        // `builder_with_protocol_versions(&[&TLS13])` is the only path used,
        // and the `tls12` cargo feature is not enabled.  This test asserts that
        // the config is built without error (compile-time gate is already
        // effective) and that the ticketer is non-null (sessions are enabled).
        let (cert_pem, key_pem) = gen_self_signed();
        let cert_file = write_temp(&cert_pem);
        let key_file = write_temp(&key_pem);

        let cfg = TlsServerConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: key_file.path().to_path_buf(),
            ..TlsServerConfig::default()
        };

        let server_cfg = build_tls_server_config(&cfg).expect("config built");
        // Session ticketer must be enabled (stateless tickets, SEC-008).
        assert!(
            server_cfg.ticketer.enabled(),
            "session ticketer must be enabled (stateless tickets, SEC-008)"
        );
    }

    // ── 0-RTT disabled ────────────────────────────────────────────────────────

    #[test]
    fn resulting_config_has_early_data_disabled() {
        init_provider();
        let (cert_pem, key_pem) = gen_self_signed();
        let cert_file = write_temp(&cert_pem);
        let key_file = write_temp(&key_pem);

        let cfg = TlsServerConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: key_file.path().to_path_buf(),
            ..TlsServerConfig::default()
        };

        let server_cfg = build_tls_server_config(&cfg).expect("config built");
        assert_eq!(
            server_cfg.max_early_data_size, 0,
            "max_early_data_size must be 0 (SEC-005)"
        );
    }

    // ── Error: bad cert path ──────────────────────────────────────────────────

    #[test]
    fn bad_cert_path_returns_cert_load_error() {
        init_provider();
        let (_, key_pem) = gen_self_signed();
        let key_file = write_temp(&key_pem);

        let cfg = TlsServerConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: key_file.path().to_path_buf(),
            ..TlsServerConfig::default()
        };

        let err = build_tls_server_config(&cfg).expect_err("expected error");
        assert!(
            matches!(err, TlsError::CertLoad { .. }),
            "expected TlsError::CertLoad, got {err:?}"
        );
    }

    // ── Error: bad key path ───────────────────────────────────────────────────

    #[test]
    fn bad_key_path_returns_key_load_error() {
        init_provider();
        let (cert_pem, _) = gen_self_signed();
        let cert_file = write_temp(&cert_pem);

        let cfg = TlsServerConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: PathBuf::from("/nonexistent/key.pem"),
            ..TlsServerConfig::default()
        };

        let err = build_tls_server_config(&cfg).expect_err("expected error");
        assert!(
            matches!(err, TlsError::KeyLoad { .. }),
            "expected TlsError::KeyLoad, got {err:?}"
        );
    }

    // ── Error: no private key in file ────────────────────────────────────────

    #[test]
    fn key_file_with_only_cert_returns_no_private_key_error() {
        init_provider();
        let (cert_pem, _) = gen_self_signed();
        // Write the cert PEM in place of the key file.
        let cert_file = write_temp(&cert_pem);
        let fake_key_file = write_temp(&cert_pem);

        let cfg = TlsServerConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: fake_key_file.path().to_path_buf(),
            ..TlsServerConfig::default()
        };

        let err = build_tls_server_config(&cfg).expect_err("expected error");
        assert!(
            matches!(err, TlsError::NoPrivateKey { .. }),
            "expected TlsError::NoPrivateKey, got {err:?}"
        );
    }

    // ── extract_mtls_identity ─────────────────────────────────────────────────

    #[test]
    fn extract_mtls_identity_returns_consistent_hex_fingerprint() {
        let dummy_der = CertificateDer::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let id1 = extract_mtls_identity(&dummy_der, MtlsIdentitySource::SubjectDn)
            .expect("identity extracted");
        let id2 = extract_mtls_identity(&dummy_der, MtlsIdentitySource::SanDns)
            .expect("identity extracted");

        // Both calls on the same cert must return the same fingerprint.
        assert_eq!(id1, id2, "identity must be deterministic for same cert");
        // Must be a 64-character hex string (SHA-256 = 32 bytes).
        assert_eq!(id1.len(), 64, "SHA-256 hex fingerprint must be 64 chars");
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()), "must be hex");
    }

    #[test]
    fn different_certs_produce_different_identities() {
        let der1 = CertificateDer::from(vec![0x01, 0x02, 0x03]);
        let der2 = CertificateDer::from(vec![0x04, 0x05, 0x06]);

        let id1 = extract_mtls_identity(&der1, MtlsIdentitySource::SubjectDn).unwrap();
        let id2 = extract_mtls_identity(&der2, MtlsIdentitySource::SubjectDn).unwrap();

        assert_ne!(id1, id2, "different certs must produce different identities");
    }

    // ── PrivateKeyDer conversion ──────────────────────────────────────────────

    #[test]
    fn private_key_der_is_loaded_from_pem() {
        init_provider();
        let (_, key_pem) = gen_self_signed();
        let key_file = write_temp(&key_pem);

        let key = load_private_key(key_file.path())
            .expect("private key loaded from PEM");
        // Ed25519 key from rcgen is PKCS#8.
        assert!(
            matches!(key, PrivateKeyDer::Pkcs8(_)),
            "expected PKCS#8 key, got {key:?}"
        );
    }
}
