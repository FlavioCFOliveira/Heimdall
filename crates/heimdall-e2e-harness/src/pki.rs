// SPDX-License-Identifier: MIT

//! Test PKI material — root CA, server cert, client cert.
//!
//! All certs are freshly generated per call, with 365-day validity and SANs
//! covering `localhost`, `127.0.0.1`, and `::1`.  No cert is checked in to
//! the repository: determinism is provided by reproducible key generation via
//! rcgen defaults.

use std::path::PathBuf;
use tempfile::TempDir;

/// All TLS material for one test run, written to a [`TempDir`].
pub struct TestPki {
    /// PEM text of the root CA certificate.
    pub ca_cert_pem: String,
    /// PEM text of the server certificate (signed by the root CA).
    pub server_cert_pem: String,
    /// PEM text of the server private key.
    pub server_key_pem: String,
    /// PEM text of the client certificate for mTLS (signed by the root CA).
    pub client_cert_pem: String,
    /// PEM text of the client private key.
    pub client_key_pem: String,
    /// Temporary directory holding all PEM files.
    pub dir: TempDir,
    /// Absolute path to `ca-cert.pem`.
    pub ca_cert_path: PathBuf,
    /// Absolute path to `server-cert.pem`.
    pub server_cert_path: PathBuf,
    /// Absolute path to `server-key.pem`.
    pub server_key_path: PathBuf,
    /// Absolute path to `client-cert.pem`.
    pub client_cert_path: PathBuf,
    /// Absolute path to `client-key.pem`.
    pub client_key_path: PathBuf,
}

impl TestPki {
    /// Generate a fresh PKI hierarchy and write all PEM files to a new
    /// [`TempDir`].  The TempDir (and its files) are kept alive for as long
    /// as the returned [`TestPki`] is alive.
    ///
    /// Cert validity is 365 days from the moment of generation.
    ///
    /// # Panics
    ///
    /// Panics on any generation or I/O error — acceptable in test code.
    pub fn generate() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};

        let dir = TempDir::new().expect("TestPki tempdir");

        // Validity window: not_before = today − 1 day, not_after = today + 365 days.
        let (nb_y, nb_m, nb_d) = ymd_offset_days(-1);
        let (na_y, na_m, na_d) = ymd_offset_days(365);

        // ── Root CA ──────────────────────────────────────────────────────────
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.not_before = rcgen::date_time_ymd(nb_y, nb_m, nb_d);
        ca_params.not_after = rcgen::date_time_ymd(na_y, na_m, na_d);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Heimdall Test Root CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");
        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = ca_key.serialize_pem();

        // ── Server certificate ────────────────────────────────────────────────
        let server_key = KeyPair::generate().expect("server key");
        let mut server_params = CertificateParams::new(vec![
            "localhost".to_owned(),
        ])
        .expect("server params");
        server_params.subject_alt_names.push(
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
        );
        server_params.subject_alt_names.push(
            SanType::IpAddress("::1".parse().unwrap()),
        );
        server_params.not_before = rcgen::date_time_ymd(nb_y, nb_m, nb_d);
        server_params.not_after = rcgen::date_time_ymd(na_y, na_m, na_d);
        server_params
            .distinguished_name
            .push(DnType::CommonName, "Heimdall Test Server");
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("server cert");
        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();

        // ── Client certificate (mTLS) ─────────────────────────────────────────
        let client_key = KeyPair::generate().expect("client key");
        let mut client_params =
            CertificateParams::new(vec!["heimdall-test-client".to_owned()])
                .expect("client params");
        client_params.not_before = rcgen::date_time_ymd(nb_y, nb_m, nb_d);
        client_params.not_after = rcgen::date_time_ymd(na_y, na_m, na_d);
        client_params
            .distinguished_name
            .push(DnType::CommonName, "Heimdall Test Client");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("client cert");
        let client_cert_pem = client_cert.pem();
        let client_key_pem = client_key.serialize_pem();

        // ── Write PEM files ───────────────────────────────────────────────────
        let ca_cert_path = dir.path().join("ca-cert.pem");
        let server_cert_path = dir.path().join("server-cert.pem");
        let server_key_path = dir.path().join("server-key.pem");
        let client_cert_path = dir.path().join("client-cert.pem");
        let client_key_path = dir.path().join("client-key.pem");

        std::fs::write(&ca_cert_path, &ca_cert_pem).expect("write ca-cert.pem");
        std::fs::write(&server_cert_path, &server_cert_pem)
            .expect("write server-cert.pem");
        std::fs::write(&server_key_path, &server_key_pem)
            .expect("write server-key.pem");
        std::fs::write(&client_cert_path, &client_cert_pem)
            .expect("write client-cert.pem");
        std::fs::write(&client_key_path, &client_key_pem)
            .expect("write client-key.pem");

        // Suppress unused variable for ca_key_pem
        drop(ca_key_pem);

        Self {
            ca_cert_pem,
            server_cert_pem,
            server_key_pem,
            client_cert_pem,
            client_key_pem,
            dir,
            ca_cert_path,
            server_cert_path,
            server_key_path,
            client_cert_path,
            client_key_path,
        }
    }

    /// Parse the server cert and return the number of days until expiry.
    ///
    /// Uses a minimal ASN.1 scan for the `notAfter` UTCTime / GeneralizedTime
    /// field.  Always returns a positive number while valid; negative means
    /// already expired.  Used by the CI expiry gate.
    pub fn server_cert_days_to_expiry(&self) -> i64 {
        cert_days_to_expiry(&self.server_cert_pem)
    }

    /// Like `server_cert_days_to_expiry` but for the CA certificate.
    pub fn ca_cert_days_to_expiry(&self) -> i64 {
        cert_days_to_expiry(&self.ca_cert_pem)
    }

    /// Like `server_cert_days_to_expiry` but for the client certificate.
    pub fn client_cert_days_to_expiry(&self) -> i64 {
        cert_days_to_expiry(&self.client_cert_pem)
    }
}

/// Return the `(year, month, day)` that is `offset_days` from today (UTC).
/// Uses arithmetic-only calendar computation; leap years are approximated
/// for test-certificate validity windows (≤ 400 days).
fn ymd_offset_days(offset_days: i64) -> (i32, u8, u8) {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let target_secs = now_secs + offset_days * 86400;
    let target_days = target_secs / 86400; // days since 1970-01-01

    // Fliegel–Van Flandern epoch conversion.
    let j = target_days + 2_440_588; // Julian Day Number from Unix epoch
    let l = j + 68_569;
    let n = (4 * l) / 146_097;
    let l = l - (146_097 * n + 3) / 4;
    let i = (4000 * (l + 1)) / 1_461_001;
    let l = l - (1_461 * i) / 4 + 31;
    let j = (80 * l) / 2_447;
    let day = (l - (2_447 * j) / 80) as u8;
    let l = j / 11;
    let month = (j + 2 - 12 * l) as u8;
    let year = (100 * (n - 49) + i + l) as i32;
    (year, month, day)
}

/// Parse a PEM certificate and return days until its `notAfter` field.
pub fn cert_days_to_expiry(cert_pem: &str) -> i64 {
    // Decode PEM to DER
    let der = pem_to_der(cert_pem);
    // Scan for notAfter: in a typical X.509 DER the Validity SEQUENCE is
    // the fifth element. We look for the first occurrence of UTCTime (0x17)
    // or GeneralizedTime (0x18) after the first such tag (notBefore), which
    // is the notAfter.  This is a best-effort scan for test purposes only.
    let not_after_str = scan_not_after_asn1(&der)
        .expect("could not parse notAfter from cert");
    let expires = parse_asn1_time(&not_after_str)
        .expect("could not parse notAfter time");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let diff_secs = expires as i64 - now as i64;
    diff_secs / 86400
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    use base64::Engine as _;
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("PEM base64 decode")
}

/// TLV-aware DER scanner: finds the second occurrence of a time tag (0x17
/// or 0x18), which is the `notAfter` field in the `Validity` SEQUENCE.
/// Properly parses DER lengths (including multi-byte long-form lengths) so it
/// is not confused by length bytes that equal 0x17 or 0x18.
fn scan_not_after_asn1(der: &[u8]) -> Option<String> {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < der.len() {
        let tag = der[i];
        i += 1;
        if i >= der.len() {
            break;
        }
        // Read length (BER/DER long-form aware).
        let (len, consumed) = read_asn1_length(der, i)?;
        i += consumed;
        if i + len > der.len() {
            break;
        }
        if tag == 0x17 || tag == 0x18 {
            // UTCTime or GeneralizedTime
            let s = std::str::from_utf8(&der[i..i + len]).ok()?;
            count += 1;
            if count == 2 {
                return Some(s.to_owned());
            }
        }
        // For constructed types (SEQUENCE, SET, etc.) we scan inside them by
        // NOT skipping their contents — just continue byte-by-byte.
        // For primitive types, skip the value.
        if tag & 0x20 == 0 {
            // Primitive: skip value.
            i += len;
        }
        // Constructed: don't advance — recurse into contents.
    }
    None
}

fn read_asn1_length(der: &[u8], i: usize) -> Option<(usize, usize)> {
    if i >= der.len() {
        return None;
    }
    let first = der[i] as usize;
    if first < 0x80 {
        // Short form
        Some((first, 1))
    } else {
        let num_bytes = first & 0x7F;
        if num_bytes == 0 || i + 1 + num_bytes > der.len() {
            return None;
        }
        let mut len = 0usize;
        for k in 0..num_bytes {
            len = (len << 8) | der[i + 1 + k] as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

/// Parse ASN.1 UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ)
/// and return Unix timestamp.
fn parse_asn1_time(s: &str) -> Option<u64> {
    // UTCTime: YYMMDDHHMMSSZ (13 bytes)
    // GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes)
    let (year, rest) = if s.len() == 13 {
        let yy: u64 = s[0..2].parse().ok()?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, &s[2..])
    } else if s.len() == 15 {
        let year: u64 = s[0..4].parse().ok()?;
        (year, &s[4..])
    } else {
        return None;
    };
    let month: u64 = rest[0..2].parse().ok()?;
    let day: u64 = rest[2..4].parse().ok()?;
    let hour: u64 = rest[4..6].parse().ok()?;
    let min: u64 = rest[6..8].parse().ok()?;
    let sec: u64 = rest[8..10].parse().ok()?;

    // Approximate: leap years not handled precisely (sufficient for test gate).
    let days_per_year = 365u64;
    let y = year - 1970;
    let leap_days = (y + 1) / 4;
    let days_in_months: [u64; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let month_days: u64 = days_in_months[..month as usize].iter().sum();
    let total_days = y * days_per_year + leap_days + month_days + day - 1;
    Some(total_days * 86400 + hour * 3600 + min * 60 + sec)
}

extern crate base64;
