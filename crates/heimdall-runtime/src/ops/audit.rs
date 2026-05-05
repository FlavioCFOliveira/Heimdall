// SPDX-License-Identifier: MIT

//! HMAC-chained audit logger for admin-RPC operations (THREAT-080).
//!
//! Every admin action is recorded as a single NDJSON line on stderr (and
//! optionally appended to a file). Each line carries a monotonic sequence
//! number, a wall-clock timestamp, the peer identity, the command name, the
//! outcome, and an HMAC-SHA256 tag computed over
//! `previous_tag || seq || ts || identity || cmd || outcome`.
//!
//! The chain can be verified offline with the shared HMAC key: any tampered or
//! inserted line will break the chain and be detected (THREAT-080).

use std::{
    fs::OpenOptions,
    io::Write as _,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use ring::hmac;
use tracing::warn;

// ── AuditEntry ────────────────────────────────────────────────────────────────

/// A single audit log entry as produced by [`AuditLogger::log`].
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number (starts at 1).
    pub seq: u64,
    /// Unix timestamp (seconds since epoch) of the event.
    pub ts: u64,
    /// Peer identity string (e.g. `"uds-local"`, mTLS subject).
    pub identity: String,
    /// Admin command name (e.g. `"zone_add"`, `"drain"`).
    pub command: String,
    /// Outcome: `"ok"` or `"error"`.
    pub outcome: String,
    /// Hex-encoded HMAC-SHA256 tag chained from the previous entry.
    pub hmac: String,
}

// ── AuditLogger ───────────────────────────────────────────────────────────────

/// Inner mutable state shared behind a `Mutex`.
struct Inner {
    /// HMAC key used for all chain links.
    key: hmac::Key,
    /// HMAC tag of the most recently emitted entry (32 bytes, all-zero initially).
    prev_tag: [u8; 32],
    /// Monotonically increasing sequence counter.
    ///
    /// Kept inside the mutex alongside `prev_tag` so that both are updated
    /// atomically — a concurrent log call cannot interleave a seq increment
    /// with another's `prev_tag` update, which would break the HMAC chain.
    seq: u64,
    /// Optional append-only file sink.
    file: Option<std::fs::File>,
}

/// Thread-safe HMAC-chained audit logger.
///
/// All log calls acquire the inner mutex for the duration of tag computation
/// and output, guaranteeing a consistent chain even under concurrent dispatch.
pub struct AuditLogger {
    inner: Mutex<Inner>,
}

impl AuditLogger {
    /// Create a new logger.
    ///
    /// `key_bytes` is the raw HMAC-SHA256 key material (recommended: 32 bytes).
    /// `audit_file` is an optional path to which each NDJSON line will be appended.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if `audit_file` is provided and cannot be opened for
    /// append (e.g. permission denied, invalid path).
    #[allow(clippy::missing_errors_doc)]
    pub fn new(key_bytes: &[u8], audit_file: Option<PathBuf>) -> Result<Self, std::io::Error> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
        let file = match audit_file {
            Some(path) => Some(OpenOptions::new().create(true).append(true).open(path)?),
            None => None,
        };
        Ok(Self {
            inner: Mutex::new(Inner {
                key,
                prev_tag: [0u8; 32],
                seq: 0,
                file,
            }),
        })
    }

    /// Emit one audit entry.
    ///
    /// Computes `HMAC-SHA256(key, prev_tag || seq || ts || identity || cmd || outcome)`,
    /// serialises as NDJSON, and writes to stderr and the optional file sink.
    /// Returns the completed [`AuditEntry`] for callers that need to inspect it
    /// (e.g. tests).
    pub fn log(&self, identity: &str, command: &str, outcome: &str) -> AuditEntry {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.seq += 1;
        let seq = guard.seq;

        // Build the HMAC input: prev_tag (32) || seq (8 BE) || ts (8 BE) || identity || NUL || cmd || NUL || outcome
        let mut ctx = hmac::Context::with_key(&guard.key);
        ctx.update(&guard.prev_tag);
        ctx.update(&seq.to_be_bytes());
        ctx.update(&ts.to_be_bytes());
        ctx.update(identity.as_bytes());
        ctx.update(b"\x00");
        ctx.update(command.as_bytes());
        ctx.update(b"\x00");
        ctx.update(outcome.as_bytes());
        let tag = ctx.sign();
        let tag_bytes: [u8; 32] = tag.as_ref().try_into().unwrap_or([0u8; 32]);
        let tag_hex = hex_encode(&tag_bytes);

        guard.prev_tag = tag_bytes;

        let entry = AuditEntry {
            seq,
            ts,
            identity: identity.to_owned(),
            command: command.to_owned(),
            outcome: outcome.to_owned(),
            hmac: tag_hex.clone(),
        };

        let line = format!(
            r#"{{"seq":{seq},"ts":{ts},"identity":"{identity}","cmd":"{cmd}","outcome":"{outcome}","hmac":"{hmac}"}}"#,
            seq = entry.seq,
            ts = entry.ts,
            identity = entry.identity,
            cmd = entry.command,
            outcome = entry.outcome,
            hmac = tag_hex,
        );

        // Write to stderr — never panic on write failure.
        if let Err(e) = writeln!(std::io::stderr(), "{line}") {
            warn!(event = "audit_stderr_error", error = %e);
        }

        // Write to file sink if configured.
        if let Some(ref mut f) = guard.file
            && let Err(e) = writeln!(f, "{line}")
        {
            warn!(event = "audit_file_error", error = %e);
        }

        entry
    }

    /// Verify a sequence of [`AuditEntry`] items against the HMAC chain.
    ///
    /// This is provided for testing and offline forensics. It requires the same
    /// HMAC key that was used to produce the chain.
    ///
    /// # Errors
    ///
    /// Returns `Err(seq)` for the first entry whose recomputed HMAC tag does
    /// not match the persisted `hmac` field — indicating either a tampered or
    /// out-of-order entry. Returns `Ok(())` when every entry verifies in
    /// order.
    pub fn verify_chain(key_bytes: &[u8], entries: &[AuditEntry]) -> Result<(), u64> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
        let mut prev_tag = [0u8; 32];

        for entry in entries {
            let mut ctx = hmac::Context::with_key(&key);
            ctx.update(&prev_tag);
            ctx.update(&entry.seq.to_be_bytes());
            ctx.update(&entry.ts.to_be_bytes());
            ctx.update(entry.identity.as_bytes());
            ctx.update(b"\x00");
            ctx.update(entry.command.as_bytes());
            ctx.update(b"\x00");
            ctx.update(entry.outcome.as_bytes());
            let expected_tag = ctx.sign();
            let expected_hex = hex_encode(expected_tag.as_ref().try_into().unwrap_or(&[0u8; 32]));

            if expected_hex != entry.hmac {
                return Err(entry.seq);
            }
            prev_tag = expected_tag.as_ref().try_into().unwrap_or([0u8; 32]);
        }
        Ok(())
    }
}

/// Hex-encode 32 bytes without pulling in an external crate.
fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_logger() -> AuditLogger {
        AuditLogger::new(b"test-key-32-bytes-padding-here!!", None).expect("new logger")
    }

    #[test]
    fn seq_increments() {
        let l = make_logger();
        let e1 = l.log("uds-local", "zone_add", "ok");
        let e2 = l.log("uds-local", "nta_add", "ok");
        assert_eq!(e1.seq, 1);
        assert_eq!(e2.seq, 2);
    }

    #[test]
    fn hmac_chain_validates() {
        let key = b"test-key-32-bytes-padding-here!!";
        let l = AuditLogger::new(key, None).expect("new logger");
        let e1 = l.log("uds-local", "zone_add", "ok");
        let e2 = l.log("uds-local", "drain", "ok");
        let e3 = l.log("uds-local", "nta_list", "ok");

        AuditLogger::verify_chain(key, &[e1, e2, e3]).expect("chain must be valid");
    }

    #[test]
    fn tampered_entry_breaks_chain() {
        let key = b"test-key-32-bytes-padding-here!!";
        let l = AuditLogger::new(key, None).expect("new logger");
        let e1 = l.log("uds-local", "zone_add", "ok");
        let mut e2 = l.log("uds-local", "drain", "ok");
        // Tamper with e2's outcome after the fact.
        e2.outcome = "ok_tampered".to_owned();

        let result = AuditLogger::verify_chain(key, &[e1, e2]);
        assert!(
            result.is_err(),
            "tampered entry must fail chain verification"
        );
        assert_eq!(result.unwrap_err(), 2);
    }

    #[test]
    fn single_entry_chain_validates() {
        let key = b"test-key-32-bytes-padding-here!!";
        let l = AuditLogger::new(key, None).expect("new logger");
        let e = l.log("uds-local", "version", "ok");
        AuditLogger::verify_chain(key, &[e]).expect("single-entry chain must be valid");
    }

    #[test]
    fn empty_chain_validates() {
        let key = b"test-key-32-bytes-padding-here!!";
        AuditLogger::verify_chain(key, &[]).expect("empty chain is trivially valid");
    }

    #[test]
    fn file_sink_appends() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("heimdall_audit_test_{}.ndjson", std::process::id()));
        {
            let key = b"test-key-32-bytes-padding-here!!";
            let l = AuditLogger::new(key, Some(path.clone())).expect("new logger with file");
            l.log("uds-local", "zone_add", "ok");
            l.log("uds-local", "nta_add", "ok");
        }
        let content = std::fs::read_to_string(&path).expect("read audit file");
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "file sink must contain 2 lines; got: {content:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
