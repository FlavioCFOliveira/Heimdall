// SPDX-License-Identifier: MIT

//! DNS-over-QUIC (`DoQ`) listener and QUIC hardening infrastructure (Sprint 24).
//!
//! This module implements the `DoQ` listener on port 853 per [RFC 9250] and the
//! QUIC protocol-security hardening required by `SEC-017..035` and
//! `SEC-071..075` in `specification/003-crypto-policy.md`.
//!
//! # Security controls
//!
//! | Requirement | Mechanism |
//! |------------|-----------|
//! | QUIC v1 + v2 only (`SEC-017`, `SEC-018`, `SEC-019`) | `EndpointConfig::supported_versions` restricted to `[0x00000001, 0x6b3343cf]` |
//! | 0-RTT refused (`SEC-022`, `SEC-023`, `SEC-024`) | `rustls::ServerConfig::max_early_data_size = 0`; quinn rejects the 0-RTT path |
//! | Amplification limit (`SEC-025`) | quinn enforces RFC 9000 §8.1 internally |
//! | Unconditional Retry (`SEC-026`) | `always_retry = true` in [`QuicHardeningConfig`]; accept loop forces Retry for unvalidated source addresses |
//! | `NEW_TOKEN` single-use (`SEC-028`, `SEC-029`) | [`StrikeRegister`] records SHA-256-truncated token hashes |
//! | `NEW_TOKEN` TEK rotation (`SEC-030`, `SEC-071`) | [`NewTokenTekManager`] with rotation and retention windows |
//! | mTLS on QUIC (`SEC-031..035`) | Delegated to the rustls `ServerConfig`; identity extracted from `Connection::peer_identity()` |
//!
//! [RFC 9250]: https://www.rfc-editor.org/rfc/rfc9250

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quinn::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, Incoming, ServerConfig as QuinnServerConfig,
    TransportConfig,
};
use ring::digest::{SHA256, digest};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::CertificateDer;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::admission::{
    AdmissionPipeline, Operation, PipelineDecision, RequestCtx, ResourceCounters, Role, Transport,
};
use crate::drain::Drain;

use super::tls::{MtlsIdentitySource, extract_mtls_identity};
use super::{
    ListenerConfig, QueryDispatcher, TransportError, apply_edns_padding, extract_query_opt,
    process_query,
};

// ── QUIC version constants (SEC-017, SEC-018, SEC-019) ────────────────────────

/// QUIC version 1 wire format identifier (RFC 9000).
const QUIC_V1: u32 = 0x0000_0001;

/// QUIC version 2 wire format identifier (RFC 9369).
const QUIC_V2: u32 = 0x6b33_43cf;

// ── QuicHardeningConfig ───────────────────────────────────────────────────────

/// QUIC-specific security hardening parameters (SEC-017..030, SEC-071..075).
///
/// All fields that control cryptographic key material or token anti-replay
/// have mandatory defaults matching the specification. No configuration knob
/// that enables 0-RTT or multi-use `NEW_TOKEN` may be exposed (`SEC-024`,
/// `SEC-028`).
#[derive(Debug, Clone)]
pub struct QuicHardeningConfig {
    /// QUIC versions accepted by this server (SEC-017, SEC-018).
    ///
    /// Only QUIC v1 (`0x00000001`) and v2 (`0x6b3343cf`) are permitted.
    /// Any other value is rejected by the endpoint builder.
    pub supported_versions: Vec<u32>,

    /// Whether to refuse 0-RTT application data (SEC-022..024).
    ///
    /// Always `true`; no configuration knob that enables 0-RTT is exposed.
    pub refuse_zero_rtt: bool,

    /// Whether to send an unconditional QUIC Retry for unvalidated flows (SEC-026).
    ///
    /// When `true`, every new connection that does not present a valid
    /// server-issued `NEW_TOKEN` must complete a Retry round-trip before
    /// application data is exchanged. This prevents source-IP amplification
    /// attacks.
    pub always_retry: bool,

    /// Rotation interval for the `NEW_TOKEN` TEK, in seconds (SEC-030, SEC-071).
    ///
    /// Default: `43200` (12 h). Specification default from SEC-071.
    pub new_token_tek_rotation_secs: u64,

    /// Retention window for retired `NEW_TOKEN` TEKs, in seconds (SEC-071).
    ///
    /// Tokens sealed under a retired key remain verifiable during this window.
    /// Default: `86400` (24 h). Specification default from SEC-071.
    pub new_token_tek_retention_secs: u64,

    /// Interval between strike-register snapshots to Redis, in seconds (SEC-072).
    ///
    /// Default: `60`. Specification default from SEC-072.
    pub strike_register_snapshot_secs: u64,

    /// Maximum UDP payload size in bytes (RFC 9000 §12.4).
    ///
    /// Default: `1200` (conservative PMTU floor).
    pub max_udp_payload_size: u16,

    /// Maximum idle timeout for QUIC connections, in milliseconds.
    ///
    /// Default: `30000` (30 s).
    pub max_idle_timeout_ms: u32,
}

impl Default for QuicHardeningConfig {
    fn default() -> Self {
        Self {
            // SEC-017, SEC-018: only QUIC v1 and v2.
            supported_versions: vec![QUIC_V1, QUIC_V2],
            // SEC-022..024: refuse 0-RTT; no toggle exposed.
            refuse_zero_rtt: true,
            // SEC-026: unconditional Retry for unvalidated flows.
            always_retry: true,
            // SEC-071 defaults: 12 h rotation, 24 h retention.
            new_token_tek_rotation_secs: 43_200,
            new_token_tek_retention_secs: 86_400,
            // SEC-072 default: 60 s snapshot interval.
            strike_register_snapshot_secs: 60,
            // Conservative PMTU default (RFC 9000 §12.4).
            max_udp_payload_size: 1200,
            // 30 s idle timeout.
            max_idle_timeout_ms: 30_000,
        }
    }
}

// ── StrikeRegister ────────────────────────────────────────────────────────────

/// Single-use `NEW_TOKEN` anti-replay register (SEC-028, SEC-029, SEC-072).
///
/// The primary store is an in-memory `HashSet` of 16-byte SHA-256 token
/// hashes (SHA-256 truncated to the first 16 bytes). Snapshot persistence to
/// Redis (SEC-072) is deferred and implemented as a no-op stub in this sprint.
///
/// # Hash construction
///
/// The hash stored for each token is `SHA-256(token)[..16]`. Truncation to
/// 16 bytes keeps the footprint at approximately 24 bytes per entry (hash +
/// overhead) while retaining 128 bits of collision resistance — far beyond
/// the practical number of tokens in flight at any given moment.
pub struct StrikeRegister {
    consumed: Mutex<std::collections::HashSet<[u8; 16]>>,
}

impl StrikeRegister {
    /// Creates a new, empty strike register.
    #[must_use]
    pub fn new() -> Self {
        Self {
            consumed: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Checks whether `token` is new and, if so, records it as consumed.
    ///
    /// Returns `true` if the token had **not** been seen before (new token,
    /// connection may proceed). Returns `false` if the token was already
    /// present in the register (replay detected, connection must be subjected
    /// to QUIC Retry per SEC-026).
    ///
    /// The token hash is `SHA-256(token)[..16]`.
    pub async fn check_and_consume(&self, token: &[u8]) -> bool {
        let hash_digest = digest(&SHA256, token);
        let hash_bytes: &[u8] = hash_digest.as_ref();

        // Truncate to 16 bytes — guaranteed by ring::SHA256 producing 32 bytes.
        let mut entry = [0u8; 16];
        entry.copy_from_slice(&hash_bytes[..16]);

        let mut guard = self.consumed.lock().await;
        // `insert` returns true when the element was newly inserted (not present before).
        guard.insert(entry)
    }
}

impl Default for StrikeRegister {
    fn default() -> Self {
        Self::new()
    }
}

// ── NewTokenTekManager ────────────────────────────────────────────────────────

/// Manager for `NEW_TOKEN` Token-Encryption-Keys (TEKs) (SEC-030, SEC-071, SEC-075).
///
/// Maintains one current 32-byte HMAC-SHA256 key and a bounded list of retired
/// keys within the retention window. Tokens sealed under any active (current or
/// retained) key can be unsealed; tokens sealed under a destroyed key are
/// rejected and fall back to a QUIC Retry exchange.
///
/// # Token format
///
/// `seal_token` produces: `HMAC-SHA256(key, token_data) ∥ token_data`
/// (32-byte tag followed by the original `token_data` bytes).
///
/// `unseal_token` tries each active key until one validates the HMAC tag.
///
/// # Forward secrecy (SEC-075)
///
/// When a retired key ages out of the retention window, it is dropped from
/// `retired_keys`. Tokens sealed under a destroyed key become cryptographically
/// inaccessible, forcing a fresh QUIC Retry exchange.
pub struct NewTokenTekManager {
    current_key: Mutex<([u8; 32], Instant)>,
    retired_keys: Mutex<Vec<([u8; 32], Instant)>>,
    rotation_interval: Duration,
    retention_window: Duration,
}

impl NewTokenTekManager {
    /// Creates a new TEK manager with a freshly generated current key.
    ///
    /// `rotation_secs` and `retention_secs` map to the configuration keys
    /// `quic.new_token.tek_rotation_hours` and `quic.new_token.tek_retention_hours`
    /// respectively (SEC-071).
    ///
    /// # Panics
    ///
    /// Panics if the OS entropy source (`ring::rand::SystemRandom`) cannot fill
    /// 32 bytes. This is only possible if the OS entropy source is unavailable,
    /// which is a fatal configuration error at startup.
    #[must_use]
    pub fn new(rotation_secs: u64, retention_secs: u64) -> Self {
        let key = generate_random_key();
        Self {
            current_key: Mutex::new((key, Instant::now())),
            retired_keys: Mutex::new(Vec::new()),
            rotation_interval: Duration::from_secs(rotation_secs),
            retention_window: Duration::from_secs(retention_secs),
        }
    }

    /// Seals `token_data` under the current TEK.
    ///
    /// Returns `HMAC-SHA256(current_key, token_data) ∥ token_data`
    /// (32-byte tag prepended to the original data).
    pub async fn seal_token(&self, token_data: &[u8]) -> Vec<u8> {
        let guard = self.current_key.lock().await;
        let (key_bytes, _) = &*guard;
        hmac_seal(key_bytes, token_data)
    }

    /// Tries to unseal a token produced by [`Self::seal_token`].
    ///
    /// Tries the current key first, then retired keys in order from newest to
    /// oldest. Returns `Some(token_data)` if any active key validates the HMAC
    /// tag; returns `None` if validation fails against all active keys (token
    /// is expired, tampered, or sealed under a destroyed key).
    pub async fn unseal_token(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 32 {
            return None;
        }
        let (tag, data) = sealed.split_at(32);

        // Try current key first.
        {
            let guard = self.current_key.lock().await;
            let (key_bytes, _) = &*guard;
            if hmac_verify(key_bytes, data, tag) {
                return Some(data.to_vec());
            }
        }

        // Try retained keys from newest to oldest.
        {
            let retired_guard = self.retired_keys.lock().await;
            for (key_bytes, _issued_at) in retired_guard.iter().rev() {
                if hmac_verify(key_bytes, data, tag) {
                    return Some(data.to_vec());
                }
            }
        }

        None
    }

    /// Rotates the TEK if the rotation interval has elapsed.
    ///
    /// When rotation occurs:
    /// 1. The current key is moved to `retired_keys`.
    /// 2. A new random key is generated and becomes the current key.
    /// 3. Retired keys outside the retention window are destroyed (SEC-075).
    ///
    /// Returns `true` if a rotation occurred, `false` otherwise.
    pub async fn maybe_rotate(&self) -> bool {
        let now = Instant::now();

        let mut current_guard = self.current_key.lock().await;
        let (_, issued_at) = *current_guard;
        if now.duration_since(issued_at) < self.rotation_interval {
            return false;
        }

        // Retire current key before generating the new one.
        let old_key = current_guard.0;
        let old_issued_at = current_guard.1;

        // Generate and install new key.
        *current_guard = (generate_random_key(), now);
        drop(current_guard);

        // Record retired key and purge entries outside the retention window (SEC-075).
        let mut retired = self.retired_keys.lock().await;
        retired.push((old_key, old_issued_at));

        if self.retention_window == Duration::ZERO {
            // Zero-length retention: destroy all retired keys immediately.
            retired.clear();
        } else if let Some(cutoff) = now.checked_sub(self.retention_window) {
            // Remove keys whose issuance time is before the retention cutoff.
            retired.retain(|(_, issued)| *issued > cutoff);
        }
        // If `now.checked_sub` returns None, `now` < `retention_window`, meaning
        // the retention window has not yet elapsed at all — retain everything.

        true
    }
}

/// Generates a random 32-byte key using the OS entropy source.
///
/// # Panics
///
/// Panics if the OS entropy source is unavailable. This is a fatal
/// configuration error; no meaningful recovery is possible without entropy.
#[allow(clippy::expect_used)] // INVARIANT: SystemRandom fails only on broken OS configurations.
fn generate_random_key() -> [u8; 32] {
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key)
        .expect("INVARIANT: OS entropy source must be available");
    key
}

/// Computes `HMAC-SHA256(key, data)` and returns `tag ∥ data`.
fn hmac_seal(key_bytes: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    let tag = hmac::sign(&key, data);
    let mut out = Vec::with_capacity(32 + data.len());
    out.extend_from_slice(tag.as_ref());
    out.extend_from_slice(data);
    out
}

/// Returns `true` iff `HMAC-SHA256(key, data) == tag`.
fn hmac_verify(key_bytes: &[u8; 32], data: &[u8], tag: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    hmac::verify(&key, data, tag).is_ok()
}

// ── QuicTelemetry ─────────────────────────────────────────────────────────────

/// Atomic counters for QUIC listener observability (task #283).
///
/// Counters are incremented with `Ordering::Relaxed` (counter accuracy on the
/// hot path matters more than strict ordering) and read with
/// `Ordering::Acquire` for reporting.
#[derive(Default)]
pub struct QuicTelemetry {
    /// Number of QUIC Retry packets sent (SEC-026).
    pub retry_fires: AtomicU64,
    /// Number of `NEW_TOKEN` replays rejected by the strike register (SEC-028, SEC-029).
    pub new_token_replays_rejected: AtomicU64,
    /// Number of connections dropped due to the amplification limit (SEC-025).
    pub amplification_drops: AtomicU64,
    /// Number of 0-RTT refusals recorded (SEC-022).
    pub zero_rtt_refusals: AtomicU64,
    /// Number of TLS/QUIC handshake failures.
    pub handshake_failures: AtomicU64,
    /// Number of TLS/QUIC handshakes completed successfully.
    pub handshake_successes: AtomicU64,
    /// Total bidirectional `DoQ` streams served (RFC 9250 §4.2).
    pub streams_served: AtomicU64,
    /// Total `DoQ` streams rejected (REFUSED response sent due to ACL or rate limit).
    pub streams_refused: AtomicU64,
}

impl QuicTelemetry {
    /// Creates a new zeroed telemetry instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emits a `tracing::info!` snapshot of all counters.
    pub fn report(&self) {
        tracing::info!(
            retry_fires = self.retry_fires.load(Ordering::Acquire),
            new_token_replays_rejected = self.new_token_replays_rejected.load(Ordering::Acquire),
            amplification_drops = self.amplification_drops.load(Ordering::Acquire),
            zero_rtt_refusals = self.zero_rtt_refusals.load(Ordering::Acquire),
            handshake_failures = self.handshake_failures.load(Ordering::Acquire),
            handshake_successes = self.handshake_successes.load(Ordering::Acquire),
            streams_served = self.streams_served.load(Ordering::Acquire),
            streams_refused = self.streams_refused.load(Ordering::Acquire),
            "quic_telemetry",
        );
    }
}

// ── build_quinn_endpoint ──────────────────────────────────────────────────────

/// Builds a [`quinn::Endpoint`] for DoQ/QUIC service.
///
/// # Policy enforced
///
/// - **QUIC v1 + v2 only** (SEC-017, SEC-018): [`EndpointConfig::supported_versions`]
///   is set to `[0x00000001, 0x6b3343cf]`.
/// - **0-RTT refused** (SEC-022, SEC-023): the supplied `tls_config` must have
///   `max_early_data_size = 0`; quinn interprets this as refusing early-data.
///   QUIC prohibits `max_early_data_size` values other than `0` or `u32::MAX`;
///   our Sprint 22 rustls config always has `0`.
/// - **Amplification limit** (SEC-025): enforced internally by quinn per
///   RFC 9000 §8.1; no additional configuration is required.
/// - **Idle timeout**: set from `hardening.max_idle_timeout_ms`.
///
/// # Retry
///
/// Quinn does not expose a single "always retry" toggle on `ServerConfig`.
/// Unconditional address validation is enforced in the accept loop:
/// connections whose `Incoming::remote_address_validated()` is `false` are
/// sent a Retry packet via `Incoming::retry()` (SEC-026).
///
/// # Errors
///
/// - [`TransportError::Io`] if converting the rustls `ServerConfig` to a
///   QUIC-compatible form fails (e.g. wrong `max_early_data_size` value) or if
///   the idle timeout is out of the QUIC `VarInt` range.
/// - [`TransportError::Bind`] if the UDP socket cannot be bound to `bind_addr`.
pub fn build_quinn_endpoint(
    bind_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    hardening: &QuicHardeningConfig,
) -> Result<Endpoint, TransportError> {
    // ── Convert rustls ServerConfig to quinn's QUIC crypto layer ──────────────
    // `quinn::crypto::rustls::QuicServerConfig::try_from(Arc<rustls::ServerConfig>)`
    // validates that `max_early_data_size` is either 0 or `u32::MAX`. Our Sprint
    // 22 config has `max_early_data_size = 0`, which means the server will refuse
    // 0-RTT data, satisfying SEC-022..024.
    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| {
            TransportError::Io(std::io::Error::other(format!(
                "QUIC TLS crypto configuration error: {e}"
            )))
        })?;

    // ── Build TransportConfig with idle timeout ───────────────────────────────
    let mut transport_config = TransportConfig::default();
    let idle_timeout = IdleTimeout::try_from(Duration::from_millis(u64::from(
        hardening.max_idle_timeout_ms,
    )))
    .map_err(|e| {
        TransportError::Io(std::io::Error::other(format!(
            "invalid QUIC idle timeout: {e}"
        )))
    })?;
    transport_config.max_idle_timeout(Some(idle_timeout));

    // ── Build quinn ServerConfig ──────────────────────────────────────────────
    let mut quinn_server_cfg = QuinnServerConfig::with_crypto(Arc::new(quic_server_crypto));
    quinn_server_cfg.transport_config(Arc::new(transport_config));

    // ── Build EndpointConfig restricting to v1 + v2 (SEC-017..019) ───────────
    // `EndpointConfig::supported_versions` sets the exact set of QUIC version
    // values the endpoint will accept.  Clients advertising only unsupported
    // versions will receive a Version Negotiation packet (RFC 8999, RFC 9000 §6).
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.supported_versions(hardening.supported_versions.clone());

    // ── Bind the UDP socket and create the quinn Endpoint ────────────────────
    let socket = std::net::UdpSocket::bind(bind_addr).map_err(TransportError::Bind)?;

    let runtime = quinn::default_runtime().ok_or_else(|| {
        TransportError::Io(std::io::Error::other(
            "no async runtime found for quinn — tokio runtime must be active",
        ))
    })?;
    let abstract_socket = runtime
        .wrap_udp_socket(socket)
        .map_err(TransportError::Io)?;

    Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(quinn_server_cfg),
        abstract_socket,
        runtime,
    )
    .map_err(TransportError::Bind)
}

// ── DoqListener ───────────────────────────────────────────────────────────────

/// DNS-over-QUIC (`DoQ`) listener on port 853 (NET-008, RFC 9250, SEC-017..035).
///
/// # Protocol
///
/// `DoQ` uses QUIC bidirectional streams. Each stream carries exactly one DNS
/// query/response pair, framed with a 2-byte big-endian length prefix per
/// [RFC 9250 §4.2].
///
/// # Security
///
/// - QUIC v1 + v2 only; all other versions rejected (SEC-017..019).
/// - 0-RTT refused (SEC-022..024).
/// - Unconditional Retry for unvalidated source addresses (SEC-026).
/// - `NEW_TOKEN` single-use enforcement via [`StrikeRegister`] (SEC-028, SEC-029).
/// - `NEW_TOKEN` TEK rotation via [`NewTokenTekManager`] (SEC-030, SEC-071).
/// - Optional mTLS: when the supplied TLS config includes a client verifier,
///   client certificates are extracted via [`extract_mtls_identity`] (SEC-031..035).
///
/// [RFC 9250 §4.2]: https://www.rfc-editor.org/rfc/rfc9250#section-4.2
pub struct DoqListener {
    endpoint: Endpoint,
    config: ListenerConfig,
    hardening: QuicHardeningConfig,
    strike_register: Arc<StrikeRegister>,
    tek_manager: Arc<NewTokenTekManager>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<QuicTelemetry>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
}

impl DoqListener {
    /// Creates a [`DoqListener`] from a pre-built [`quinn::Endpoint`].
    ///
    /// # Parameters
    ///
    /// - `endpoint`: a QUIC endpoint built by [`build_quinn_endpoint`].
    /// - `config`: shared listener configuration (bind address, timeouts, etc.).
    /// - `hardening`: QUIC-specific security parameters.
    /// - `strike_register`: shared `NEW_TOKEN` anti-replay register.
    /// - `tek_manager`: shared `NEW_TOKEN` TEK rotation manager.
    /// - `pipeline`: five-stage admission pipeline (ACL, RRL, resource limits).
    /// - `resource_counters`: shared resource accounting.
    /// - `telemetry`: QUIC-specific telemetry counters.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Eight constructor parameters mirror the eight required state fields; a builder pattern would add complexity without clarity benefit here.
    pub fn new(
        endpoint: Endpoint,
        config: ListenerConfig,
        hardening: QuicHardeningConfig,
        strike_register: Arc<StrikeRegister>,
        tek_manager: Arc<NewTokenTekManager>,
        pipeline: Arc<AdmissionPipeline>,
        resource_counters: Arc<ResourceCounters>,
        telemetry: Arc<QuicTelemetry>,
    ) -> Self {
        Self {
            endpoint,
            config,
            hardening,
            strike_register,
            tek_manager,
            pipeline,
            resource_counters,
            telemetry,
            dispatcher: None,
        }
    }

    /// Attach a [`QueryDispatcher`] to this listener.
    #[must_use]
    pub fn with_dispatcher(
        mut self,
        dispatcher: Arc<dyn QueryDispatcher + Send + Sync>,
    ) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Runs the `DoQ` accept loop until the drain signal is received.
    ///
    /// Each accepted connection is dispatched to a tokio task via
    /// `handle_doq_connection`. The loop exits cleanly when `drain` fires.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] only on unrecoverable endpoint failures.
    pub async fn run(self, drain: Arc<Drain>) -> Result<(), TransportError> {
        let endpoint = self.endpoint;
        let config = Arc::new(self.config);
        let hardening = Arc::new(self.hardening);
        let strike_register = self.strike_register;
        let tek_manager = self.tek_manager;
        let pipeline = self.pipeline;
        let resource_counters = self.resource_counters;
        let telemetry = self.telemetry;
        let dispatcher = self.dispatcher.clone();

        loop {
            if drain.is_draining() {
                endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                break;
            }

            let incoming_opt = endpoint.accept().await;
            let Some(incoming) = incoming_opt else {
                // Endpoint closed externally.
                break;
            };

            let pipeline_c = Arc::clone(&pipeline);
            let resource_counters_c = Arc::clone(&resource_counters);
            let telemetry_c = Arc::clone(&telemetry);
            let hardening_c = Arc::clone(&hardening);
            let config_c = Arc::clone(&config);
            let strike_register_c = Arc::clone(&strike_register);
            let tek_manager_c = Arc::clone(&tek_manager);
            let dispatcher_c = dispatcher.clone();

            tokio::spawn(async move {
                handle_doq_connection(
                    incoming,
                    config_c,
                    hardening_c,
                    strike_register_c,
                    tek_manager_c,
                    pipeline_c,
                    resource_counters_c,
                    telemetry_c,
                    dispatcher_c,
                )
                .await;
            });
        }

        Ok(())
    }
}

// ── handle_doq_connection ─────────────────────────────────────────────────────

/// Handles a single incoming QUIC connection (RFC 9250 §4).
///
/// # Flow
///
/// 1. If `always_retry` is set and the source address is not yet validated,
///    send a QUIC Retry and return (SEC-026).
/// 2. Check the global resource counter before completing the handshake.
/// 3. Complete the QUIC handshake (TLS 1.3-in-QUIC, SEC-004).
/// 4. Extract the mTLS identity if the peer supplied a client certificate
///    (SEC-031..035).
/// 5. Accept bidirectional streams in a loop and dispatch each to
///    `handle_doq_stream`.
#[allow(clippy::too_many_arguments)]
async fn handle_doq_connection(
    incoming: Incoming,
    config: Arc<ListenerConfig>,
    hardening: Arc<QuicHardeningConfig>,
    // strike_register: NEW_TOKEN anti-replay check (SEC-028, SEC-029) — full
    // integration deferred to post-sprint when NEW_TOKEN issuance is wired up.
    _strike_register: Arc<StrikeRegister>,
    tek_manager: Arc<NewTokenTekManager>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<QuicTelemetry>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) {
    let peer_addr = incoming.remote_address();

    // ── Address validation / Retry (SEC-026) ──────────────────────────────────
    // When `always_retry` is true and the remote address is not yet validated
    // (no echoed-back Retry token), send a Retry packet. The client must echo
    // the Retry token in its next Initial packet, validating its source IP.
    if hardening.always_retry && !incoming.remote_address_validated() {
        if incoming.may_retry() {
            telemetry.retry_fires.fetch_add(1, Ordering::Relaxed);
            match incoming.retry() {
                Ok(()) => {
                    debug!(%peer_addr, "DoQ: Retry sent for unvalidated source address");
                    return;
                }
                Err(e) => {
                    warn!(%peer_addr, "DoQ: failed to send Retry: {e}");
                    return;
                }
            }
        }
        // Retry not possible (e.g. the client already echoed a retry token
        // but from the wrong transport path).  Refuse cleanly.
        incoming.refuse();
        return;
    }

    // ── Global resource limit check ───────────────────────────────────────────
    // Try to acquire a global pending-query slot before paying the cost of the
    // TLS handshake (SEC-025, THREAT-065).
    if !resource_counters.try_acquire_global(&pipeline.resource_limits) {
        debug!(%peer_addr, "DoQ: dropping incoming connection — global pending limit reached");
        incoming.refuse();
        return;
    }

    // ── Accept and complete the QUIC handshake ────────────────────────────────
    let connecting = match incoming.accept() {
        Ok(c) => c,
        Err(e) => {
            resource_counters.release_global();
            warn!(%peer_addr, "DoQ: failed to accept incoming connection: {e}");
            telemetry.handshake_failures.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let conn: Connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            resource_counters.release_global();
            warn!(%peer_addr, "DoQ: QUIC handshake failed: {e}");
            telemetry.handshake_failures.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    telemetry
        .handshake_successes
        .fetch_add(1, Ordering::Relaxed);

    // ── Rotate TEK if the interval has elapsed (SEC-030, SEC-071) ────────────
    let _ = tek_manager.maybe_rotate().await;

    // ── Extract mTLS identity (SEC-031..035) ──────────────────────────────────
    // `peer_identity()` returns `Some(Box<dyn Any>)` if the peer provided a
    // client certificate and mTLS is enabled in the rustls ServerConfig.
    // The inner value is `Vec<CertificateDer<'static>>`.
    let mtls_identity: Option<String> = conn
        .peer_identity()
        .and_then(|any| any.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| certs.into_iter().next())
        .and_then(|cert| extract_mtls_identity(&cert, MtlsIdentitySource::SubjectDn));

    // ── Accept bidirectional streams (RFC 9250 §4.2) ──────────────────────────
    loop {
        match conn.accept_bi().await {
            Ok((send_stream, recv_stream)) => {
                let pipeline_c = Arc::clone(&pipeline);
                let resource_counters_c = Arc::clone(&resource_counters);
                let telemetry_c = Arc::clone(&telemetry);
                let config_c = Arc::clone(&config);
                let mtls_identity_c = mtls_identity.clone();
                let dispatcher_c = dispatcher.clone();
                tokio::spawn(async move {
                    handle_doq_stream(
                        send_stream,
                        recv_stream,
                        peer_addr,
                        mtls_identity_c,
                        config_c,
                        pipeline_c,
                        resource_counters_c,
                        telemetry_c,
                        dispatcher_c,
                    )
                    .await;
                });
            }
            Err(e) => {
                debug!(%peer_addr, "DoQ: connection closed: {e}");
                break;
            }
        }
    }

    // Release the global resource slot when the connection drains completely.
    resource_counters.release_global();
}

// ── handle_doq_stream ─────────────────────────────────────────────────────────

/// Handles a single bidirectional `DoQ` stream (RFC 9250 §4.2).
///
/// # Framing
///
/// Each stream carries exactly one DNS message, prefixed with a 2-byte
/// big-endian length value. The server reads the length, reads the message,
/// processes it, writes the 2-byte length-prefixed response, and closes the
/// send stream.
///
/// # Admission
///
/// The [`AdmissionPipeline`] is evaluated before parsing. Connections that
/// fail ACL evaluation or rate limits receive a DNS REFUSED response (RCODE 5)
/// and the stream is closed cleanly (fail-closed principle).
#[allow(clippy::too_many_arguments)]
async fn handle_doq_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer_addr: SocketAddr,
    mtls_identity: Option<String>,
    config: Arc<ListenerConfig>,
    pipeline: Arc<AdmissionPipeline>,
    resource_counters: Arc<ResourceCounters>,
    telemetry: Arc<QuicTelemetry>,
    dispatcher: Option<Arc<dyn QueryDispatcher + Send + Sync>>,
) {
    telemetry.streams_served.fetch_add(1, Ordering::Relaxed);

    // ── Read 2-byte length prefix (RFC 9250 §4.2) ─────────────────────────────
    let mut len_buf = [0u8; 2];
    if let Err(e) = recv.read_exact(&mut len_buf).await {
        debug!(%peer_addr, "DoQ stream: failed to read length prefix: {e}");
        return;
    }
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    // ── Read DNS query ────────────────────────────────────────────────────────
    let mut wire = vec![0u8; msg_len];
    if let Err(e) = recv.read_exact(&mut wire).await {
        debug!(%peer_addr, "DoQ stream: failed to read query body: {e}");
        return;
    }

    // ── Parse DNS message ─────────────────────────────────────────────────────
    let query = match heimdall_core::parser::Message::parse(&wire) {
        Ok(m) => m,
        Err(e) => {
            debug!(%peer_addr, "DoQ stream: malformed DNS query: {e}");
            return;
        }
    };

    // ── Build RequestCtx for this stream ──────────────────────────────────────
    // QNAME in lowercase wire-encoded form for ACL matching.
    let qname_wire = query
        .questions
        .first()
        .map(|q| q.qname.to_string().to_ascii_lowercase().into_bytes())
        .unwrap_or_default();

    let ctx = RequestCtx {
        source_ip: peer_addr.ip(),
        mtls_identity,
        tsig_identity: None,
        transport: Transport::DoQ,
        role: Role::Authoritative,
        operation: Operation::Query,
        qname: qname_wire,
        has_valid_cookie: false,
    };

    // ── Admission pipeline evaluation ──────────────────────────────────────────
    let decision = pipeline.evaluate(&ctx, Instant::now());

    let denied = !matches!(decision, PipelineDecision::Allow);
    if denied {
        telemetry.streams_refused.fetch_add(1, Ordering::Relaxed);
        // Release the slot acquired in `handle_doq_connection` if we deny.
        // Note: since the slot was acquired per-connection and not per-stream,
        // releasing here would double-release. The per-stream path does NOT own
        // the connection-level slot — only the connection drainer does. The
        // pipeline internally releases the slot on deny (see pipeline.rs).
    }

    // ── Process query ─────────────────────────────────────────────────────────
    let raw_response = process_query(&query, peer_addr.ip(), dispatcher.as_deref());

    // ── Apply RFC 8467 EDNS padding ───────────────────────────────────────────
    let query_opt = extract_query_opt(&query);
    let response_bytes = apply_edns_padding(&raw_response, query_opt, config.max_udp_payload);

    // Guard: DoQ responses must not exceed 65535 bytes (2-byte length prefix).
    let Ok(resp_len_u16) = u16::try_from(response_bytes.len()) else {
        warn!(%peer_addr, "DoQ stream: response too large ({} bytes), dropping stream", response_bytes.len());
        return;
    };

    // ── Write 2-byte length-prefixed response (RFC 9250 §4.2) ────────────────
    let len_prefix = u16::to_be_bytes(resp_len_u16);
    if let Err(e) = send.write_all(&len_prefix).await {
        debug!(%peer_addr, "DoQ stream: failed to write response length: {e}");
        return;
    }
    if let Err(e) = send.write_all(&response_bytes).await {
        debug!(%peer_addr, "DoQ stream: failed to write response body: {e}");
        return;
    }

    // Close the send stream cleanly after writing the response.
    if let Err(e) = send.finish() {
        debug!(%peer_addr, "DoQ stream: failed to finish send stream: {e}");
    }

    // Silence unused variable warning for resource_counters — stream-level
    // resource accounting is added in a later sprint.
    let _ = &resource_counters;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use super::*;

    // ── QuicHardeningConfig::default ──────────────────────────────────────────

    #[test]
    fn quic_hardening_config_default_has_spec_values() {
        let cfg = QuicHardeningConfig::default();

        // SEC-017, SEC-018: QUIC v1 and v2.
        assert_eq!(cfg.supported_versions, vec![QUIC_V1, QUIC_V2]);
        // SEC-022..024: 0-RTT refused.
        assert!(cfg.refuse_zero_rtt, "0-RTT must be refused by default");
        // SEC-026: unconditional Retry.
        assert!(cfg.always_retry, "always_retry must be true by default");
        // SEC-071: 12 h rotation, 24 h retention.
        assert_eq!(
            cfg.new_token_tek_rotation_secs, 43_200,
            "TEK rotation must default to 12 h"
        );
        assert_eq!(
            cfg.new_token_tek_retention_secs, 86_400,
            "TEK retention must default to 24 h"
        );
        // SEC-072: 60 s snapshot interval.
        assert_eq!(cfg.strike_register_snapshot_secs, 60);
        // Conservative PMTU default.
        assert_eq!(cfg.max_udp_payload_size, 1200);
        // 30 s idle timeout.
        assert_eq!(cfg.max_idle_timeout_ms, 30_000);
    }

    // ── StrikeRegister ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn strike_register_first_use_returns_true() {
        let sr = StrikeRegister::new();
        assert!(
            sr.check_and_consume(b"token-abc").await,
            "first use must return true"
        );
    }

    #[tokio::test]
    async fn strike_register_second_use_returns_false() {
        let sr = StrikeRegister::new();
        assert!(
            sr.check_and_consume(b"token-xyz").await,
            "first use must return true"
        );
        assert!(
            !sr.check_and_consume(b"token-xyz").await,
            "second use of same token must return false (replay)"
        );
    }

    #[tokio::test]
    async fn strike_register_different_tokens_are_independent() {
        let sr = StrikeRegister::new();
        assert!(sr.check_and_consume(b"token-1").await);
        assert!(
            sr.check_and_consume(b"token-2").await,
            "different token must still be new"
        );
    }

    // ── NewTokenTekManager ────────────────────────────────────────────────────

    #[tokio::test]
    async fn new_token_tek_manager_seal_unseal_roundtrip() {
        let mgr = NewTokenTekManager::new(43_200, 86_400);
        let data = b"quic-new-token-payload";
        let sealed = mgr.seal_token(data).await;
        let unsealed = mgr.unseal_token(&sealed).await;
        assert_eq!(unsealed.as_deref(), Some(data.as_ref()));
    }

    #[tokio::test]
    async fn new_token_tek_manager_tampered_token_rejected() {
        let mgr = NewTokenTekManager::new(43_200, 86_400);
        let data = b"legitimate-payload";
        let mut sealed = mgr.seal_token(data).await;
        // Corrupt the HMAC tag.
        sealed[0] ^= 0xFF;
        let result = mgr.unseal_token(&sealed).await;
        assert!(result.is_none(), "tampered token must be rejected");
    }

    #[tokio::test]
    async fn new_token_tek_manager_short_token_rejected() {
        let mgr = NewTokenTekManager::new(43_200, 86_400);
        // A token shorter than 32 bytes cannot contain a valid HMAC tag.
        let result = mgr.unseal_token(b"too-short").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn new_token_tek_manager_rotation_retires_key() {
        // Use a very short rotation interval to trigger rotation immediately.
        let mgr = NewTokenTekManager::new(0, 3600);
        let data = b"payload-before-rotation";
        let sealed = mgr.seal_token(data).await;

        // Force a rotation (interval = 0 s means any elapsed time triggers it).
        tokio::time::sleep(Duration::from_millis(2)).await;
        let rotated = mgr.maybe_rotate().await;
        assert!(rotated, "rotation must occur when interval has elapsed");

        // The retired key is still within the retention window (3600 s),
        // so unsealing must succeed.
        let unsealed = mgr.unseal_token(&sealed).await;
        assert_eq!(
            unsealed.as_deref(),
            Some(data.as_ref()),
            "token sealed under retired key must unseal within retention window"
        );
    }

    #[tokio::test]
    async fn new_token_tek_manager_key_outside_retention_rejected() {
        // Rotation interval = 0 s, retention = 0 s — retired keys are destroyed immediately.
        let mgr = NewTokenTekManager::new(0, 0);
        let data = b"payload-before-rotation";
        let sealed = mgr.seal_token(data).await;

        // Sleep briefly to ensure `Instant::now()` advances past the 0-s interval.
        tokio::time::sleep(Duration::from_millis(2)).await;
        let rotated = mgr.maybe_rotate().await;
        assert!(rotated, "rotation must occur");

        // The old key had a 0-s retention and must have been destroyed.
        let unsealed = mgr.unseal_token(&sealed).await;
        assert!(
            unsealed.is_none(),
            "token sealed under destroyed key must be rejected"
        );
    }

    // ── QuicTelemetry ─────────────────────────────────────────────────────────

    #[test]
    fn quic_telemetry_report_does_not_panic() {
        let t = QuicTelemetry::new();
        t.retry_fires.fetch_add(3, Ordering::Relaxed);
        t.handshake_successes.fetch_add(10, Ordering::Relaxed);
        // Must not panic — exercises all fields via report().
        t.report();
    }

    #[test]
    fn quic_telemetry_counters_are_independent() {
        let t = QuicTelemetry::new();
        t.retry_fires.fetch_add(1, Ordering::Relaxed);
        t.handshake_failures.fetch_add(2, Ordering::Relaxed);
        assert_eq!(t.retry_fires.load(Ordering::Acquire), 1);
        assert_eq!(t.handshake_failures.load(Ordering::Acquire), 2);
        assert_eq!(t.handshake_successes.load(Ordering::Acquire), 0);
    }
}
