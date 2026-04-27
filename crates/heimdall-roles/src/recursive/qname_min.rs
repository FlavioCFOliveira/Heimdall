// SPDX-License-Identifier: MIT

//! QNAME minimisation per RFC 9156 (PROTO-020..024).
//!
//! QNAME minimisation limits the labels sent to intermediate authoritative
//! nameservers to only those needed to reach the next delegation, reducing
//! privacy leakage.
//!
//! # Protocol summary
//!
//! Given `full_qname = "a.b.example.com."` and starting zone `"."`:
//!
//! | Step | `current_zone` | Minimised query            |
//! |------|----------------|----------------------------|
//! | 1    | `.`            | `com. NS IN`               |
//! | 2    | `com.`         | `example.com. NS IN`       |
//! | 3    | `example.com.` | `a.b.example.com. <A> IN`  |
//!
//! At step 3 the full QNAME is already within `current_zone`, so the real
//! QTYPE is sent instead of NS.

use std::net::IpAddr;

use heimdall_core::name::{Name, NameError};
use heimdall_core::record::Rtype;

// ── QnameMinError ─────────────────────────────────────────────────────────────

/// Errors produced by QNAME minimisation logic.
#[derive(Debug)]
pub enum QnameMinError {
    /// The mode string passed to [`QnameMinMode::parse`] is unrecognised.
    UnknownMode(String),
    /// Strict mode prevents falling back to the full QNAME.
    StrictFallbackForbidden {
        /// The upstream server that returned an unexpected response.
        server: IpAddr,
        /// The zone being queried at the time of fallback.
        zone: String,
    },
    /// An internal name-construction error during minimisation.
    NameError(NameError),
}

impl std::fmt::Display for QnameMinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownMode(s) => write!(f, "unknown QNAME minimisation mode: {s:?}"),
            Self::StrictFallbackForbidden { server, zone } => {
                write!(
                    f,
                    "strict QNAME minimisation: server {server} returned unexpected \
                     response for zone {zone}; fallback to full QNAME is forbidden"
                )
            }
            Self::NameError(e) => write!(f, "name construction error: {e}"),
        }
    }
}

impl std::error::Error for QnameMinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NameError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<NameError> for QnameMinError {
    fn from(e: NameError) -> Self {
        Self::NameError(e)
    }
}

// ── QnameMinMode ─────────────────────────────────────────────────────────────

/// QNAME minimisation mode (PROTO-021/022).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QnameMinMode {
    /// Relaxed (default): fall back to the full QNAME on an uncooperative
    /// server (PROTO-021).  Privacy leakage is bounded to individual queries.
    #[default]
    Relaxed,
    /// Strict: return [`QnameMinError::StrictFallbackForbidden`] rather than
    /// send the full QNAME to an uncooperative server (PROTO-022).  This
    /// preserves privacy at the cost of potential resolution failure.
    Strict,
}

impl QnameMinMode {
    /// Parses from a configuration string.
    ///
    /// Accepts `"relaxed"` and `"strict"` (case-insensitive).  Any other value
    /// returns [`QnameMinError::UnknownMode`].
    ///
    /// # Errors
    ///
    /// Returns [`QnameMinError::UnknownMode`] when `s` is not a recognised mode.
    pub fn parse(s: &str) -> Result<Self, QnameMinError> {
        match s.to_ascii_lowercase().as_str() {
            "relaxed" => Ok(Self::Relaxed),
            "strict" => Ok(Self::Strict),
            _ => Err(QnameMinError::UnknownMode(s.to_owned())),
        }
    }
}

impl std::str::FromStr for QnameMinMode {
    type Err = QnameMinError;

    /// Parses a [`QnameMinMode`] from a string.
    ///
    /// Accepts `"relaxed"` and `"strict"` (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns [`QnameMinError::UnknownMode`] when the value is not recognised.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ── QnameMinimiser ────────────────────────────────────────────────────────────

/// Per-resolution QNAME minimisation state (RFC 9156).
///
/// Each iterative resolution step maintains a `QnameMinimiser`.  The
/// minimiser tracks the current zone cut and computes the minimal QNAME to
/// send to the next authoritative server.
pub struct QnameMinimiser {
    /// The complete QNAME the client asked for.
    full_qname: Name,
    /// The zone cut the resolver has currently reached.
    current_zone: Name,
    /// Set to `true` when a relaxed-mode fallback to the full QNAME occurred.
    fell_back: bool,
    /// The configured minimisation mode for this resolution.
    pub mode: QnameMinMode,
}

impl QnameMinimiser {
    /// Creates a new `QnameMinimiser` for `full_qname` starting from the root zone.
    #[must_use]
    pub fn new(full_qname: Name, mode: QnameMinMode) -> Self {
        Self {
            full_qname,
            current_zone: Name::root(),
            fell_back: false,
            mode,
        }
    }

    /// Returns the minimised `(qname, qtype)` to send for the current step.
    ///
    /// The logic:
    ///
    /// 1. If a fallback has already occurred, return the full QNAME with the
    ///    real qtype immediately.
    /// 2. If `current_zone` has reached SLD depth (`label_count >= 2`) and
    ///    `full_qname` is within `current_zone`, the resolver has reached the
    ///    authoritative zone; return the full QNAME with the real qtype.
    /// 3. Otherwise, build the name one label below `current_zone` within
    ///    `full_qname` and return it with qtype `NS` to probe the next zone cut.
    ///
    /// # Privacy note
    ///
    /// QNAME minimisation is most effective above the SLD level.  Root (`"."`)
    /// and TLD zones (one label, e.g. `"com."`) are always queried with the
    /// minimised QNAME regardless of bailiwick; the full QNAME is only sent
    /// once the resolver has followed delegations down to at least the SLD
    /// (`current_zone.label_count() >= 2`).  This prevents accidental disclosure
    /// of the full QNAME to root and TLD servers.
    #[must_use]
    pub fn minimised_query(&self, actual_qtype: Rtype) -> (Name, Rtype) {
        if self.fell_back {
            return (self.full_qname.clone(), actual_qtype);
        }

        // Apply the bailiwick short-circuit only from SLD level downward.
        // Root and TLD zones are always probed with a minimised QNAME.
        let is_at_sld_or_below = self.current_zone.label_count() >= 2;
        if is_at_sld_or_below && self.full_qname.is_in_bailiwick(&self.current_zone) {
            return (self.full_qname.clone(), actual_qtype);
        }

        // Build the name one label below the current zone within full_qname.
        match self.build_one_below() {
            Ok(name) => (name, Rtype::Ns),
            Err(_) => {
                // Construction failed (should not happen for valid inputs);
                // fall back to the full QNAME to avoid resolution failure.
                (self.full_qname.clone(), actual_qtype)
            }
        }
    }

    /// Advances the minimiser to the given child zone after a successful
    /// referral.
    ///
    /// Call this each time the resolver follows a referral downward.
    pub fn advance_to_zone(&mut self, new_zone: Name) {
        self.current_zone = new_zone;
    }

    /// Handles an unexpected response from a minimised query.
    ///
    /// In [`QnameMinMode::Relaxed`] mode, sets `fell_back = true` and returns
    /// the full QNAME with the real qtype for the next attempt.
    ///
    /// In [`QnameMinMode::Strict`] mode, returns
    /// [`QnameMinError::StrictFallbackForbidden`] without modifying state.
    ///
    /// # Errors
    ///
    /// Returns [`QnameMinError::StrictFallbackForbidden`] in strict mode.
    pub fn handle_fallback(
        &mut self,
        server: IpAddr,
        zone: String,
        actual_qtype: Rtype,
    ) -> Result<(Name, Rtype), QnameMinError> {
        match self.mode {
            QnameMinMode::Relaxed => {
                self.fell_back = true;
                Ok((self.full_qname.clone(), actual_qtype))
            }
            QnameMinMode::Strict => Err(QnameMinError::StrictFallbackForbidden { server, zone }),
        }
    }

    /// Returns `true` if a relaxed-mode fallback to the full QNAME has occurred.
    #[must_use]
    pub fn has_fallen_back(&self) -> bool {
        self.fell_back
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Builds the name that is exactly one label below `current_zone` within
    /// `full_qname`.
    ///
    /// Given `full_qname = "a.b.example.com."` and `current_zone = "com."`,
    /// the labels of `full_qname` from the right (excluding root) are:
    /// `["com", "example", "b", "a"]`.  We want `current_zone.label_count() + 1`
    /// labels from the right, which gives `["com", "example"]` → `"example.com."`.
    ///
    /// # Errors
    ///
    /// Returns [`QnameMinError::NameError`] on any name construction failure.
    fn build_one_below(&self) -> Result<Name, QnameMinError> {
        let full_labels: Vec<&[u8]> = self.full_qname.iter_labels().collect();
        let zone_label_count = self.current_zone.label_count();

        // We need zone_label_count + 1 labels from the right of full_qname.
        let target_count = zone_label_count + 1;

        if full_labels.len() < target_count {
            // full_qname is shallower than needed; fall back to the full name.
            return Ok(self.full_qname.clone());
        }

        // Labels in the slice are ordered left-to-right (most specific first).
        // We want the rightmost `target_count` of them.
        let offset = full_labels.len() - target_count;
        let chosen_labels = &full_labels[offset..];

        // Build the Name from those labels (they are already in left-to-right order).
        let mut name = Name::root();
        // We must add labels from the most specific (leftmost in `chosen_labels`)
        // to the least specific, but `Name` stores them in wire order (left to right).
        // Since chosen_labels[0] is the leftmost (most specific of the chosen set),
        // append them in order. But we actually need to traverse top-down:
        // chosen_labels from offset..end are [label_at_depth_offset, ..., rightmost_label].
        // For "example.com." with offset=1: labels = ["example", "com"].
        // Wire format is: \x07example\x03com\x00.
        // We want to prepend them from left to right: first "example", then "com".
        //
        // Wait — iter_labels yields labels left to right (most specific first):
        // "a.b.example.com." → ["a", "b", "example", "com"]
        // Rightmost 2 (target_count=2 for zone="com.") → offset=2 → ["example", "com"]
        // So we append "example" then "com" to root → "example.com." ✓
        for &label in chosen_labels {
            name.append_label(label)?;
        }

        Ok(name)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("INVARIANT: valid test name")
    }

    #[test]
    fn minimised_query_at_root_gives_tld_ns() {
        // full_qname = "a.b.example.com.", current_zone = "."
        let minimiser = QnameMinimiser::new(name("a.b.example.com."), QnameMinMode::Relaxed);
        let (q, qtype) = minimiser.minimised_query(Rtype::A);
        assert_eq!(q, name("com."), "minimised name should be 'com.'");
        assert_eq!(qtype, Rtype::Ns, "minimised qtype should be NS");
    }

    #[test]
    fn minimised_query_after_advance_to_com() {
        let mut minimiser = QnameMinimiser::new(name("a.b.example.com."), QnameMinMode::Relaxed);
        minimiser.advance_to_zone(name("com."));
        let (q, qtype) = minimiser.minimised_query(Rtype::A);
        assert_eq!(q, name("example.com."));
        assert_eq!(qtype, Rtype::Ns);
    }

    #[test]
    fn minimised_query_at_target_zone_gives_full_qname() {
        let mut minimiser = QnameMinimiser::new(name("a.b.example.com."), QnameMinMode::Relaxed);
        minimiser.advance_to_zone(name("example.com."));
        let (q, qtype) = minimiser.minimised_query(Rtype::A);
        assert_eq!(q, name("a.b.example.com."));
        assert_eq!(
            qtype,
            Rtype::A,
            "should send the real qtype at the target zone"
        );
    }

    #[test]
    fn relaxed_fallback_returns_full_qname() {
        let server: IpAddr = "1.2.3.4".parse().unwrap();
        let mut minimiser = QnameMinimiser::new(name("a.b.example.com."), QnameMinMode::Relaxed);
        let result = minimiser.handle_fallback(server, "com.".into(), Rtype::A);
        assert!(result.is_ok(), "relaxed fallback must succeed");
        let (q, qtype) = result.unwrap();
        assert_eq!(q, name("a.b.example.com."));
        assert_eq!(qtype, Rtype::A);
        assert!(minimiser.has_fallen_back());
    }

    #[test]
    fn strict_fallback_returns_error() {
        let server: IpAddr = "1.2.3.4".parse().unwrap();
        let mut minimiser = QnameMinimiser::new(name("a.b.example.com."), QnameMinMode::Strict);
        let result = minimiser.handle_fallback(server, "com.".into(), Rtype::A);
        assert!(
            matches!(result, Err(QnameMinError::StrictFallbackForbidden { .. })),
            "strict mode must return error on fallback"
        );
        assert!(
            !minimiser.has_fallen_back(),
            "fell_back must remain false in strict mode"
        );
    }

    #[test]
    fn mode_from_str_relaxed() {
        assert!(matches!(
            QnameMinMode::parse("relaxed"),
            Ok(QnameMinMode::Relaxed)
        ));
        assert!(matches!(
            QnameMinMode::parse("RELAXED"),
            Ok(QnameMinMode::Relaxed)
        ));
    }

    #[test]
    fn mode_from_str_strict() {
        assert!(matches!(
            QnameMinMode::parse("strict"),
            Ok(QnameMinMode::Strict)
        ));
    }

    #[test]
    fn mode_from_str_unknown_returns_error() {
        let result = QnameMinMode::parse("turbo");
        assert!(matches!(result, Err(QnameMinError::UnknownMode(_))));
    }
}
