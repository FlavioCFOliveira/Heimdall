// SPDX-License-Identifier: MIT

//! Zone-file directive handlers: `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`
//! (Task #215).
//!
//! Each handler is called by the zone parser when it encounters the
//! corresponding directive keyword.

use std::path::PathBuf;

use crate::{
    header::Qclass,
    name::{Name, NameError},
    record::{Record, Rtype},
    zone::{
        ZoneError,
        limits::{LimitKind, ZoneLimits},
        parser::ZoneParser,
        tokenizer::{Token, Tokenizer},
    },
};

// ── $ORIGIN ───────────────────────────────────────────────────────────────────

/// Handles `$ORIGIN <name>`.
///
/// Sets the current origin to the absolute domain name that follows.
///
/// # Errors
///
/// Returns [`ZoneError`] if the name token is missing or invalid.
pub(crate) fn handle_origin(
    tok: &mut Tokenizer<'_>,
    origin: &mut Option<Name>,
) -> Result<(), ZoneError> {
    let line = tok.line();
    let name_str = expect_word(tok, line, "$ORIGIN")?;
    let name = parse_absolute_name(name_str, origin.clone(), line)?;
    *origin = Some(name);
    // Consume through the end of the logical line.
    consume_line(tok)?;
    Ok(())
}

// ── $TTL ──────────────────────────────────────────────────────────────────────

/// Handles `$TTL <ttl>`.
///
/// Sets the default TTL for subsequent records.
///
/// # Errors
///
/// Returns [`ZoneError`] if the TTL token is missing or not a valid decimal
/// integer.
pub(crate) fn handle_ttl(
    tok: &mut Tokenizer<'_>,
    default_ttl: &mut Option<u32>,
) -> Result<(), ZoneError> {
    let line = tok.line();
    let ttl_str = expect_word(tok, line, "$TTL")?;
    let ttl = parse_ttl(ttl_str, line)?;
    *default_ttl = Some(ttl);
    consume_line(tok)?;
    Ok(())
}

// ── $INCLUDE ──────────────────────────────────────────────────────────────────

/// Handles `$INCLUDE <filename> [<origin>]`.
///
/// Reads the referenced file, optionally overrides the origin for its scope,
/// then parses all records within it.  After parsing the included file the
/// previous origin is restored.
///
/// # Security
///
/// Cycle detection and depth limiting are enforced before any I/O.
///
/// # Errors
///
/// Returns [`ZoneError`] on cycle, depth exceeded, I/O failure, or any parse
/// error within the included file.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_include(
    tok: &mut Tokenizer<'_>,
    current_origin: Option<Name>,
    current_default_ttl: Option<u32>,
    current_last_owner: Option<Name>,
    include_stack: &mut Vec<PathBuf>,
    limits: &ZoneLimits,
    records: &mut Vec<Record>,
    rr_count: &mut usize,
    rrsig_count: &mut usize,
    ns_count: &mut usize,
) -> Result<(), ZoneError> {
    let line = tok.line();

    if include_stack.len() >= limits.max_include_depth {
        return Err(ZoneError::IncludeDepthExceeded);
    }

    let filename_token = expect_word(tok, line, "$INCLUDE")?;
    let path = PathBuf::from(filename_token);

    // Optional origin override for the scope of the included file.
    let include_origin = match tok.peek_token()? {
        Token::Word(w) => {
            let s = w.to_string();
            tok.next_token()?; // consume
            Some(parse_absolute_name(&s, current_origin, line)?)
        }
        _ => current_origin,
    };

    consume_line(tok)?;

    // Resolve the path relative to the canonical path of the parent file
    // (if one is known).  For simplicity, resolve relative to the current
    // working directory when no parent path is recorded.
    let canonical = path
        .canonicalize()
        .map_err(|e| ZoneError::Io(e.to_string()))?;

    // Cycle detection.
    if include_stack.contains(&canonical) {
        return Err(ZoneError::IncludeCycle { path: canonical });
    }

    // Read the file.
    let src = std::fs::read_to_string(&canonical)?;

    if src.len() > limits.max_zone_size_bytes {
        return Err(ZoneError::ZoneSizeLimit(LimitKind::ZoneSizeBytes));
    }

    include_stack.push(canonical);

    let mut inner = ZoneParser::new_inner(
        &src,
        include_origin,
        current_default_ttl,
        current_last_owner,
        limits.clone(),
        include_stack.clone(),
        *rr_count,
        *rrsig_count,
        *ns_count,
    );
    let inner_records = inner.parse_all()?;

    // Propagate counters back.
    *rr_count = inner.rr_count();
    *rrsig_count = inner.rrsig_count();
    *ns_count = inner.ns_count();

    include_stack.pop();
    records.extend(inner_records);
    Ok(())
}

// ── $GENERATE ─────────────────────────────────────────────────────────────────

/// Handles `$GENERATE <range> <lhs> [<type>] <rhs>`.
///
/// Expands to a set of synthetic resource records.
///
/// `range` syntax: `start-stop[/step]`.
/// Template substitution: `$` or `${offset[,width[,base]]}`.
///
/// # Security
///
/// The total expansion count is bounded by `limits.max_generate_records`
/// (THREAT-067).
///
/// # Errors
///
/// Returns [`ZoneError`] on malformed range, template error, or limit
/// violation.
pub(crate) fn handle_generate(
    tok: &mut Tokenizer<'_>,
    origin: Option<&Name>,
    default_ttl: Option<u32>,
    _last_owner: Option<&Name>,
    limits: &ZoneLimits,
    records: &mut Vec<Record>,
    rr_count: &mut usize,
) -> Result<(), ZoneError> {
    let line = tok.line();

    // Parse range: "start-stop[/step]"
    let range_str = expect_word(tok, line, "$GENERATE range")?;
    let (start, stop, step) = parse_generate_range(range_str, line)?;

    if step == 0 {
        return Err(ZoneError::ParseRdata {
            line,
            rtype: "$GENERATE".into(),
            reason: "step must be > 0".into(),
        });
    }

    // Count iterations.
    if stop < start {
        // Empty range — nothing to generate.
        consume_line(tok)?;
        return Ok(());
    }
    let iterations = (stop - start) / step + 1;
    if iterations > limits.max_generate_records {
        return Err(ZoneError::GenerateOverflow { line });
    }

    // Parse lhs (owner template).
    let lhs_tok = expect_word(tok, line, "$GENERATE lhs")?;
    let lhs = lhs_tok.to_string();

    // Peek at the next token to decide if it's a type or the rhs.
    let (rtype, rhs) = {
        let next = tok.peek_token()?;
        match next {
            Token::Word(w) => {
                // Try to parse as a record type.
                if let Some(rt) = parse_generate_rtype(w) {
                    tok.next_token()?; // consume the type
                    let rhs_tok = expect_word(tok, line, "$GENERATE rhs")?;
                    (rt, rhs_tok.to_string())
                } else {
                    // Not a type — treat as rhs with default type A.
                    let rhs_tok = w.to_string();
                    tok.next_token()?; // consume
                    (Rtype::A, rhs_tok)
                }
            }
            _ => {
                return Err(ZoneError::ParseRdata {
                    line,
                    rtype: "$GENERATE".into(),
                    reason: "expected rhs template".into(),
                });
            }
        }
    };

    consume_line(tok)?;

    // Determine TTL.
    let ttl = default_ttl.ok_or(ZoneError::ParseRdata {
        line,
        rtype: "$GENERATE".into(),
        reason: "no TTL defined (set $TTL or specify a TTL on an earlier record)".into(),
    })?;

    let class = Qclass::In;

    // Generate records.
    let mut i = start;
    loop {
        if i > stop {
            break;
        }

        // Expand the lhs template to an owner name.
        let owner_str = expand_generate_template(&lhs, i, line)?;
        let owner = parse_absolute_name(&owner_str, origin.cloned(), line)?;

        // Expand the rhs template to RDATA text.
        let rdata_str = expand_generate_template(&rhs, i, line)?;

        // Parse the RDATA for the given type.
        let rdata =
            crate::zone::parser::parse_rdata_from_str(rtype, &rdata_str, origin.cloned(), line)?;

        records.push(Record {
            name: owner,
            rtype,
            rclass: class,
            ttl,
            rdata,
        });
        *rr_count += 1;

        // Guard against overflow when adding step.
        if i > stop.saturating_sub(step) {
            break;
        }
        i += step;
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parses `start-stop[/step]` from a `$GENERATE` range token.
fn parse_generate_range(s: &str, line: usize) -> Result<(u32, u32, u32), ZoneError> {
    let err = || ZoneError::ParseRdata {
        line,
        rtype: "$GENERATE".into(),
        reason: format!("invalid range '{s}': expected start-stop[/step]"),
    };

    // Split on '/'.
    let (range_part, step) = if let Some(idx) = s.find('/') {
        let step_str = &s[idx + 1..];
        let step: u32 = step_str.parse().map_err(|_| err())?;
        (&s[..idx], step)
    } else {
        (s, 1u32)
    };

    let dash = range_part.find('-').ok_or_else(err)?;
    let start: u32 = range_part[..dash].parse().map_err(|_| err())?;
    let stop: u32 = range_part[dash + 1..].parse().map_err(|_| err())?;

    Ok((start, stop, step))
}

/// Expands a `$GENERATE` template string for iteration index `i`.
///
/// Substitution forms:
/// - `$` → `i` in decimal.
/// - `${offset}` → `i + offset` in decimal.
/// - `${offset,width}` → zero-padded decimal.
/// - `${offset,width,base}` → formatted in `base` (d=decimal, o=octal, x=hex, X=HEX).
fn expand_generate_template(template: &str, i: u32, line: usize) -> Result<String, ZoneError> {
    let mut out = String::with_capacity(template.len() + 8);
    let bytes = template.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() {
        if bytes[pos] != b'$' {
            out.push(char::from(bytes[pos]));
            pos += 1;
            continue;
        }
        pos += 1; // skip '$'

        if pos >= bytes.len() || bytes[pos] != b'{' {
            // Plain '$' — substitute `i` as decimal.
            out.push_str(&i.to_string());
            continue;
        }
        // '${...}'
        pos += 1; // skip '{'
        let brace_start = pos;
        while pos < bytes.len() && bytes[pos] != b'}' {
            pos += 1;
        }
        if pos >= bytes.len() {
            return Err(ZoneError::GenerateOverflow { line });
        }
        let inner = &template[brace_start..pos];
        pos += 1; // skip '}'

        // Parse inner: "offset[,width[,base]]"
        let parts: Vec<&str> = inner.split(',').collect();
        let offset: i64 = parts[0].parse().unwrap_or(0);
        let width: usize = if parts.len() > 1 {
            parts[1].parse().unwrap_or(0)
        } else {
            0
        };
        let base: char = if parts.len() > 2 {
            parts[2].chars().next().unwrap_or('d')
        } else {
            'd'
        };

        // INVARIANT: .max(0) ensures the value is non-negative; u32::MAX is
        // larger than i32::MAX so no truncation occurs for valid DNS iteration
        // counts (u32).  We cap to u32::MAX rather than panic.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let val = ((i64::from(i) + offset).max(0).min(i64::from(u32::MAX))) as u32;
        let formatted = match base {
            'o' | 'O' => format!("{val:0>width$o}"),
            'x' => format!("{val:0>width$x}"),
            'X' => format!("{val:0>width$X}"),
            _ => format!("{val:0>width$}"),
        };
        out.push_str(&formatted);
    }

    Ok(out)
}

/// Attempts to parse a string as a record type for `$GENERATE`.
fn parse_generate_rtype(s: &str) -> Option<Rtype> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(Rtype::A),
        "AAAA" => Some(Rtype::Aaaa),
        "CNAME" => Some(Rtype::Cname),
        "NS" => Some(Rtype::Ns),
        "PTR" => Some(Rtype::Ptr),
        "MX" => Some(Rtype::Mx),
        "SRV" => Some(Rtype::Srv),
        "TXT" => Some(Rtype::Txt),
        _ => None,
    }
}

/// Parses an absolute domain name from a token string, falling back to
/// appending the current `origin` for relative names.
pub(crate) fn parse_absolute_name(
    s: &str,
    origin: Option<Name>,
    line: usize,
) -> Result<Name, ZoneError> {
    if s == "@" {
        return origin.ok_or(ZoneError::MissingOrigin { line });
    }
    if s.ends_with('.') {
        // Already absolute.
        Name::parse_str(s).map_err(|e| name_err(&e, line))
    } else {
        // Relative — append origin labels.
        let origin = origin.ok_or(ZoneError::MissingOrigin { line })?;
        append_relative(s, &origin, line)
    }
}

/// Appends the labels of a relative name to `origin`.
fn append_relative(relative: &str, origin: &Name, line: usize) -> Result<Name, ZoneError> {
    // Build a synthetic absolute string: relative + "." + origin_presentation
    let origin_str = origin.to_string(); // already ends with '.'
    let full = format!("{relative}.{origin_str}");
    Name::parse_str(&full).map_err(|e| name_err(&e, line))
}

/// Parses a TTL value.  Only decimal integers are currently supported.
pub(crate) fn parse_ttl(s: &str, line: usize) -> Result<u32, ZoneError> {
    s.parse::<u32>().map_err(|_| ZoneError::ParseRdata {
        line,
        rtype: "TTL".into(),
        reason: format!("'{s}' is not a valid TTL (expected decimal integer)"),
    })
}

/// Expects a [`Token::Word`] and returns its string slice.
pub(crate) fn expect_word<'src>(
    tok: &mut Tokenizer<'src>,
    line: usize,
    context: &'static str,
) -> Result<&'src str, ZoneError> {
    match tok.next_token()? {
        Token::Word(w) => Ok(w),
        Token::QuotedString(_) => Err(ZoneError::ParseRdata {
            line,
            rtype: context.into(),
            reason: "expected unquoted token".into(),
        }),
        Token::Newline | Token::Eof => Err(ZoneError::ParseRdata {
            line,
            rtype: context.into(),
            reason: "unexpected end of line".into(),
        }),
    }
}

/// Skips any remaining tokens on the current logical line.
pub(crate) fn consume_line(tok: &mut Tokenizer<'_>) -> Result<(), ZoneError> {
    loop {
        match tok.peek_token()? {
            Token::Newline => {
                tok.next_token()?;
                return Ok(());
            }
            Token::Eof => return Ok(()),
            _ => {
                tok.next_token()?;
            }
        }
    }
}

fn name_err(e: &NameError, line: usize) -> ZoneError {
    ZoneError::InvalidName {
        line,
        reason: e.to_string(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_basic() {
        let (s, e, st) = parse_generate_range("1-10", 1).unwrap();
        assert_eq!((s, e, st), (1, 10, 1));
    }

    #[test]
    fn parse_range_with_step() {
        let (s, e, st) = parse_generate_range("0-100/10", 1).unwrap();
        assert_eq!((s, e, st), (0, 100, 10));
    }

    #[test]
    fn expand_template_plain_dollar() {
        let out = expand_generate_template("host$", 5, 1).unwrap();
        assert_eq!(out, "host5");
    }

    #[test]
    fn expand_template_with_offset() {
        let out = expand_generate_template("${2}", 5, 1).unwrap();
        assert_eq!(out, "7");
    }

    #[test]
    fn expand_template_hex() {
        let out = expand_generate_template("${0,4,x}", 255, 1).unwrap();
        assert_eq!(out, "00ff");
    }

    #[test]
    fn expand_template_octal() {
        let out = expand_generate_template("${0,4,o}", 8, 1).unwrap();
        assert_eq!(out, "0010");
    }

    #[test]
    fn parse_absolute_name_with_dot() {
        let n = parse_absolute_name("example.com.", None, 1).unwrap();
        assert_eq!(n.to_string(), "example.com.");
    }

    #[test]
    fn parse_absolute_name_relative() {
        let origin = Name::parse_str("example.com.").unwrap();
        let n = parse_absolute_name("host", Some(origin), 1).unwrap();
        assert_eq!(n.to_string(), "host.example.com.");
    }

    #[test]
    fn parse_absolute_name_at() {
        let origin = Name::parse_str("example.com.").unwrap();
        let n = parse_absolute_name("@", Some(origin.clone()), 1).unwrap();
        assert_eq!(n, origin);
    }

    #[test]
    fn parse_absolute_name_missing_origin() {
        let result = parse_absolute_name("host", None, 1);
        assert!(matches!(result, Err(ZoneError::MissingOrigin { .. })));
    }

    #[test]
    fn parse_ttl_valid() {
        assert_eq!(parse_ttl("3600", 1).unwrap(), 3600);
    }

    #[test]
    fn parse_ttl_invalid() {
        assert!(parse_ttl("abc", 1).is_err());
    }
}
