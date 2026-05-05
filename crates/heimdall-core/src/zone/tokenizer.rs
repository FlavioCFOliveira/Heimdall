// SPDX-License-Identifier: MIT

//! Hand-rolled RFC 1035 §5.1 zone-file tokenizer (Task #214).
//!
//! The tokenizer produces a stream of [`Token`]s from zone-file source text.
//! It handles:
//!
//! - Semicolons (`';'`) — skip to end of physical line (comment).
//! - Parentheses (`'('` / `')'`) — suppress [`Token::Newline`] until the
//!   matching `')'`, allowing multi-line RDATA.
//! - Quoted strings (`"..."`) with `\"` and `\\` escape sequences.
//! - Unquoted tokens: `\DDD` (decimal octet) and `\\` escape sequences.
//! - Tab and space as whitespace separators.
//! - [`Token::Newline`] signals a logical end-of-line (only emitted when not
//!   inside a parenthesised group).

use crate::zone::ZoneError;

// ── Token ─────────────────────────────────────────────────────────────────────

/// A token produced by the zone-file tokenizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token<'src> {
    /// An unquoted, whitespace-delimited token (slice into source).
    Word(&'src str),
    /// A `"..."` quoted string with escape sequences resolved.
    QuotedString(String),
    /// Logical end-of-line.  Not emitted while inside parentheses.
    Newline,
    /// End of input.
    Eof,
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

/// Zone-file tokenizer.
///
/// Maintains a cursor into `src` and produces [`Token`]s on demand.
pub struct Tokenizer<'src> {
    src: &'src str,
    pos: usize,
    /// Physical line number (1-based).
    line: usize,
    /// Parenthesis nesting depth.  `Newline` tokens are suppressed while > 0.
    paren_depth: usize,
    /// One-token look-ahead cache.
    peeked: Option<Result<Token<'src>, ZoneError>>,
    /// `true` when the most-recently produced non-Newline token was the first
    /// token on its logical line **and** was preceded by horizontal whitespace.
    ///
    /// RFC 1035 §5.1: if a line begins with a space or tab the owner field is
    /// omitted and the previous owner is reused ("blank owner").
    blank_owner_line: bool,
    /// `true` while we are at the beginning of a new physical line (set after
    /// emitting `Token::Newline` or at the very start of input).
    at_bol: bool,
}

impl<'src> Tokenizer<'src> {
    /// Creates a new tokenizer for `src`.
    #[must_use]
    pub fn new(src: &'src str) -> Self {
        // Start of input counts as beginning-of-line for blank-owner detection.
        Self {
            src,
            pos: 0,
            line: 1,
            paren_depth: 0,
            peeked: None,
            blank_owner_line: false,
            at_bol: true,
        }
    }

    /// Returns the current physical line number (1-based).
    #[must_use]
    pub fn line(&self) -> usize {
        self.line
    }

    /// Returns `true` if the last consumed token was the first token on its
    /// line **and** was preceded by horizontal whitespace.
    ///
    /// The parser uses this to implement RFC 1035 §5.1 blank-owner carry-over:
    /// a line that begins with whitespace reuses the owner of the previous RR.
    #[must_use]
    pub fn is_blank_owner_line(&self) -> bool {
        self.blank_owner_line
    }

    /// Returns the next token without consuming it.
    ///
    /// Repeated calls return the same token.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] if the underlying source is malformed.
    pub fn peek_token(&mut self) -> Result<Token<'src>, ZoneError> {
        if self.peeked.is_none() {
            self.peeked = Some(self.advance());
        }
        // Clone the cached result.
        match self.peeked.as_ref() {
            Some(Ok(t)) => Ok(t.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => unreachable!(),
        }
    }

    /// Consumes and returns the next token.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] if the source is malformed (e.g. unclosed
    /// string literal, invalid escape sequence, unmatched parenthesis).
    pub fn next_token(&mut self) -> Result<Token<'src>, ZoneError> {
        if let Some(cached) = self.peeked.take() {
            return cached;
        }
        self.advance()
    }

    /// Puts a token back so it will be returned by the next call to
    /// [`Tokenizer::next_token`] or [`Tokenizer::peek_token`].
    ///
    /// Only one token may be held in the peek slot at a time.  Callers must
    /// not call `put_back` when a peeked token is already cached.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the peek slot is already occupied.
    pub fn put_back(&mut self, token: Token<'src>) {
        debug_assert!(
            self.peeked.is_none(),
            "put_back called with a token already in peek slot"
        );
        self.peeked = Some(Ok(token));
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Core tokenizer step.
    fn advance(&mut self) -> Result<Token<'src>, ZoneError> {
        loop {
            // Record whether we are at the beginning of a line before consuming
            // any horizontal whitespace, so we can detect blank-owner lines.
            let was_at_bol = self.at_bol;

            // Skip horizontal whitespace (space, tab).
            let ws_start = self.pos;
            self.skip_horizontal_whitespace();
            let had_leading_ws = self.pos > ws_start;

            if self.pos >= self.src.len() {
                self.at_bol = false;
                self.blank_owner_line = false;
                return Ok(Token::Eof);
            }

            let b = self.src.as_bytes()[self.pos];

            match b {
                b'\n' => {
                    self.pos += 1;
                    self.line += 1;
                    if self.paren_depth == 0 {
                        self.at_bol = true;
                        self.blank_owner_line = false;
                        return Ok(Token::Newline);
                    }
                    // Inside parentheses: treat newline as whitespace.
                    // at_bol stays false inside a parenthesised group.
                }
                b'\r' => {
                    // CRLF: consume the '\r', let the '\n' be handled next iteration.
                    self.pos += 1;
                }
                b';' => {
                    // Comment: skip to end of physical line (do not consume '\n' here).
                    self.skip_to_newline();
                }
                b'(' => {
                    self.pos += 1;
                    self.at_bol = false;
                    self.paren_depth += 1;
                }
                b')' => {
                    if self.paren_depth == 0 {
                        return Err(ZoneError::Tokenize {
                            line: self.line,
                            msg: "unmatched closing parenthesis",
                        });
                    }
                    self.pos += 1;
                    self.at_bol = false;
                    self.paren_depth -= 1;
                }
                b'"' => {
                    // A quoted string at the start of a line with leading ws is a
                    // blank-owner line (unusual but technically valid).
                    self.blank_owner_line = was_at_bol && had_leading_ws;
                    self.at_bol = false;
                    return self.read_quoted_string();
                }
                _ => {
                    // Word token: set blank_owner_line if this is the first token
                    // on the line and it was preceded by horizontal whitespace.
                    self.blank_owner_line = was_at_bol && had_leading_ws;
                    self.at_bol = false;
                    return self.read_word();
                }
            }
        }
    }

    /// Skips space and tab characters.
    fn skip_horizontal_whitespace(&mut self) {
        while self.pos < self.src.len() {
            let b = self.src.as_bytes()[self.pos];
            if b == b' ' || b == b'\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Skips bytes until (but not including) the next `'\n'` or EOF.
    fn skip_to_newline(&mut self) {
        while self.pos < self.src.len() && self.src.as_bytes()[self.pos] != b'\n' {
            self.pos += 1;
        }
    }

    /// Reads an unquoted word token.
    ///
    /// A word ends at whitespace, `'('`, `')'`, `';'`, `'"'`, or EOF.
    /// Escape sequences (`\DDD` and `\\`) are accepted; if any are present the
    /// word contains the raw escape bytes (callers that need resolution must
    /// call [`resolve_word_escapes`]).
    fn read_word(&mut self) -> Result<Token<'src>, ZoneError> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let b = self.src.as_bytes()[self.pos];
            match b {
                b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b';' | b'"' => break,
                b'\\' => {
                    // Consume the backslash and the next character (or 3 digits).
                    self.pos += 1;
                    if self.pos >= self.src.len() {
                        return Err(ZoneError::Tokenize {
                            line: self.line,
                            msg: "backslash at end of input",
                        });
                    }
                    let next = self.src.as_bytes()[self.pos];
                    if next.is_ascii_digit() {
                        // \DDD: consume exactly 3 digits.
                        if self.pos + 2 >= self.src.len() {
                            return Err(ZoneError::Tokenize {
                                line: self.line,
                                msg: "incomplete \\DDD escape in word",
                            });
                        }
                        let d1 = self.src.as_bytes()[self.pos];
                        let d2 = self.src.as_bytes()[self.pos + 1];
                        let d3 = self.src.as_bytes()[self.pos + 2];
                        if !d1.is_ascii_digit() || !d2.is_ascii_digit() || !d3.is_ascii_digit() {
                            return Err(ZoneError::Tokenize {
                                line: self.line,
                                msg: "\\DDD escape must have exactly 3 decimal digits",
                            });
                        }
                        self.pos += 3;
                    } else {
                        // \X — consume just X.
                        self.pos += 1;
                    }
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
        // Return a slice of the original source — zero-copy.
        // INVARIANT: start..self.pos is always within a valid UTF-8 boundary
        // because we only advance by ASCII-byte amounts and the source is &str.
        Ok(Token::Word(&self.src[start..self.pos]))
    }

    /// Reads a `"..."` quoted string, resolving `\"` and `\\`.
    fn read_quoted_string(&mut self) -> Result<Token<'src>, ZoneError> {
        // Skip opening `"`.
        self.pos += 1;
        let mut s = String::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(ZoneError::Tokenize {
                    line: self.line,
                    msg: "unterminated quoted string",
                });
            }
            let b = self.src.as_bytes()[self.pos];
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(Token::QuotedString(s));
                }
                b'\n' => {
                    // Newlines inside quoted strings are allowed when inside parentheses.
                    self.line += 1;
                    s.push('\n');
                    self.pos += 1;
                }
                b'\r' => {
                    self.pos += 1;
                }
                b'\\' => {
                    self.pos += 1;
                    if self.pos >= self.src.len() {
                        return Err(ZoneError::Tokenize {
                            line: self.line,
                            msg: "backslash at end of quoted string",
                        });
                    }
                    let next = self.src.as_bytes()[self.pos];
                    if next.is_ascii_digit() {
                        // \DDD decimal escape.
                        if self.pos + 2 >= self.src.len() {
                            return Err(ZoneError::Tokenize {
                                line: self.line,
                                msg: "incomplete \\DDD escape in quoted string",
                            });
                        }
                        let d1 = ascii_digit_val(self.src.as_bytes()[self.pos]);
                        let d2 = ascii_digit_val(self.src.as_bytes()[self.pos + 1]);
                        let d3 = ascii_digit_val(self.src.as_bytes()[self.pos + 2]);
                        if d1.is_none() || d2.is_none() || d3.is_none() {
                            return Err(ZoneError::Tokenize {
                                line: self.line,
                                msg: "\\DDD escape must have exactly 3 decimal digits",
                            });
                        }
                        let val: u16 = u16::from(d1.unwrap_or(0)) * 100
                            + u16::from(d2.unwrap_or(0)) * 10
                            + u16::from(d3.unwrap_or(0));
                        if val > 255 {
                            return Err(ZoneError::Tokenize {
                                line: self.line,
                                msg: "\\DDD escape value exceeds 255",
                            });
                        }
                        // INVARIANT: val ≤ 255; cast to u8 is safe.
                        #[allow(clippy::cast_possible_truncation)]
                        s.push(val as u8 as char);
                        self.pos += 3;
                    } else {
                        // \X — literal character.
                        s.push(char::from(next));
                        self.pos += 1;
                    }
                }
                _ => {
                    s.push(char::from(b));
                    self.pos += 1;
                }
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Converts an ASCII digit byte to its numeric value, or `None` if not a digit.
fn ascii_digit_val(b: u8) -> Option<u8> {
    if b.is_ascii_digit() {
        Some(b - b'0')
    } else {
        None
    }
}

/// Resolves `\DDD` and `\\` escape sequences in an unquoted word token.
///
/// If the word contains no escapes the original bytes are returned as-is
/// (no allocation).
///
/// # Errors
///
/// Returns `None` if an escape sequence is malformed (caller converts to
/// [`ZoneError`]).
#[must_use]
pub fn resolve_word_escapes(word: &str) -> Option<Vec<u8>> {
    if !word.contains('\\') {
        return Some(word.as_bytes().to_vec());
    }
    let mut out = Vec::with_capacity(word.len());
    let bytes = word.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 1;
            if i >= bytes.len() {
                return None;
            }
            let next = bytes[i];
            if next.is_ascii_digit() {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let d1 = ascii_digit_val(bytes[i])?;
                let d2 = ascii_digit_val(bytes[i + 1])?;
                let d3 = ascii_digit_val(bytes[i + 2])?;
                let val: u16 = u16::from(d1) * 100 + u16::from(d2) * 10 + u16::from(d3);
                if val > 255 {
                    return None;
                }
                // INVARIANT: val ≤ 255; cast is safe.
                #[allow(clippy::cast_possible_truncation)]
                out.push(val as u8);
                i += 3;
            } else {
                out.push(next);
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(src: &str) -> Vec<Token<'_>> {
        let mut tok = Tokenizer::new(src);
        let mut out = Vec::new();
        loop {
            let t = tok.next_token().unwrap();
            let done = t == Token::Eof;
            out.push(t);
            if done {
                break;
            }
        }
        out
    }

    #[test]
    fn simple_words() {
        let ts = tokens("foo bar baz");
        assert_eq!(
            ts,
            [
                Token::Word("foo"),
                Token::Word("bar"),
                Token::Word("baz"),
                Token::Eof
            ]
        );
    }

    #[test]
    fn comment_skipped() {
        let ts = tokens("; this is a comment\nfoo");
        assert_eq!(ts, [Token::Newline, Token::Word("foo"), Token::Eof]);
    }

    #[test]
    fn newline_emitted() {
        let ts = tokens("a\nb");
        assert_eq!(
            ts,
            [
                Token::Word("a"),
                Token::Newline,
                Token::Word("b"),
                Token::Eof
            ]
        );
    }

    #[test]
    fn parens_suppress_newline() {
        let ts = tokens("a (\nb\n) c");
        // Newlines inside parens are suppressed.
        assert_eq!(
            ts,
            [
                Token::Word("a"),
                Token::Word("b"),
                Token::Word("c"),
                Token::Eof
            ]
        );
    }

    #[test]
    fn quoted_string() {
        let ts = tokens(r#""hello world""#);
        assert_eq!(ts, [Token::QuotedString("hello world".into()), Token::Eof]);
    }

    #[test]
    fn quoted_string_escape() {
        let ts = tokens(r#""he\"llo""#);
        assert_eq!(ts, [Token::QuotedString("he\"llo".into()), Token::Eof]);
    }

    #[test]
    fn decimal_escape_in_quoted() {
        // \065 = 'A'
        let ts = tokens("\"\\065\"");
        assert_eq!(ts, [Token::QuotedString("A".into()), Token::Eof]);
    }

    #[test]
    fn word_escape_preserved() {
        // Backslash-escapes in words are passed through verbatim.
        let ts = tokens(r"foo\.bar");
        assert_eq!(ts, [Token::Word(r"foo\.bar"), Token::Eof]);
    }

    #[test]
    fn resolve_word_no_escape() {
        let v = resolve_word_escapes("hello").unwrap();
        assert_eq!(v, b"hello");
    }

    #[test]
    fn resolve_word_decimal_escape() {
        // \065 = 'A' (65 decimal)
        let v = resolve_word_escapes(r"\065").unwrap();
        assert_eq!(v, b"A");
    }

    #[test]
    fn resolve_word_backslash_escape() {
        let v = resolve_word_escapes(r"\.").unwrap();
        assert_eq!(v, b".");
    }

    #[test]
    fn peek_does_not_consume() {
        let mut tok = Tokenizer::new("a b");
        let p1 = tok.peek_token().unwrap();
        let p2 = tok.peek_token().unwrap();
        assert_eq!(p1, p2);
        let n = tok.next_token().unwrap();
        assert_eq!(n, p1);
    }

    #[test]
    fn unmatched_paren_error() {
        let mut tok = Tokenizer::new(")");
        assert!(tok.next_token().is_err());
    }

    #[test]
    fn unterminated_string_error() {
        let mut tok = Tokenizer::new("\"abc");
        assert!(tok.next_token().is_err());
    }
}
