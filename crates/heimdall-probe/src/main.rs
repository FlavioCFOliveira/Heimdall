// SPDX-License-Identifier: MIT

//! Minimal HTTP health-check probe for the Dockerfile `HEALTHCHECK` directive
//! (ENV-065, Sprint 48 task #570).
//!
//! Opens a TCP connection to the observability endpoint, issues
//! `GET /healthz HTTP/1.0`, and exits 0 on HTTP 200, or 1 on any error
//! (connection refused, timeout, or non-200 status).
//!
//! # Usage
//!
//! ```text
//! heimdall-probe [<host>] [<port>] [<timeout_ms>]
//! ```
//!
//! Defaults: host = `127.0.0.1`, port = `9090`, timeout = `2000` ms.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | `/healthz` returned HTTP 200 |
//! | 1    | Connection error, timeout, or non-200 response |

#![deny(unsafe_code)]

use std::{
    io::{BufRead as _, BufReader, Write as _},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).map_or("127.0.0.1", String::as_str);
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(9090);
    let timeout_ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2_000);
    let timeout = Duration::from_millis(timeout_ms);

    let addr_str = format!("{host}:{port}");
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("heimdall-probe: invalid address {addr_str}: {e}");
            std::process::exit(1);
        }
    };

    std::process::exit(probe(host, addr, timeout));
}

fn probe(host: &str, addr: SocketAddr, timeout: Duration) -> i32 {
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("heimdall-probe: connect {addr}: {e}");
            return 1;
        }
    };

    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        eprintln!("heimdall-probe: set_read_timeout: {e}");
        return 1;
    }

    let request = format!("GET /healthz HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if let Err(e) = stream.write_all(request.as_bytes()) {
        eprintln!("heimdall-probe: send request: {e}");
        return 1;
    }

    // Read only the HTTP status line; discard headers and body.
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    if let Err(e) = reader.read_line(&mut status_line) {
        eprintln!("heimdall-probe: read response: {e}");
        return 1;
    }

    match parse_http_status(status_line.trim()) {
        Some(200) => 0,
        Some(code) => {
            eprintln!("heimdall-probe: non-200 status {code}");
            1
        }
        None => {
            eprintln!("heimdall-probe: unexpected response: {status_line:?}");
            1
        }
    }
}

/// Parse the HTTP status code from the first response line.
///
/// Accepts `"HTTP/1.x NNN ..."` and returns the three-digit code, or `None`
/// if the line does not have the expected shape.
fn parse_http_status(line: &str) -> Option<u16> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_200_ok() {
        assert_eq!(parse_http_status("HTTP/1.0 200 OK"), Some(200));
        assert_eq!(parse_http_status("HTTP/1.1 200 OK"), Some(200));
    }

    #[test]
    fn parse_non_200_returns_code() {
        assert_eq!(
            parse_http_status("HTTP/1.0 503 Service Unavailable"),
            Some(503)
        );
        assert_eq!(parse_http_status("HTTP/1.0 404 Not Found"), Some(404));
    }

    #[test]
    fn parse_empty_or_malformed_returns_none() {
        assert_eq!(parse_http_status(""), None);
        assert_eq!(parse_http_status("garbage"), None);
        assert_eq!(parse_http_status("SMTP/1.0 200 OK"), None);
        assert_eq!(parse_http_status("HTTP/1.0 abc Not-A-Number"), None);
    }

    #[test]
    fn parse_with_crlf_still_extracts_status() {
        // BufReader::read_line includes the trailing \r\n. The CRLF attaches to
        // the reason-phrase token (third split on ' '), so the numeric status code
        // token is unaffected and parses correctly without explicit trimming.
        assert_eq!(parse_http_status("HTTP/1.0 200 OK\r\n"), Some(200));
        assert_eq!(
            parse_http_status("HTTP/1.0 503 Service Unavailable\r\n"),
            Some(503)
        );
    }
}
