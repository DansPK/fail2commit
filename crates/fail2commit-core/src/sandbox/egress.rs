//! Shared egress policy core for Linux and hardened Windows transports.
//! Transport modules may differ; parsing, destination checks, bait inspection
//! and the job stop/report state must remain one implementation (SPEC-018 §5).

use crate::isolation::{ActivityKind, ActivityReport};
use crate::sandbox::{bait::BaitSet, netpolicy};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Report plus the stop flag shared by the proxy, bait watcher and meters.
#[derive(Default)]
pub(crate) struct Watch {
    report: Mutex<ActivityReport>,
    tripped: AtomicBool,
}

impl Watch {
    pub(crate) fn record(&self, kind: ActivityKind, detail: impl Into<String>) {
        if let Ok(mut report) = self.report.lock() {
            report.push(kind, detail);
        }
    }

    pub(crate) fn trip(&self, kind: ActivityKind, detail: impl Into<String>) {
        self.record(kind, detail);
        self.tripped.store(true, Ordering::SeqCst);
    }

    pub(crate) fn tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    pub(crate) fn take_report(&self) -> ActivityReport {
        self.report
            .lock()
            .map(|report| report.clone())
            .unwrap_or_default()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Request {
    /// Parse CONNECT authority or an absolute HTTP URI. Origin-form requests do
    /// not identify a destination and are refused by both transports.
    pub(crate) fn parse(head: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(head).ok()?;
        let line = text.split("\r\n").next()?;
        let mut parts = line.split(' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        if parts.next().is_some()
            || !valid_method(method)
            || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
            || target.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
        {
            return None;
        }
        let method = method.to_owned();
        let (host, port) = if method.eq_ignore_ascii_case("CONNECT") {
            split_authority(target, 443)?
        } else {
            let rest = target
                .strip_prefix("http://")
                .or_else(|| target.strip_prefix("HTTP://"))?;
            let authority = rest.split(['/', '?', '#']).next()?;
            split_authority(authority, 80)?
        };
        if host.is_empty() || method.is_empty() {
            return None;
        }
        Some(Self { method, host, port })
    }

    pub(crate) fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn split_authority(value: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let host = host.parse::<std::net::Ipv6Addr>().ok()?.to_string();
        let port = match tail {
            "" => default_port,
            tail if tail.starts_with(':') && !tail[1..].contains(':') => tail[1..].parse().ok()?,
            _ => return None,
        };
        return Some((host.to_owned(), port));
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port.parse().ok()?),
        Some(_) => return None,
        None => (value, default_port),
    };
    if !valid_host(host) {
        return None;
    }
    Some((host.to_owned(), port))
}

fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

pub(crate) fn all_public(addrs: &[SocketAddr]) -> bool {
    !addrs.is_empty() && addrs.iter().all(|addr| netpolicy::is_public(addr.ip()))
}

pub(crate) fn resolve(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse() {
        return Some(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    (!addrs.is_empty()).then_some(addrs)
}

pub(crate) fn has_bait(bait: Option<&BaitSet>, head: &[u8], body: &[u8]) -> bool {
    bait.is_some_and(|set| set.find_value(head).is_some() || set.find_value(body).is_some())
}

pub(crate) fn find_head_end(head: &[u8]) -> Option<usize> {
    head.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

pub(crate) fn content_length(head: &[u8]) -> Option<usize> {
    for line in String::from_utf8_lossy(head).lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                // Preserve the Linux proxy's original first-match behavior:
                // a malformed first Content-Length rejects body parsing, even
                // if a later duplicate happens to be parseable.
                return value.trim().parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn shared_request_parser_and_public_destination_policy_are_strict() {
        let connect = Request::parse(b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\n\r\n")
            .expect("CONNECT request");
        assert_eq!(connect.authority(), "registry.npmjs.org:443");
        assert!(Request::parse(b"GET /path HTTP/1.1\r\n\r\n").is_none());
        let v6 = Request::parse(b"CONNECT [2001:4860:4860::8888]:443 HTTP/1.1\r\n\r\n")
            .expect("IPv6 CONNECT request");
        assert_eq!(v6.authority(), "[2001:4860:4860::8888]:443");
        for malformed in [
            b"CONNECT [::1]trailing HTTP/1.1\r\n\r\n".as_slice(),
            b"CONNECT [::1]:443junk HTTP/1.1\r\n\r\n",
            b"CONNECT [not-ipv6]:443 HTTP/1.1\r\n\r\n",
            b"CONNECT host:443 extra HTTP/1.1\r\n\r\n",
            b"CONNECT host:443 HTTP/1.2\r\n\r\n",
            b"CONNECT user@host:443 HTTP/1.1\r\n\r\n",
            b"GET http://host/path  HTTP/1.1\r\n\r\n",
        ] {
            assert!(Request::parse(malformed).is_none(), "{malformed:?}");
        }

        let socket = |address: &str| address.parse::<SocketAddr>().unwrap();
        assert!(all_public(&[socket("104.16.0.35:443")]));
        assert!(!all_public(&[
            socket("104.16.0.35:443"),
            socket("127.0.0.1:443")
        ]));
        assert!(!all_public(&[socket("169.254.169.254:80")]));
        assert!(!all_public(&[]));
    }

    #[test]
    fn both_transports_share_bait_tripping_and_length_parsing() {
        let bait = BaitSet::generate().unwrap();
        let value = &bait.env[1].1;
        assert!(has_bait(
            Some(&bait),
            b"GET http://example.test/ HTTP/1.1\r\n\r\n",
            value.as_bytes()
        ));
        assert!(!has_bait(
            None,
            b"GET http://example.test/ HTTP/1.1\r\n\r\n",
            b""
        ));
        assert_eq!(
            content_length(b"POST http://example.test/ HTTP/1.1\r\ncontent-length: 7\r\n\r\n"),
            Some(7)
        );
        assert_eq!(
            content_length(
                b"POST http://example.test/ HTTP/1.1\r\ncontent-length: bad\r\ncontent-length: 7\r\n\r\n"
            ),
            None
        );
        assert_eq!(
            content_length(
                b"POST http://example.test/ HTTP/1.1\r\ncontent-length: 5\r\ncontent-length: 7\r\n\r\n"
            ),
            Some(5)
        );

        let watch = Watch::default();
        watch.trip(ActivityKind::Bait, "egress: example.test:80");
        assert!(watch.tripped());
        assert_eq!(watch.take_report().events[0].kind, ActivityKind::Bait);
    }
}
