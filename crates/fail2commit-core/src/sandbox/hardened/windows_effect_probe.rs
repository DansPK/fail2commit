//! Fixed probe payload used only by the authenticated SYSTEM service probe.
//! It has no caller-supplied destination or command surface.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const WSAEACCES: i32 = 10013;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const PROBE_LINE_LIMIT: usize = 4096;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EffectResults {
    pub proxy_loopback_permitted: bool,
    pub proxy_public_route_permitted: bool,
    pub other_loopback_refused: bool,
    pub other_loopback_v6_refused: bool,
    pub direct_interface_v4_refused: bool,
    pub direct_public_v4_refused: bool,
    pub direct_private_v4_refused: bool,
    pub direct_metadata_v4_refused: bool,
    pub direct_interface_v6_refused: bool,
    pub direct_public_v6_refused: bool,
    pub direct_private_v6_refused: bool,
    pub direct_metadata_v6_refused: bool,
    pub direct_dns_udp_v4_refused: bool,
    pub direct_dns_udp_v6_refused: bool,
    pub direct_udp_other_loopback_refused: bool,
    pub direct_udp_other_loopback_v6_refused: bool,
    pub direct_udp_interface_v4_refused: bool,
    pub direct_udp_interface_v6_refused: bool,
    pub direct_udp_private_v4_refused: bool,
    pub direct_udp_private_v6_refused: bool,
    pub direct_udp_metadata_v4_refused: bool,
    pub direct_udp_metadata_v6_refused: bool,
    pub listen_v4_refused: bool,
    pub listen_v6_refused: bool,
    pub udp_listen_v4_refused: bool,
    pub udp_listen_v6_refused: bool,
}

impl EffectResults {
    pub(crate) fn complete(&self) -> bool {
        self.proxy_loopback_permitted
            && self.proxy_public_route_permitted
            && self.other_loopback_refused
            && self.other_loopback_v6_refused
            && self.direct_interface_v4_refused
            && self.direct_public_v4_refused
            && self.direct_private_v4_refused
            && self.direct_metadata_v4_refused
            && self.direct_interface_v6_refused
            && self.direct_public_v6_refused
            && self.direct_private_v6_refused
            && self.direct_metadata_v6_refused
            && self.direct_dns_udp_v4_refused
            && self.direct_dns_udp_v6_refused
            && self.direct_udp_other_loopback_refused
            && self.direct_udp_other_loopback_v6_refused
            && self.direct_udp_private_v4_refused
            && self.direct_udp_private_v6_refused
            && self.direct_udp_metadata_v4_refused
            && self.direct_udp_metadata_v6_refused
            && self.listen_v4_refused
            && self.listen_v6_refused
            && self.udp_listen_v4_refused
            && self.udp_listen_v6_refused
    }

    pub(crate) fn failed_checks(&self) -> Vec<&'static str> {
        [
            (self.proxy_loopback_permitted, "proxy_loopback_permitted"),
            (
                self.proxy_public_route_permitted,
                "proxy_public_route_permitted",
            ),
            (self.other_loopback_refused, "other_loopback_refused"),
            (self.other_loopback_v6_refused, "other_loopback_v6_refused"),
            (
                self.direct_interface_v4_refused,
                "direct_interface_v4_refused",
            ),
            (self.direct_public_v4_refused, "direct_public_v4_refused"),
            (self.direct_private_v4_refused, "direct_private_v4_refused"),
            (
                self.direct_metadata_v4_refused,
                "direct_metadata_v4_refused",
            ),
            (
                self.direct_interface_v6_refused,
                "direct_interface_v6_refused",
            ),
            (self.direct_public_v6_refused, "direct_public_v6_refused"),
            (self.direct_private_v6_refused, "direct_private_v6_refused"),
            (
                self.direct_metadata_v6_refused,
                "direct_metadata_v6_refused",
            ),
            (self.direct_dns_udp_v4_refused, "direct_dns_udp_v4_refused"),
            (self.direct_dns_udp_v6_refused, "direct_dns_udp_v6_refused"),
            (
                self.direct_udp_other_loopback_refused,
                "direct_udp_other_loopback_refused",
            ),
            (
                self.direct_udp_other_loopback_v6_refused,
                "direct_udp_other_loopback_v6_refused",
            ),
            (
                self.direct_udp_interface_v4_refused,
                "direct_udp_interface_v4_refused",
            ),
            (
                self.direct_udp_interface_v6_refused,
                "direct_udp_interface_v6_refused",
            ),
            (
                self.direct_udp_private_v4_refused,
                "direct_udp_private_v4_refused",
            ),
            (
                self.direct_udp_private_v6_refused,
                "direct_udp_private_v6_refused",
            ),
            (
                self.direct_udp_metadata_v4_refused,
                "direct_udp_metadata_v4_refused",
            ),
            (
                self.direct_udp_metadata_v6_refused,
                "direct_udp_metadata_v6_refused",
            ),
            (self.listen_v4_refused, "listen_v4_refused"),
            (self.listen_v6_refused, "listen_v6_refused"),
            (self.udp_listen_v4_refused, "udp_listen_v4_refused"),
            (self.udp_listen_v6_refused, "udp_listen_v6_refused"),
        ]
        .into_iter()
        .filter_map(|(passed, name)| (!passed).then_some(name))
        .collect()
    }
}

/// Entry used by a fixed hidden CLI action launched inside the freshly-created
/// LPAC. All fixture endpoints are injected by the SYSTEM service and are
/// validated before launch; public, private and metadata destinations are
/// compiled constants so a caller cannot turn this into a network client.
pub(crate) fn run_child() -> crate::Result<EffectResults> {
    let other_loopback = required_endpoint("F2C_PROBE_OTHER_LOOPBACK")?;
    let other_loopback_v6 = required_endpoint("F2C_PROBE_OTHER_LOOPBACK_V6")?;
    let interface_v4 = required_endpoint("F2C_PROBE_INTERFACE_V4")?;
    let interface_v6 = required_endpoint("F2C_PROBE_INTERFACE_V6")?;
    let proxy = proxy_endpoint()?;

    let results = EffectResults {
        proxy_loopback_permitted: proxy_connect_status(&proxy, "127.0.0.1:1", b"HTTP/1.1 403 "),
        proxy_public_route_permitted: proxy_connect_status(&proxy, "1.1.1.1:443", b"HTTP/1.1 200 "),
        other_loopback_refused: tcp_refused(other_loopback),
        other_loopback_v6_refused: tcp_refused(other_loopback_v6),
        direct_public_v4_refused: tcp_refused("1.1.1.1:443".parse().unwrap()),
        direct_interface_v4_refused: tcp_refused(interface_v4),
        direct_private_v4_refused: tcp_refused("10.0.0.1:443".parse().unwrap()),
        direct_metadata_v4_refused: tcp_refused("169.254.169.254:80".parse().unwrap()),
        direct_public_v6_refused: tcp_refused("[2606:4700:4700::1111]:443".parse().unwrap()),
        direct_interface_v6_refused: tcp_refused(interface_v6),
        direct_private_v6_refused: tcp_refused("[fd00::1]:443".parse().unwrap()),
        direct_metadata_v6_refused: tcp_refused("[fd00:ec2::254]:80".parse().unwrap()),
        direct_dns_udp_v4_refused: udp_connect_refused("1.1.1.1:53".parse().unwrap()),
        direct_dns_udp_v6_refused: udp_connect_refused(
            "[2606:4700:4700::1111]:53".parse().unwrap(),
        ),
        direct_udp_other_loopback_refused: udp_connect_refused(other_loopback),
        direct_udp_other_loopback_v6_refused: udp_connect_refused(other_loopback_v6),
        direct_udp_interface_v4_refused: udp_connect_refused(interface_v4),
        direct_udp_interface_v6_refused: udp_connect_refused(interface_v6),
        direct_udp_private_v4_refused: udp_connect_refused("10.0.0.1:53".parse().unwrap()),
        direct_udp_private_v6_refused: udp_connect_refused("[fd00::1]:53".parse().unwrap()),
        direct_udp_metadata_v4_refused: udp_connect_refused("169.254.169.254:53".parse().unwrap()),
        direct_udp_metadata_v6_refused: udp_connect_refused("[fd00:ec2::254]:53".parse().unwrap()),
        listen_v4_refused: listen_refused("127.0.0.1:0"),
        listen_v6_refused: listen_refused("[::1]:0"),
        udp_listen_v4_refused: udp_listen_refused("127.0.0.1:0"),
        udp_listen_v6_refused: udp_listen_refused("[::1]:0"),
    };

    // The service also checks its listeners stayed reachable from the host and
    // received no connection; these fixture routes distinguish refusal from
    // an absent private interface/listener.
    Ok(results)
}

fn required_endpoint(name: &str) -> crate::Result<SocketAddr> {
    let value = std::env::var(name)
        .map_err(|_| crate::Error::integrity(format!("SYSTEM probe fixture is missing {name}")))?;
    let address = value.parse::<SocketAddr>().map_err(|_| {
        crate::Error::integrity(format!("SYSTEM probe fixture {name} is malformed"))
    })?;
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(crate::Error::integrity(format!(
            "SYSTEM probe fixture {name} is not a concrete endpoint"
        )));
    }
    Ok(address)
}

fn proxy_endpoint() -> crate::Result<SocketAddr> {
    let value = std::env::var("HTTP_PROXY")
        .or_else(|_| std::env::var("http_proxy"))
        .map_err(|_| crate::Error::integrity("sandbox proxy endpoint is missing"))?;
    parse_proxy_endpoint(&value)
}

fn parse_proxy_endpoint(value: &str) -> crate::Result<SocketAddr> {
    let endpoint = value
        .strip_prefix("http://")
        .ok_or_else(|| crate::Error::integrity("sandbox proxy endpoint is not HTTP loopback"))?;
    let address = endpoint.parse::<SocketAddr>().map_err(|_| {
        crate::Error::integrity("sandbox proxy endpoint is not a numeric socket address")
    })?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(crate::Error::integrity(
            "sandbox proxy endpoint is not a concrete loopback listener",
        ));
    }
    Ok(address)
}

fn proxy_connect_status(address: &SocketAddr, destination: &str, expected: &[u8]) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(address, CONNECT_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
    let request = format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while response.len() < PROBE_LINE_LIMIT && !response.ends_with(b"\r\n\r\n") {
        if Instant::now() >= deadline || stream.read_exact(&mut byte).is_err() {
            return false;
        }
        response.push(byte[0]);
    }
    response.starts_with(expected)
}

fn tcp_refused(address: SocketAddr) -> bool {
    match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
        Err(error) => error.raw_os_error() == Some(WSAEACCES),
        Ok(stream) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            false
        }
    }
}

fn udp_connect_refused(address: SocketAddr) -> bool {
    let bind = match address {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let Ok(socket) = UdpSocket::bind(bind) else {
        return false;
    };
    socket
        .connect(address)
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(WSAEACCES))
}

fn listen_refused(address: &str) -> bool {
    TcpListener::bind(address)
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(WSAEACCES))
}

fn udp_listen_refused(address: &str) -> bool {
    UdpSocket::bind(address)
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(WSAEACCES))
}

#[cfg(test)]
mod tests {
    use super::EffectResults;

    #[test]
    fn effect_report_is_available_only_when_every_required_route_is_verified() {
        let complete = EffectResults {
            proxy_loopback_permitted: true,
            proxy_public_route_permitted: true,
            other_loopback_refused: true,
            other_loopback_v6_refused: true,
            direct_interface_v4_refused: true,
            direct_public_v4_refused: true,
            direct_private_v4_refused: true,
            direct_metadata_v4_refused: true,
            direct_interface_v6_refused: true,
            direct_public_v6_refused: true,
            direct_private_v6_refused: true,
            direct_metadata_v6_refused: true,
            direct_dns_udp_v4_refused: true,
            direct_dns_udp_v6_refused: true,
            direct_udp_other_loopback_refused: true,
            direct_udp_other_loopback_v6_refused: true,
            direct_udp_interface_v4_refused: true,
            direct_udp_interface_v6_refused: true,
            direct_udp_private_v4_refused: true,
            direct_udp_private_v6_refused: true,
            direct_udp_metadata_v4_refused: true,
            direct_udp_metadata_v6_refused: true,
            listen_v4_refused: true,
            listen_v6_refused: true,
            udp_listen_v4_refused: true,
            udp_listen_v6_refused: true,
        };
        assert!(complete.complete());
        let mut missing = complete.clone();
        missing.direct_dns_udp_v6_refused = false;
        assert!(!missing.complete());
        assert_eq!(missing.failed_checks(), ["direct_dns_udp_v6_refused"]);
        missing = complete.clone();
        missing.proxy_loopback_permitted = false;
        assert!(!missing.complete());
        assert_eq!(missing.failed_checks(), ["proxy_loopback_permitted"]);
        missing = complete;
        missing.direct_udp_other_loopback_v6_refused = false;
        assert!(!missing.complete());
        assert_eq!(
            missing.failed_checks(),
            ["direct_udp_other_loopback_v6_refused"]
        );
    }

    #[test]
    fn probe_proxy_target_is_a_numeric_exact_loopback_endpoint() {
        use super::parse_proxy_endpoint;

        assert_eq!(
            parse_proxy_endpoint("http://127.0.0.1:32123").unwrap(),
            "127.0.0.1:32123".parse().unwrap()
        );
        for rejected in [
            "https://127.0.0.1:32123",
            "http://localhost:32123",
            "http://8.8.8.8:32123",
            "http://127.0.0.1:0",
            "http://127.0.0.1:32123/path",
        ] {
            assert!(
                parse_proxy_endpoint(rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }
}
