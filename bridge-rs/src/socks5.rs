//! SOCKS5 protocol engine for RFC 1928 compliance.
//!
//! Handles SOCKS5 client authentication greeting, request parsing,
//! destination routing evaluation via SmartRouter, outbound TCP connection,
//! success/failure response formatting, and zero-copy bidirectional streaming.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::dns::connect_to_remote;
use crate::metrics::ProxyMetrics;
use crate::router::SmartRouter;

/// RFC 1928 SOCKS5 Protocol Constants
pub const SOCKS_VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// Reply status codes (RFC 1928 Section 6)
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Handshake timeout duration to mitigate slowloris attacks
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Buffer sizes for asymmetric zero-copy relay:
/// Upstream (client -> remote): 16 KB (HTTP requests / small packets)
/// Downstream (remote -> client): 64 KB (high-throughput 4K media chunks)
pub const UPSTREAM_BUF_SIZE: usize = 16 * 1024;
pub const DOWNSTREAM_BUF_SIZE: usize = 64 * 1024;

/// Socket buffer size: 128 KB for high-throughput 4K streaming
pub const SOCKET_BUF_SIZE: usize = 128 * 1024;

/// Destination target parsed from SOCKS5 CONNECT request
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Socks5Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Socks5Target {
    pub fn host_and_port(&self) -> (String, u16) {
        match self {
            Socks5Target::Ip(sa) => (sa.ip().to_string(), sa.port()),
            Socks5Target::Domain(domain, port) => (domain.clone(), *port),
        }
    }
}

pub fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = sock.set_send_buffer_size(SOCKET_BUF_SIZE);
}

/// Negotiates SOCKS5 authentication method (RFC 1928 Section 3).
pub async fn negotiate_auth<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut ver_nmethods = [0u8; 2];
    stream.read_exact(&mut ver_nmethods).await?;
    let ver = ver_nmethods[0];
    let nmethods = ver_nmethods[1] as usize;

    if ver != SOCKS_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported SOCKS version"));
    }
    if nmethods == 0 {
        let _ = stream.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await;
        let _ = stream.flush().await;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "No auth methods offered"));
    }

    let mut methods = [0u8; 256];
    stream.read_exact(&mut methods[..nmethods]).await?;

    if methods[..nmethods].contains(&METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        stream.flush().await?;
        Ok(())
    } else {
        let _ = stream.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await;
        let _ = stream.flush().await;
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "No acceptable auth methods"))
    }
}

/// Parses SOCKS5 request frame (RFC 1928 Section 4).
pub async fn parse_connect_request<S>(stream: &mut S) -> io::Result<Socks5Target>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;

    let ver = hdr[0];
    let cmd = hdr[1];
    let rsv = hdr[2];
    let atyp = hdr[3];

    if ver != SOCKS_VERSION {
        let _ = stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SOCKS version in request"));
    }

    if rsv != 0x00 {
        let _ = stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid reserved field"));
    }

    // Read destination address according to atyp so all request bytes are consumed
    let target = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Socks5Target::Ip(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let dlen = len_buf[0] as usize;
            if dlen == 0 {
                let _ = stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Domain length cannot be 0"));
            }
            let mut buf = [0u8; 257];
            stream.read_exact(&mut buf[..dlen + 2]).await?;
            let domain = match std::str::from_utf8(&buf[..dlen]) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let _ = stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Domain name is not valid UTF-8"));
                }
            };
            let port = u16::from_be_bytes([buf[dlen], buf[dlen + 1]]);
            Socks5Target::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[..16]);
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Socks5Target::Ip(SocketAddr::new(std::net::IpAddr::V6(ip), port))
        }
        other => {
            let _ = stream.write_all(&[SOCKS_VERSION, REP_ADDRESS_TYPE_NOT_SUPPORTED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("SOCKS5 address type 0x{other:02X} not supported")));
        }
    };

    if cmd != CMD_CONNECT {
        // Reject unsupported commands (e.g. BIND 0x02, UDP ASSOCIATE 0x03) with code 0x07
        let _ = stream.write_all(&[SOCKS_VERSION, REP_COMMAND_NOT_SUPPORTED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return Err(io::Error::new(io::ErrorKind::Unsupported, format!("SOCKS5 command 0x{cmd:02X} not supported")));
    }

    Ok(target)
}

/// Handles a single SOCKS5 stream: authentication greeting, request parsing,
/// outbound connection, reply, and zero-copy bidirectional relay.
pub async fn handle_socks5_stream(
    mut stream: TcpStream,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let _conn_guard = metrics.connection_guard();
    tune_socket(&stream);

    // 1. Handshake Phase (Greeting)
    if let Err(e) = timeout(HANDSHAKE_TIMEOUT, negotiate_auth(&mut stream)).await {
        metrics.inc_errors();
        return Err(match e {
            _ if e.to_string().contains("elapsed") => io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 greeting timeout"),
            _ => io::Error::new(io::ErrorKind::Other, "SOCKS5 greeting failed"),
        });
    }

    // 2. Request Parsing Phase
    let target = match timeout(HANDSHAKE_TIMEOUT, parse_connect_request(&mut stream)).await {
        Ok(Ok(target)) => target,
        Ok(Err(e)) => {
            metrics.inc_errors();
            return Err(e);
        }
        Err(_) => {
            metrics.inc_errors();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 request timeout"));
        }
    };

    let (host, port) = target.host_and_port();

    // 3. Routing Evaluation
    let (_should_route, _reason) = router.should_route(&host);

    // 4. Outbound Connection
    let remote_conn = connect_to_remote(&host, port).await;
    let mut remote_stream = match remote_conn {
        Some((remote, _remote_ip)) => remote,
        None => {
            let _ = stream.write_all(&[SOCKS_VERSION, REP_HOST_UNREACHABLE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            metrics.inc_errors();
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("Failed to connect to {host}:{port}")));
        }
    };

    tune_socket(&remote_stream);

    // 5. Success Reply with Bound Address
    let reply = match remote_stream.local_addr() {
        Ok(SocketAddr::V4(v4)) => {
            let o = v4.ip().octets();
            let p = v4.port().to_be_bytes();
            [SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4, o[0], o[1], o[2], o[3], p[0], p[1]]
        }
        _ => [SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0],
    };
    stream.write_all(&reply).await?;
    stream.flush().await?;

    // 6. Bidirectional Zero-Copy Relay
    match tokio::io::copy_bidirectional_with_sizes(
        &mut stream,
        &mut remote_stream,
        UPSTREAM_BUF_SIZE,
        DOWNSTREAM_BUF_SIZE,
    ).await {
        Ok((bytes_up, bytes_down)) => {
            metrics.add_bytes_up(bytes_up);
            metrics.add_bytes_down(bytes_down);
            Ok(())
        }
        Err(e) => {
            if e.kind() != io::ErrorKind::ConnectionReset && e.kind() != io::ErrorKind::NotConnected {
                metrics.inc_errors();
            }
            Err(e)
        }
    }
}

/// Runs a dedicated standalone SOCKS5 listener (e.g. on port 1080).
pub async fn run_socks5_listener(
    addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    let _ = socket.set_recv_buffer_size(SOCKET_BUF_SIZE as u32);
    let _ = socket.set_send_buffer_size(SOCKET_BUF_SIZE as u32);
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;

    println!("[SOCKS5] Dedicated listener active on {}", addr);

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let router_cloned = router.clone();
        let metrics_cloned = metrics.clone();

        tokio::spawn(async move {
            let _ = handle_socks5_stream(stream, router_cloned, metrics_cloned).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_target_host_and_port() {
        let ipv4_target = Socks5Target::Ip("127.0.0.1:8080".parse().unwrap());
        assert_eq!(ipv4_target.host_and_port(), ("127.0.0.1".to_string(), 8080));

        let domain_target = Socks5Target::Domain("example.com".to_string(), 443);
        assert_eq!(domain_target.host_and_port(), ("example.com".to_string(), 443));
    }

    #[tokio::test]
    async fn test_negotiate_auth_success() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x02, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0x00]);
        });
        negotiate_auth(&mut server).await.unwrap();
    }

    #[tokio::test]
    async fn test_negotiate_auth_unsupported() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0xFF]);
        });
        let res = negotiate_auth(&mut server).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_parse_connect_request_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90]).await.unwrap();
        });
        let target = parse_connect_request(&mut server).await.unwrap();
        assert_eq!(target.host_and_port(), ("127.0.0.1".to_string(), 8080));
    }

    #[tokio::test]
    async fn test_parse_connect_request_domain() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let domain = b"example.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            req.extend_from_slice(domain);
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });
        let target = parse_connect_request(&mut server).await.unwrap();
        assert_eq!(target.host_and_port(), ("example.com".to_string(), 443));
    }

    #[tokio::test]
    async fn test_parse_connect_request_unsupported_command() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90]).await.unwrap();
            let mut resp = [0u8; 10];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp[1], 0x07);
        });
        let res = parse_connect_request(&mut server).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_parse_connect_request_unsupported_atyp() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4]).await.unwrap();
            let mut resp = [0u8; 10];
            client.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp[1], 0x08);
        });
        let res = parse_connect_request(&mut server).await;
        assert!(res.is_err());
    }
}
