use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::dns::connect_to_remote;
use crate::metrics::ProxyMetrics;
use crate::router::SmartRouter;
use crate::socks5;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(3000);
pub const MAX_HEADER_SIZE: usize = 65536;
pub const UPSTREAM_BUF_SIZE: usize = 16384;   // 16 KB client -> remote
pub const DOWNSTREAM_BUF_SIZE: usize = 65536; // 64 KB remote -> client
pub const SOCKET_BUF_SIZE: usize = 128 * 1024; // 128 KB OS socket buffer

/// Runs the unified protocol-autodetecting proxy listener with default web router.
pub async fn run_proxy_listener(
    addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let web_config = crate::web::WebConfig::default_with_port(addr.port());
    let web_router = crate::web::create_web_router(Arc::clone(&metrics), web_config);
    run_proxy_listener_with_web(addr, router, metrics, web_router).await
}

/// Runs the unified protocol-autodetecting proxy listener with a custom web router.
pub async fn run_proxy_listener_with_web(
    addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
    web_router: axum::Router,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[Proxy] Universal listener active on {}", addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => {
                metrics.inc_errors();
                continue;
            }
        };

        let router = Arc::clone(&router);
        let metrics = Arc::clone(&metrics);
        let web_router = web_router.clone();

        tokio::spawn(async move {
            let _ = handle_inbound_stream_with_web(stream, peer_addr, router, metrics, web_router).await;
        });
    }
}

/// Dispatches inbound streams via 1-byte non-destructive peek autodetection.
pub async fn handle_inbound_stream(
    stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let web_config = crate::web::WebConfig::default_with_port(8080);
    let web_router = crate::web::create_web_router(Arc::clone(&metrics), web_config);
    handle_inbound_stream_with_web(stream, peer_addr, router, metrics, web_router).await
}

/// Dispatches inbound streams via 1-byte non-destructive peek autodetection with custom web router.
pub async fn handle_inbound_stream_with_web(
    stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
    web_router: axum::Router,
) -> io::Result<()> {
    tune_socket(&stream);

    // Non-destructive 1-byte peek
    let mut peek_buf = [0u8; 1];
    let peek_res = match timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut peek_buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            metrics.inc_errors();
            return Err(e);
        }
        Err(_) => {
            metrics.inc_errors();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Handshake timed out"));
        }
    };

    if peek_res == 0 {
        return Ok(());
    }

    let first_byte = peek_buf[0];
    if first_byte == socks5::SOCKS_VERSION {
        // Dispatch to SOCKS5 engine (tracks its own connection guard)
        socks5::handle_socks5_stream(stream, router, metrics).await
    } else if first_byte.is_ascii_alphabetic() {
        // Dispatch to HTTP engine (tracks its own connection guard)
        handle_http_stream_with_web(stream, peer_addr, router, metrics, web_router).await
    } else {
        metrics.inc_errors();
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported protocol leading byte: 0x{:02X}", first_byte),
        ))
    }
}

/// Handles incoming HTTP stream: parses headers, determines routing, and delegates.
pub async fn handle_http_stream(
    stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let web_config = crate::web::WebConfig::default_with_port(8080);
    let web_router = crate::web::create_web_router(Arc::clone(&metrics), web_config);
    handle_http_stream_with_web(stream, peer_addr, router, metrics, web_router).await
}

/// Handles incoming HTTP stream with given web router.
pub async fn handle_http_stream_with_web(
    mut client: TcpStream,
    _peer_addr: SocketAddr,
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
    web_router: axum::Router,
) -> io::Result<()> {
    let _guard = metrics.connection_guard();
    let mut header_buf = Vec::with_capacity(2048);
    let mut temp = [0u8; 2048];

    let (header_len, is_connect, target, path, method_str) = loop {
        let n = match timeout(HANDSHAKE_TIMEOUT, client.read(&mut temp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                metrics.inc_errors();
                return Err(e);
            }
            Err(_) => {
                metrics.inc_errors();
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Header read timed out"));
            }
        };

        if n == 0 {
            return Ok(());
        }

        header_buf.extend_from_slice(&temp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 256];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&header_buf) {
            Ok(httparse::Status::Complete(offset)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let is_connect = method.eq_ignore_ascii_case("CONNECT");
                let mut target = path.clone();

                // Reject invalid or unsupported HTTP version (only HTTP/1.0 and HTTP/1.1 allowed)
                if req.version != Some(1) && req.version != Some(0) {
                    let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    let _ = client.flush().await;
                    metrics.inc_errors();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported HTTP version"));
                }

                if !is_connect {
                    // Extract Host header for forward plain HTTP proxy
                    for h in req.headers.iter() {
                        if h.name.eq_ignore_ascii_case("Host") {
                            if let Ok(v) = std::str::from_utf8(h.value) {
                                target = v.to_string();
                            }
                            break;
                        }
                    }
                }
                break (offset, is_connect, target, path, method);
            }
            Ok(httparse::Status::Partial) => {
                if header_buf.len() >= MAX_HEADER_SIZE {
                    let _ = client
                        .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    let _ = client.flush().await;
                    // Drain remaining in-flight incoming bytes from client socket to avoid TCP RST on Windows
                    let mut drain_buf = [0u8; 4096];
                    while let Ok(Ok(n)) = timeout(Duration::from_millis(50), client.read(&mut drain_buf)).await {
                        if n == 0 {
                            break;
                        }
                    }
                    metrics.inc_errors();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Header size exceeded"));
                }
                continue;
            }
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                let _ = client.flush().await;
                metrics.inc_errors();
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
    };

    let local_port = client.local_addr().map(|a| a.port()).unwrap_or(8080);
    let is_local = if is_connect {
        false
    } else if path.starts_with('/') && !path.starts_with("//") {
        true
    } else if is_addressed_to_self(&target, local_port) {
        true
    } else {
        false
    };

    if is_connect {
        handle_http_connect(client, &target, header_len, &header_buf, router, metrics).await
    } else if is_local {
        let mut parsed_headers = [httparse::EMPTY_HEADER; 256];
        let mut parsed_req = httparse::Request::new(&mut parsed_headers);
        let _ = parsed_req.parse(&header_buf);

        let body_slice = if header_len < header_buf.len() {
            &header_buf[header_len..]
        } else {
            &[]
        };

        crate::web::handle_local_request(
            client,
            &method_str,
            &path,
            &parsed_headers,
            body_slice,
            web_router,
        )
        .await
    } else {
        handle_plain_http(client, &target, &header_buf, router, metrics).await
    }
}

/// Handles RFC 7231 HTTP CONNECT tunneling with zero-copy bidirectional streaming.
pub async fn handle_http_connect(
    mut client: TcpStream,
    target: &str,
    header_len: usize,
    header_buf: &[u8],
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let (host, port) = match parse_connect_target(target) {
        Some((h, p)) => (h, p),
        None => {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            let _ = client.flush().await;
            metrics.inc_errors();
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Malformed CONNECT target (missing port)"));
        }
    };

    let (_should_route, _reason) = router.should_route(&host);

    // Fast failover connection via DNS candidate cache or direct lookup
    let remote_conn = connect_to_remote(&host, port).await;
    let mut remote = match remote_conn {
        Some((stream, _)) => stream,
        None => {
            metrics.inc_errors();
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            let _ = client.flush().await;
            let _ = client.shutdown().await;
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Remote connection failed"));
        }
    };

    tune_socket(&remote);

    // Send 200 Connection Established handshake response
    if let Err(e) = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await {
        metrics.inc_errors();
        return Err(e);
    }
    let _ = client.flush().await;

    // Flush any pipelined data received during header read
    if header_len < header_buf.len() {
        if let Err(e) = remote.write_all(&header_buf[header_len..]).await {
            metrics.inc_errors();
            return Err(e);
        }
        let _ = remote.flush().await;
    }

    // Zero-copy bidirectional relay with asymmetric buffer sizes
    let relay_res = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut remote,
        UPSTREAM_BUF_SIZE,
        DOWNSTREAM_BUF_SIZE,
    )
    .await;

    match relay_res {
        Ok((up, down)) => {
            metrics.add_bytes_up(up);
            metrics.add_bytes_down(down);
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

/// Handles plain forward HTTP requests.
pub async fn handle_plain_http(
    mut client: TcpStream,
    target: &str,
    initial_request: &[u8],
    router: Arc<SmartRouter>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let (host, port) = parse_host_port(target, 80);
    let (_should_route, _reason) = router.should_route(&host);

    let remote_conn = connect_to_remote(&host, port).await;
    let mut remote = match remote_conn {
        Some((stream, _)) => stream,
        None => {
            metrics.inc_errors();
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            let _ = client.flush().await;
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Plain HTTP connect failed"));
        }
    };

    tune_socket(&remote);

    if let Err(e) = remote.write_all(initial_request).await {
        metrics.inc_errors();
        return Err(e);
    }
    let _ = remote.flush().await;

    let relay_res = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut remote,
        UPSTREAM_BUF_SIZE,
        DOWNSTREAM_BUF_SIZE,
    )
    .await;

    match relay_res {
        Ok((up, down)) => {
            metrics.add_bytes_up(up);
            metrics.add_bytes_down(down);
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

/// Handles local HTTP diagnostic routes via the embedded Axum web engine.
pub async fn handle_local_route(
    client: TcpStream,
    path: &str,
) -> io::Result<()> {
    let metrics = Arc::new(ProxyMetrics::new());
    let config = crate::web::WebConfig::default();
    let router = crate::web::create_web_router(metrics, config);
    crate::web::handle_local_request(client, "GET", path, &[], &[], router).await
}

/// Checks whether an HTTP request target is addressed to the local proxy instance itself.
pub fn is_addressed_to_self(target: &str, local_port: u16) -> bool {
    let (host, port) = parse_host_port(target, local_port);
    let h = host.trim().to_ascii_lowercase();
    let is_self_host = h == "127.0.0.1"
        || h == "localhost"
        || h == "0.0.0.0"
        || h == "::1"
        || h == "[::1]";
    is_self_host && (port == local_port || port == 80)
}

/// Parses target host and port strictly for CONNECT (requires host:port).
pub fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Bracketed IPv6 address [2001:db8::1]:443
    if trimmed.starts_with('[') {
        if let Some(end_bracket) = trimmed.find(']') {
            let host = trimmed[1..end_bracket].to_string();
            let remainder = &trimmed[end_bracket + 1..];
            if remainder.starts_with(':') {
                if let Ok(p) = remainder[1..].parse::<u16>() {
                    return Some((host, p));
                }
            }
            return None;
        }
    }

    // Host:port (IPv4 or hostname)
    if let Some(pos) = trimmed.rfind(':') {
        let host = trimmed[..pos].trim();
        let port_str = &trimmed[pos + 1..];
        if let Ok(p) = port_str.parse::<u16>() {
            if !host.is_empty() {
                return Some((host.to_string(), p));
            }
        }
    }

    None
}

/// Parses target host and port with a default port fallback.
pub fn parse_host_port(target: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = parse_connect_target(target) {
        (h, p)
    } else {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            ("127.0.0.1".to_string(), default_port)
        } else {
            (trimmed.to_string(), default_port)
        }
    }
}

/// Configures socket options: TCP_NODELAY and 128 KB receive/send buffers.
pub fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = sock.set_send_buffer_size(SOCKET_BUF_SIZE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        assert_eq!(
            parse_connect_target("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_connect_target("127.0.0.1:8080"),
            Some(("127.0.0.1".to_string(), 8080))
        );
        assert_eq!(
            parse_connect_target("[::1]:443"),
            Some(("::1".to_string(), 443))
        );
        assert_eq!(parse_connect_target("127.0.0.1"), None);
        assert_eq!(parse_connect_target("example.com"), None);
        assert_eq!(parse_connect_target(""), None);
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("example.com:8080", 80),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("example.com", 80),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            parse_host_port("", 443),
            ("127.0.0.1".to_string(), 443)
        );
    }
}
