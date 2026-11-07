#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Allocates an ephemeral port by binding to 127.0.0.1:0 and immediately closing the socket.
pub async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral listener for port allocation");
    let port = listener
        .local_addr()
        .expect("Failed to get local address")
        .port();
    drop(listener);
    // Yield to allow OS socket release
    tokio::task::yield_now().await;
    port
}

/// Binds an ephemeral TCP listener on 127.0.0.1:0 and returns both the listener and its assigned port.
pub async fn bind_ephemeral_listener() -> std::io::Result<(TcpListener, u16)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// Mock TCP Echo Server for testing data streaming and relay functionality.
pub struct MockEchoServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    is_running: Arc<AtomicBool>,
    bytes_echoed: Arc<AtomicUsize>,
}

impl MockEchoServer {
    /// Starts a new Mock TCP Echo server on an ephemeral loopback port.
    pub async fn start() -> Self {
        let (listener, port) = bind_ephemeral_listener()
            .await
            .expect("Failed to bind mock echo server");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let is_running = Arc::new(AtomicBool::new(true));
        let is_running_clone = is_running.clone();
        let bytes_echoed = Arc::new(AtomicUsize::new(0));
        let bytes_echoed_clone = bytes_echoed.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        is_running_clone.store(false, Ordering::SeqCst);
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((mut socket, _client_addr)) => {
                                let counter = bytes_echoed_clone.clone();
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 65536];
                                    loop {
                                        match socket.read(&mut buf).await {
                                            Ok(0) => break, // EOF
                                            Ok(n) => {
                                                if socket.write_all(&buf[..n]).await.is_err() {
                                                    break;
                                                }
                                                counter.fetch_add(n, Ordering::Relaxed);
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
            is_running,
            bytes_echoed,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn bytes_echoed(&self) -> usize {
        self.bytes_echoed.load(Ordering::Relaxed)
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }
}

impl Drop for MockEchoServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Mock HTTP Upstream Server returning HTTP 200 OK with test body.
pub struct MockHttpServer {
    addr: SocketAddr,
    body: Vec<u8>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    request_count: Arc<AtomicUsize>,
}

impl MockHttpServer {
    /// Starts a mock HTTP server with a default 200 OK test response body.
    pub async fn start() -> Self {
        Self::start_with_body(b"HTTP 200 OK: Mock Upstream Content".to_vec()).await
    }

    /// Starts a mock HTTP server with custom response payload bytes.
    pub async fn start_with_body(body: Vec<u8>) -> Self {
        let (listener, port) = bind_ephemeral_listener()
            .await
            .expect("Failed to bind mock http server");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();
        let body_clone = body.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((mut socket, _client_addr)) => {
                                let count = request_count_clone.clone();
                                let resp_body = body_clone.clone();
                                tokio::spawn(async move {
                                    let mut req_buf = vec![0u8; 4096];
                                    let mut total_read = 0;
                                    // Read until \r\n\r\n or EOF
                                    loop {
                                        match socket.read(&mut req_buf[total_read..]).await {
                                            Ok(0) => break,
                                            Ok(n) => {
                                                total_read += n;
                                                if req_buf[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
                                                    break;
                                                }
                                                if total_read >= req_buf.len() {
                                                    break;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }

                                    if total_read > 0 {
                                        count.fetch_add(1, Ordering::Relaxed);
                                        let headers = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                                            resp_body.len()
                                        );
                                        let _ = socket.write_all(headers.as_bytes()).await;
                                        let _ = socket.write_all(&resp_body).await;
                                        let _ = socket.flush().await;
                                    }
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Self {
            addr,
            body,
            shutdown_tx: Some(shutdown_tx),
            request_count,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Returns the target proxy endpoint address.
/// Checks the BRIDGE_PROXY_ADDR environment variable, defaulting to 127.0.0.1:8080.
pub fn get_proxy_addr() -> SocketAddr {
    std::env::var("BRIDGE_PROXY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("Invalid BRIDGE_PROXY_ADDR")
}

/// Returns the dedicated SOCKS5 endpoint address.
/// Checks the BRIDGE_SOCKS5_ADDR environment variable, defaulting to 127.0.0.1:1080.
pub fn get_socks5_addr() -> SocketAddr {
    std::env::var("BRIDGE_SOCKS5_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:1080".to_string())
        .parse()
        .expect("Invalid BRIDGE_SOCKS5_ADDR")
}

/// Probes whether a TCP service is accepting connections at the specified address.
pub async fn check_proxy_alive(addr: SocketAddr) -> bool {
    tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Verifies that the proxy server is reachable, returning an error message if not.
pub async fn ensure_proxy_ready(addr: SocketAddr) -> Result<(), String> {
    if check_proxy_alive(addr).await {
        Ok(())
    } else {
        Err(format!(
            "Target proxy daemon is not accepting connections at {}. \
            Ensure ZapretTVBridge is running or set BRIDGE_PROXY_ADDR / BRIDGE_SOCKS5_ADDR.",
            addr
        ))
    }
}

/// Establishes an HTTP CONNECT tunnel through the proxy to the target destination.
/// Returns (stream, status_code, full_handshake_response_headers).
pub async fn http_connect_tunnel(
    proxy_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
) -> Result<(TcpStream, u16, String), String> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("Failed to connect to proxy at {}: {}", proxy_addr, e))?;

    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        target_host, target_port, target_host, target_port
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("Failed to send CONNECT request: {}", e))?;

    // Read response until \r\n\r\n
    let mut resp_buf = Vec::new();
    let mut temp = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut temp)
            .await
            .map_err(|e| format!("Error reading CONNECT response: {}", e))?;
        if n == 0 {
            return Err("Proxy closed connection before completing CONNECT handshake".to_string());
        }
        resp_buf.extend_from_slice(&temp[..n]);
        if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if resp_buf.len() > 16384 {
            return Err("CONNECT response headers exceeded maximum limit".to_string());
        }
    }

    let resp_str = String::from_utf8_lossy(&resp_buf).to_string();
    let first_line = resp_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("Malformed HTTP response status line: {}", first_line));
    }
    let status_code: u16 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid status code in response line: {}", first_line))?;

    Ok((stream, status_code, resp_str))
}

/// Executes SOCKS5 authentication negotiation (Phase 1).
/// Returns the accepted authentication method code (e.g. 0x00 for No Auth, 0xFF for failure).
pub async fn socks5_handshake(stream: &mut TcpStream, methods: &[u8]) -> Result<u8, String> {
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05); // Version 5
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);

    stream
        .write_all(&greeting)
        .await
        .map_err(|e| format!("Failed to send SOCKS5 greeting: {}", e))?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| format!("Failed to read SOCKS5 greeting response: {}", e))?;

    if resp[0] != 0x05 {
        return Err(format!("Invalid SOCKS5 version byte in response: 0x{:02X}", resp[0]));
    }

    Ok(resp[1])
}

/// Reads the standard SOCKS5 reply header and bound address/port (RFC 1928).
/// Returns (reply_code, address_type).
pub async fn read_socks5_reply(stream: &mut TcpStream) -> Result<(u8, u8), String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("Failed to read SOCKS5 reply header: {}", e))?;

    if header[0] != 0x05 {
        return Err(format!("Invalid SOCKS5 reply version byte: 0x{:02X}", header[0]));
    }

    let rep = header[1];
    let atyp = header[3];

    // Read bound address and port based on ATYP
    match atyp {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut addr_buf = [0u8; 6];
            let _ = stream.read_exact(&mut addr_buf).await;
        }
        0x03 => {
            // Domain: 1 byte len + L bytes domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            if stream.read_exact(&mut len_buf).await.is_ok() {
                let domain_len = len_buf[0] as usize;
                let mut rem = vec![0u8; domain_len + 2];
                let _ = stream.read_exact(&mut rem).await;
            }
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut addr_buf = [0u8; 18];
            let _ = stream.read_exact(&mut addr_buf).await;
        }
        _ => {
            // Unknown ATYP, reply read finishes here
        }
    }

    Ok((rep, atyp))
}

/// Executes SOCKS5 CONNECT request using an IPv4 destination (ATYP 0x01).
/// Returns the server reply status code (0x00 = success, 0x04 = host unreachable, 0x05 = conn refused, etc.).
pub async fn socks5_connect_ipv4(
    stream: &mut TcpStream,
    ip: [u8; 4],
    port: u16,
) -> Result<u8, String> {
    let mut req = Vec::with_capacity(10);
    req.push(0x05); // VER
    req.push(0x01); // CMD: CONNECT
    req.push(0x00); // RSV
    req.push(0x01); // ATYP: IPv4
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port.to_be_bytes());

    stream
        .write_all(&req)
        .await
        .map_err(|e| format!("Failed to write SOCKS5 IPv4 CONNECT request: {}", e))?;

    let (rep, _) = read_socks5_reply(stream).await?;
    Ok(rep)
}

/// Executes SOCKS5 CONNECT request using a domain name destination (ATYP 0x03).
/// Returns the server reply status code.
pub async fn socks5_connect_domain(
    stream: &mut TcpStream,
    domain: &str,
    port: u16,
) -> Result<u8, String> {
    let domain_bytes = domain.as_bytes();
    if domain_bytes.len() > 255 {
        return Err("Domain length exceeds 255 bytes".to_string());
    }

    let mut req = Vec::with_capacity(7 + domain_bytes.len());
    req.push(0x05); // VER
    req.push(0x01); // CMD: CONNECT
    req.push(0x00); // RSV
    req.push(0x03); // ATYP: Domain
    req.push(domain_bytes.len() as u8);
    req.extend_from_slice(domain_bytes);
    req.extend_from_slice(&port.to_be_bytes());

    stream
        .write_all(&req)
        .await
        .map_err(|e| format!("Failed to write SOCKS5 Domain CONNECT request: {}", e))?;

    let (rep, _) = read_socks5_reply(stream).await?;
    Ok(rep)
}
