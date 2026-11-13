mod common;

use common::{
    get_free_port, get_proxy_addr, get_socks5_addr, http_connect_tunnel, read_socks5_reply,
    socks5_connect_domain, socks5_connect_ipv4, socks5_handshake, MockEchoServer, MockHttpServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// =========================================================================
// TIER 1: FEATURE COVERAGE TESTS
// =========================================================================

/// Tier 1: HTTP CONNECT proxying to mock HTTP upstream server.
/// Verifies RFC 7231 tunnel establishment (200 Connection Established) and HTTP GET data transfer.
#[tokio::test]
async fn test_tier1_http_connect_to_mock_http_upstream() {
    let mock_body = b"HTTP Upstream 200 OK: Content Delivered via Proxy Tunnel".to_vec();
    let mock_server = MockHttpServer::start_with_body(mock_body.clone()).await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let (mut tunnel, status, _headers) =
        http_connect_tunnel(proxy_addr, "127.0.0.1", mock_server.port())
            .await
            .expect("HTTP CONNECT handshake failed");

    assert_eq!(
        status, 200,
        "Expected HTTP 200 Connection Established from proxy"
    );

    // Send HTTP GET request through the established tunnel
    let http_get = format!(
        "GET /test-path HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        mock_server.port()
    );
    tunnel
        .write_all(http_get.as_bytes())
        .await
        .expect("Failed to send HTTP GET through tunnel");

    // Read HTTP response from the mock upstream server
    let mut response_buf = Vec::new();
    tunnel
        .read_to_end(&mut response_buf)
        .await
        .expect("Failed to read response from upstream through tunnel");

    let response_str = String::from_utf8_lossy(&response_buf);
    assert!(
        response_str.starts_with("HTTP/1.1 200 OK"),
        "Upstream response should be 200 OK, got: {}",
        response_str
    );
    assert!(
        response_buf
            .windows(mock_body.len())
            .any(|window| window == mock_body.as_slice()),
        "Response body should contain mock payload"
    );
    assert_eq!(
        mock_server.request_count(),
        1,
        "Mock server should have received exactly 1 request"
    );
}

/// Tier 1: HTTP CONNECT proxying to mock TCP echo server.
/// Verifies raw binary data streaming through an HTTP CONNECT tunnel.
#[tokio::test]
async fn test_tier1_http_connect_to_mock_tcp_echo() {
    let echo_server = MockEchoServer::start().await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let (mut tunnel, status, _) = http_connect_tunnel(proxy_addr, "127.0.0.1", echo_server.port())
        .await
        .expect("HTTP CONNECT handshake failed");

    assert_eq!(status, 200, "Expected HTTP 200 Connection Established");

    // Send binary test payload
    let test_data = (0u8..=255u8).cycle().take(4096).collect::<Vec<u8>>();
    tunnel
        .write_all(&test_data)
        .await
        .expect("Failed to write to tunnel");

    let mut echo_buf = vec![0u8; test_data.len()];
    tunnel
        .read_exact(&mut echo_buf)
        .await
        .expect("Failed to read echo from tunnel");

    assert_eq!(echo_buf, test_data, "Echoed payload must match sent data");
    assert!(
        echo_server.bytes_echoed() >= test_data.len(),
        "Echo server must record echoed bytes"
    );
}

/// Tier 1: SOCKS5 authentication negotiation (RFC 1928 Phase 1).
/// Verifies client greeting `0x05, 0x01, 0x00` receives `0x05, 0x00` (NO AUTHENTICATION).
#[tokio::test]
async fn test_tier1_socks5_handshake_negotiation() {
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    // Offer Method 0x00 (NO AUTH REQUIRED)
    let selected_method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("SOCKS5 handshake failed");

    assert_eq!(
        selected_method, 0x00,
        "Proxy should accept No Authentication (0x00)"
    );
}

/// Tier 1: SOCKS5 CONNECT via IPv4 address (ATYP 0x01) and data streaming.
/// Verifies connection establishment and full-duplex data streaming.
#[tokio::test]
async fn test_tier1_socks5_connect_ipv4_data_streaming() {
    let echo_server = MockEchoServer::start().await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    // Phase 1: Handshake
    let method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("Handshake failed");
    assert_eq!(method, 0x00);

    // Phase 2: CONNECT via IPv4 (127.0.0.1)
    let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_server.port())
        .await
        .expect("SOCKS5 CONNECT request failed");
    assert_eq!(rep, 0x00, "SOCKS5 CONNECT must succeed with REP = 0x00");

    // Phase 3: Data streaming
    let payload = b"SOCKS5 IPv4 binary data stream verification 1234567890".to_vec();
    stream
        .write_all(&payload)
        .await
        .expect("Failed to send payload through SOCKS5");

    let mut echo_buf = vec![0u8; payload.len()];
    stream
        .read_exact(&mut echo_buf)
        .await
        .expect("Failed to read echoed payload from SOCKS5");

    assert_eq!(
        echo_buf, payload,
        "Echoed payload over SOCKS5 must match exactly"
    );
}

/// Tier 1: SOCKS5 CONNECT via domain name (ATYP 0x03) and data streaming.
/// Verifies domain name parsing and subsequent HTTP data streaming.
#[tokio::test]
async fn test_tier1_socks5_connect_domain_data_streaming() {
    let mock_body = b"SOCKS5 Domain Destination Response Content".to_vec();
    let mock_server = MockHttpServer::start_with_body(mock_body.clone()).await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    // Phase 1: Handshake
    let method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("Handshake failed");
    assert_eq!(method, 0x00);

    // Phase 2: CONNECT via Domain "127.0.0.1"
    let rep = socks5_connect_domain(&mut stream, "127.0.0.1", mock_server.port())
        .await
        .expect("SOCKS5 Domain CONNECT failed");
    assert_eq!(
        rep, 0x00,
        "SOCKS5 Domain CONNECT must succeed with REP = 0x00"
    );

    // Phase 3: Send HTTP request over tunnel
    let http_req = format!(
        "GET /socks5-domain HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        mock_server.port()
    );
    stream
        .write_all(http_req.as_bytes())
        .await
        .expect("Failed to send HTTP request via SOCKS5 tunnel");

    let mut resp_buf = Vec::new();
    stream
        .read_to_end(&mut resp_buf)
        .await
        .expect("Failed to read response from SOCKS5 stream");

    assert!(
        resp_buf
            .windows(mock_body.len())
            .any(|w| w == mock_body.as_slice()),
        "Response body through SOCKS5 domain tunnel must match mock content"
    );
}

/// Tier 1: Protocol Autodetection on single port (port 8080).
/// Verifies that sending SOCKS5 greeting vs HTTP CONNECT to the same port both succeed.
#[tokio::test]
async fn test_tier1_protocol_autodetection_single_port() {
    let echo_server = MockEchoServer::start().await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    // Client Session 1: SOCKS5 protocol on proxy_addr
    {
        let mut socks_stream = TcpStream::connect(proxy_addr)
            .await
            .expect("Failed to connect session 1");
        let method = socks5_handshake(&mut socks_stream, &[0x00])
            .await
            .expect("SOCKS5 handshake failed on autodetect port");
        assert_eq!(
            method, 0x00,
            "SOCKS5 handshake must be accepted on autodetect port"
        );

        let rep = socks5_connect_ipv4(&mut socks_stream, [127, 0, 0, 1], echo_server.port())
            .await
            .expect("SOCKS5 CONNECT failed on autodetect port");
        assert_eq!(rep, 0x00);

        let msg = b"Autodetect SOCKS5 Session Data";
        socks_stream.write_all(msg).await.unwrap();
        let mut echo = vec![0u8; msg.len()];
        socks_stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, msg);
    }

    // Client Session 2: HTTP CONNECT on the EXACT SAME proxy_addr
    {
        let (mut http_tunnel, status, _) =
            http_connect_tunnel(proxy_addr, "127.0.0.1", echo_server.port())
                .await
                .expect("HTTP CONNECT failed on autodetect port");
        assert_eq!(status, 200, "HTTP CONNECT must succeed on autodetect port");

        let msg = b"Autodetect HTTP CONNECT Session Data";
        http_tunnel.write_all(msg).await.unwrap();
        let mut echo = vec![0u8; msg.len()];
        http_tunnel.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, msg);
    }
}

/// Tier 1: Dedicated SOCKS5 Listener (port 1080).
/// Verifies that the dedicated standalone SOCKS5 port handles client traffic.
#[tokio::test]
async fn test_tier1_dedicated_socks5_port() {
    let echo_server = MockEchoServer::start().await;
    let socks5_addr = get_socks5_addr();

    common::ensure_proxy_ready(socks5_addr)
        .await
        .expect("Dedicated SOCKS5 listener must be running for E2E tests");

    let mut stream = TcpStream::connect(socks5_addr)
        .await
        .expect("Failed to connect to dedicated SOCKS5 port");

    let method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("Handshake on port 1080 failed");
    assert_eq!(method, 0x00);

    let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_server.port())
        .await
        .expect("CONNECT on port 1080 failed");
    assert_eq!(rep, 0x00);

    let test_bytes = b"Dedicated port 1080 SOCKS5 data transfer";
    stream.write_all(test_bytes).await.unwrap();
    let mut echo = vec![0u8; test_bytes.len()];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, test_bytes);
}

// =========================================================================
// TIER 2: BOUNDARY & ERROR CASES
// =========================================================================

/// Tier 2: Malformed HTTP CONNECT line (missing destination port).
/// Verifies proxy rejects malformed request without crashing or hanging.
#[tokio::test]
async fn test_tier2_http_connect_malformed_missing_port() {
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    // Malformed CONNECT: host without port number
    let malformed_req = b"CONNECT 127.0.0.1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    stream
        .write_all(malformed_req)
        .await
        .expect("Failed to send malformed request");

    let mut resp = vec![0u8; 1024];
    let n = stream.read(&mut resp).await.unwrap_or(0);

    if n > 0 {
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        // Server should respond with 400 Bad Request, 502, or close connection
        assert!(
            resp_str.contains("400") || resp_str.contains("502"),
            "Expected 400 Bad Request or 502 for malformed CONNECT line, got: {}",
            resp_str
        );
    }
    // If n == 0, connection was closed by proxy, which is also an acceptable rejection
}

/// Tier 2: Malformed HTTP CONNECT line (invalid HTTP version).
/// Verifies rejection of unsupported protocol versions or garbage syntax.
#[tokio::test]
async fn test_tier2_http_connect_malformed_invalid_version() {
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    let invalid_req = b"CONNECT 127.0.0.1:443 HTTP/0.9\r\n\r\n";
    stream
        .write_all(invalid_req)
        .await
        .expect("Failed to send request with invalid version");

    let mut resp = vec![0u8; 1024];
    let n = stream.read(&mut resp).await.unwrap_or(0);

    if n > 0 {
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(
            resp_str.contains("400") || resp_str.contains("505") || resp_str.contains("502"),
            "Expected 400, 505 or 502 for invalid version, got: {}",
            resp_str
        );
    }
}

/// Tier 2: HTTP CONNECT target host unreachable.
/// Verifies proxy returns `HTTP/1.1 502 Bad Gateway` when upstream cannot be reached.
#[tokio::test]
async fn test_tier2_http_connect_target_unreachable() {
    let closed_port = get_free_port().await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let result = http_connect_tunnel(proxy_addr, "127.0.0.1", closed_port).await;

    match result {
        Ok((_, status, headers)) => {
            assert_eq!(
                status, 502,
                "Proxy must return 502 Bad Gateway for unreachable target. Headers: {}",
                headers
            );
        }
        Err(e) => {
            // Alternatively proxy may close connection or return 502 error string
            assert!(
                e.contains("502") || e.contains("closed"),
                "Expected 502 or connection termination for unreachable target, got: {}",
                e
            );
        }
    }
}

/// Tier 2: Unsupported SOCKS5 authentication methods.
/// Verifies server rejects greeting when client only offers unsupported auth methods (0x05, 0xFF).
#[tokio::test]
async fn test_tier2_socks5_unsupported_auth_methods() {
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    // Offer Method 0x02 (Username/Password) without offering 0x00 (No Auth)
    let selected_method = socks5_handshake(&mut stream, &[0x02])
        .await
        .expect("Handshake response expected");

    assert_eq!(
        selected_method, 0xFF,
        "Proxy must reject unsupported auth methods with 0xFF (NO ACCEPTABLE METHODS)"
    );
}

/// Tier 2: Unsupported SOCKS5 command (BIND 0x02).
/// Verifies proxy responds with REP = 0x07 (Command not supported).
#[tokio::test]
async fn test_tier2_socks5_unsupported_command_bind() {
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    let method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("Handshake failed");
    assert_eq!(method, 0x00);

    // Send BIND command (CMD 0x02)
    let bind_req = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];
    stream
        .write_all(&bind_req)
        .await
        .expect("Failed to write BIND request");

    let (rep, _) = read_socks5_reply(&mut stream)
        .await
        .expect("Expected SOCKS5 reply for unsupported command");

    assert_eq!(
        rep, 0x07,
        "Proxy must return 0x07 (Command not supported) for BIND, got: 0x{:02X}",
        rep
    );
}

/// Tier 2: Unsupported SOCKS5 command (UDP ASSOCIATE 0x03).
/// Verifies proxy responds with REP = 0x07 (Command not supported).
#[tokio::test]
async fn test_tier2_socks5_unsupported_command_udp() {
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    let method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("Handshake failed");
    assert_eq!(method, 0x00);

    // Send UDP ASSOCIATE command (CMD 0x03)
    let udp_req = [0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];
    stream
        .write_all(&udp_req)
        .await
        .expect("Failed to write UDP request");

    let (rep, _) = read_socks5_reply(&mut stream)
        .await
        .expect("Expected SOCKS5 reply for unsupported command");

    assert_eq!(
        rep, 0x07,
        "Proxy must return 0x07 (Command not supported) for UDP ASSOCIATE, got: 0x{:02X}",
        rep
    );
}

/// Tier 2: SOCKS5 target host unreachable.
/// Verifies proxy returns REP = 0x04 (Host unreachable) or 0x05 (Connection refused).
#[tokio::test]
async fn test_tier2_socks5_target_unreachable() {
    let closed_port = get_free_port().await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    let method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("Handshake failed");
    assert_eq!(method, 0x00);

    let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], closed_port)
        .await
        .expect("Expected SOCKS5 reply for unreachable target");

    assert!(
        rep == 0x04 || rep == 0x05,
        "Expected REP 0x04 (Host unreachable) or 0x05 (Connection refused), got: 0x{:02X}",
        rep
    );
}

/// Tier 2: Large payload transfer over HTTP CONNECT (multi-megabyte stream).
/// Verifies zero-copy relay integrity across 2 Megabytes of stream data without corruption or truncation.
#[tokio::test]
async fn test_tier2_large_payload_http_connect() {
    let echo_server = MockEchoServer::start().await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let (tunnel, status, _) = http_connect_tunnel(proxy_addr, "127.0.0.1", echo_server.port())
        .await
        .expect("HTTP CONNECT handshake failed");

    assert_eq!(status, 200);

    let total_bytes: usize = 2 * 1024 * 1024; // 2 Megabytes
    let (mut reader, mut writer) = tokio::io::split(tunnel);

    // Spawn concurrent reader
    let reader_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(total_bytes);
        let mut chunk = vec![0u8; 65536];
        while received.len() < total_bytes {
            let to_read = std::cmp::min(chunk.len(), total_bytes - received.len());
            let n = reader
                .read(&mut chunk[..to_read])
                .await
                .expect("Failed to read chunk from tunnel");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
        }
        received
    });

    // Writer generates deterministic byte sequence
    let writer_handle = tokio::spawn(async move {
        let chunk_size = 32768;
        let mut sent = 0;
        let mut chunk = vec![0u8; chunk_size];

        while sent < total_bytes {
            let this_chunk_size = std::cmp::min(chunk_size, total_bytes - sent);
            for i in 0..this_chunk_size {
                chunk[i] = ((sent + i) % 251) as u8;
            }
            writer
                .write_all(&chunk[..this_chunk_size])
                .await
                .expect("Failed to write chunk to tunnel");
            sent += this_chunk_size;
        }
        writer.flush().await.expect("Failed to flush writer");
    });

    let (_, received_data) = tokio::join!(writer_handle, reader_handle);
    let received = received_data.expect("Reader task panicked");

    assert_eq!(
        received.len(),
        total_bytes,
        "Received byte count must match total sent bytes exactly"
    );

    // Verify deterministic contents
    for (i, &byte) in received.iter().enumerate() {
        let expected = (i % 251) as u8;
        if byte != expected {
            panic!(
                "Data corruption at byte offset {}: expected 0x{:02X}, got 0x{:02X}",
                i, expected, byte
            );
        }
    }
}

/// Tier 2: Large payload transfer over SOCKS5 CONNECT (multi-megabyte stream).
/// Verifies zero-copy relay integrity across 2 Megabytes of stream data.
#[tokio::test]
async fn test_tier2_large_payload_socks5_connect() {
    let echo_server = MockEchoServer::start().await;
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    let method = socks5_handshake(&mut stream, &[0x00])
        .await
        .expect("Handshake failed");
    assert_eq!(method, 0x00);

    let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_server.port())
        .await
        .expect("CONNECT failed");
    assert_eq!(rep, 0x00);

    let total_bytes: usize = 2 * 1024 * 1024; // 2 Megabytes
    let (mut reader, mut writer) = tokio::io::split(stream);

    let reader_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(total_bytes);
        let mut chunk = vec![0u8; 65536];
        while received.len() < total_bytes {
            let to_read = std::cmp::min(chunk.len(), total_bytes - received.len());
            let n = reader
                .read(&mut chunk[..to_read])
                .await
                .expect("Failed to read chunk from SOCKS5 tunnel");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
        }
        received
    });

    let writer_handle = tokio::spawn(async move {
        let chunk_size = 32768;
        let mut sent = 0;
        let mut chunk = vec![0u8; chunk_size];

        while sent < total_bytes {
            let this_chunk_size = std::cmp::min(chunk_size, total_bytes - sent);
            for i in 0..this_chunk_size {
                chunk[i] = ((sent + i) % 241) as u8;
            }
            writer
                .write_all(&chunk[..this_chunk_size])
                .await
                .expect("Failed to write chunk to SOCKS5 tunnel");
            sent += this_chunk_size;
        }
        writer.flush().await.expect("Failed to flush writer");
    });

    let (_, received_data) = tokio::join!(writer_handle, reader_handle);
    let received = received_data.expect("Reader task panicked");

    assert_eq!(
        received.len(),
        total_bytes,
        "Received byte count over SOCKS5 must match total sent bytes"
    );

    for (i, &byte) in received.iter().enumerate() {
        let expected = (i % 241) as u8;
        if byte != expected {
            panic!(
                "SOCKS5 data corruption at byte offset {}: expected 0x{:02X}, got 0x{:02X}",
                i, expected, byte
            );
        }
    }
}

/// Tier 2: SOCKS5 invalid greeting version (e.g. SOCKS4 version byte 0x04).
/// Verifies proxy rejects non-version-5 greeting gracefully.
#[tokio::test]
async fn test_tier2_socks5_invalid_greeting_version() {
    let proxy_addr = get_proxy_addr();

    common::ensure_proxy_ready(proxy_addr)
        .await
        .expect("Proxy server must be running for E2E tests");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("Failed to connect to proxy");

    // Send SOCKS4 greeting (VER = 0x04)
    let socks4_greeting = [0x04, 0x01, 0x00];
    stream
        .write_all(&socks4_greeting)
        .await
        .expect("Failed to send invalid greeting");

    let mut resp = [0u8; 16];
    let n = stream.read(&mut resp).await.unwrap_or(0);

    // Server should reject by closing connection (n == 0) or replying with error
    if n >= 2 {
        assert_ne!(
            resp[0], 0x05,
            "Server should not accept SOCKS4 greeting as valid SOCKS5"
        );
    }
}
