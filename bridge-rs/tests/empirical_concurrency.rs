mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zapret_tv_bridge_rs::{metrics::ProxyMetrics, proxy, router::SmartRouter, socks5};

use common::{
    bind_ephemeral_listener, http_connect_tunnel, socks5_connect_ipv4, socks5_handshake,
    MockEchoServer,
};

/// Helper to spin up an in-process test proxy instance with its own metrics tracker.
async fn start_test_proxy() -> (SocketAddr, SocketAddr, Arc<ProxyMetrics>) {
    let (p_listener, p_port) = bind_ephemeral_listener()
        .await
        .expect("Failed to bind autodetect proxy port");
    let (s_listener, s_port) = bind_ephemeral_listener()
        .await
        .expect("Failed to bind dedicated SOCKS5 port");

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], p_port));
    let socks5_addr = SocketAddr::from(([127, 0, 0, 1], s_port));

    // Release temporary listeners so runners can bind
    drop(p_listener);
    drop(s_listener);
    tokio::task::yield_now().await;

    let base_dir = PathBuf::from("d:\\projects\\zapret-tv-bridge");
    let router = Arc::new(SmartRouter::new(&base_dir));
    let metrics = Arc::new(ProxyMetrics::new());

    let r1 = Arc::clone(&router);
    let m1 = Arc::clone(&metrics);
    tokio::spawn(async move {
        let _ = proxy::run_proxy_listener(proxy_addr, r1, m1).await;
    });

    let r2 = Arc::clone(&router);
    let m2 = Arc::clone(&metrics);
    tokio::spawn(async move {
        let _ = socks5::run_socks5_listener(socks5_addr, r2, m2).await;
    });

    // Wait until both ports accept connections
    for _ in 0..50 {
        let c1 = TcpStream::connect(proxy_addr).await;
        let c2 = TcpStream::connect(socks5_addr).await;
        if c1.is_ok() && c2.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Allow probes to settle and finish
    tokio::time::sleep(Duration::from_millis(100)).await;

    (proxy_addr, socks5_addr, metrics)
}

/// Stress Test 1: 100 concurrent connections across port 8080 (autodetect) and 1080 (dedicated).
/// Verifies that all 100 connections succeed and active_connections returns to 0.
#[tokio::test]
async fn test_100_concurrent_connections_no_leak() {
    let (proxy_addr, socks5_addr, metrics) = start_test_proxy().await;
    let echo_server = MockEchoServer::start().await;
    let echo_port = echo_server.port();

    let total_before = metrics.total_connections.load(Ordering::Relaxed);
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);

    let mut handles = Vec::with_capacity(100);

    // 50 concurrent HTTP CONNECT tunnels on autodetect port
    for i in 0..50 {
        let p_addr = proxy_addr;
        handles.push(tokio::spawn(async move {
            let (mut tunnel, status, _) = http_connect_tunnel(p_addr, "127.0.0.1", echo_port)
                .await
                .expect("HTTP CONNECT tunnel failed");
            assert_eq!(status, 200);

            let msg = format!("HTTP-CONCURRENCY-TEST-PAYLOAD-{}\n", i);
            tunnel
                .write_all(msg.as_bytes())
                .await
                .expect("Write failed");
            let mut buf = vec![0u8; msg.len()];
            tunnel
                .read_exact(&mut buf)
                .await
                .expect("Read exact failed");
            assert_eq!(buf, msg.as_bytes());
        }));
    }

    // 50 concurrent SOCKS5 tunnels on dedicated SOCKS5 port
    for i in 0..50 {
        let s_addr = socks5_addr;
        handles.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(s_addr)
                .await
                .expect("Failed to connect to SOCKS5 port");
            let method = socks5_handshake(&mut stream, &[0x00])
                .await
                .expect("SOCKS5 handshake failed");
            assert_eq!(method, 0x00);

            let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_port)
                .await
                .expect("SOCKS5 connect failed");
            assert_eq!(rep, 0x00);

            let msg = format!("SOCKS5-CONCURRENCY-TEST-PAYLOAD-{}\n", i);
            stream
                .write_all(msg.as_bytes())
                .await
                .expect("Write failed");
            let mut buf = vec![0u8; msg.len()];
            stream
                .read_exact(&mut buf)
                .await
                .expect("Read exact failed");
            assert_eq!(buf, msg.as_bytes());
        }));
    }

    // Await all 100 concurrent tasks
    for h in handles {
        h.await.expect("Concurrent worker task panicked");
    }

    // Wait up to 2 seconds for all connection tasks to drop their guards
    let start = std::time::Instant::now();
    while metrics.active_connections.load(Ordering::Relaxed) > 0
        && start.elapsed() < Duration::from_secs(2)
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let active = metrics.active_connections.load(Ordering::Relaxed);
    let total = metrics.total_connections.load(Ordering::Relaxed);
    let delta = total - total_before;

    println!(
        "[Test 100 Concurrency] Total delta: {}, Active remaining: {}",
        delta, active
    );

    assert_eq!(
        active, 0,
        "Active connections must return to 0 after all 100 concurrent connections finish"
    );
    assert_eq!(delta, 100, "Total connections delta must equal 100");
}

/// Stress Test 2: Concurrency with abrupt client terminations (TCP RST, sudden drop, half-close, incomplete handshakes).
/// Verifies active_connections returns to 0 and does not leak under hostile disconnection scenarios.
#[tokio::test]
async fn test_abrupt_client_terminations_rst_drop_half_close() {
    let (proxy_addr, socks5_addr, metrics) = start_test_proxy().await;
    let echo_server = MockEchoServer::start().await;
    let echo_port = echo_server.port();

    let mut handles = Vec::new();

    // Group A (25 connections): Sudden drop during data streaming
    for _ in 0..25 {
        let p_addr = proxy_addr;
        handles.push(tokio::spawn(async move {
            if let Ok((mut tunnel, 200, _)) =
                http_connect_tunnel(p_addr, "127.0.0.1", echo_port).await
            {
                let _ = tunnel.write_all(b"STREAMING-DATA-BEFORE-DROP").await;
                // Abruptly drop stream without reading response
                drop(tunnel);
            }
        }));
    }

    // Group B (25 connections): Half-close (shutdown write) during streaming
    for _ in 0..25 {
        let s_addr = socks5_addr;
        handles.push(tokio::spawn(async move {
            if let Ok(mut stream) = TcpStream::connect(s_addr).await {
                if socks5_handshake(&mut stream, &[0x00]).await.is_ok() {
                    if socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_port).await == Ok(0x00)
                    {
                        let _ = stream.write_all(b"HALF-CLOSE-TEST").await;
                        let _ = stream.shutdown().await;
                        // Read until EOF
                        let mut sink = vec![0u8; 1024];
                        let _ = stream.read_to_end(&mut sink).await;
                    }
                }
            }
        }));
    }

    // Group C (25 connections): Force TCP RST via SO_LINGER = 0
    for _ in 0..25 {
        let p_addr = proxy_addr;
        handles.push(tokio::spawn(async move {
            if let Ok((mut tunnel, 200, _)) =
                http_connect_tunnel(p_addr, "127.0.0.1", echo_port).await
            {
                let _ = tunnel.write_all(b"DATA-BEFORE-RST").await;
                // Set SO_LINGER on=true, timeout=0 for hard TCP RST on close
                let sock_ref = socket2::SockRef::from(&tunnel);
                let _ = sock_ref.set_linger(Some(Duration::from_secs(0)));
                drop(tunnel);
            }
        }));
    }

    // Group D (25 connections): Incomplete protocol handshakes (aborted mid-header / mid-greeting)
    for i in 0..25 {
        let p_addr = proxy_addr;
        let s_addr = socks5_addr;
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                // Incomplete HTTP CONNECT header: send only first few bytes and drop
                if let Ok(mut stream) = TcpStream::connect(p_addr).await {
                    let _ = stream.write_all(b"CONN").await;
                    drop(stream);
                }
            } else {
                // Incomplete SOCKS5 handshake: send only version byte 0x05 and drop
                if let Ok(mut stream) = TcpStream::connect(s_addr).await {
                    let _ = stream.write_all(&[0x05]).await;
                    drop(stream);
                }
            }
        }));
    }

    // Await all 100 abrupt termination tasks
    for h in handles {
        let _ = h.await;
    }

    // Wait up to 3 seconds for all connection guards to drop
    let start = std::time::Instant::now();
    while metrics.active_connections.load(Ordering::Relaxed) > 0
        && start.elapsed() < Duration::from_secs(3)
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let active = metrics.active_connections.load(Ordering::Relaxed);
    let total = metrics.total_connections.load(Ordering::Relaxed);
    let errors = metrics.errors_count.load(Ordering::Relaxed);

    println!(
        "[Test Abrupt Drops] Total: {}, Active remaining: {}, Recorded errors: {}",
        total, active, errors
    );

    assert_eq!(
        active, 0,
        "Active connections must return to 0 after all abrupt client disconnections"
    );
    assert!(
        total >= 75,
        "Expected at least 75 connections tracked, got: {}",
        total
    );
}

/// Stress Test 3: High-throughput 4K media streaming simulation (multi-megabyte).
/// Verifies deterministic transmission and zero data corruption across 10 MB HTTP CONNECT and SOCKS5 tunnels.
#[tokio::test]
async fn test_high_throughput_4k_streaming_multi_mb() {
    let (proxy_addr, socks5_addr, _) = start_test_proxy().await;
    let echo_server = MockEchoServer::start().await;
    let echo_port = echo_server.port();

    let stream_size: usize = 10 * 1024 * 1024; // 10 Megabytes

    // 1. HTTP CONNECT 10 MB Stream
    {
        let (tunnel, status, _) = http_connect_tunnel(proxy_addr, "127.0.0.1", echo_port)
            .await
            .expect("HTTP CONNECT tunnel failed");
        assert_eq!(status, 200);

        let (mut reader, mut writer) = tokio::io::split(tunnel);

        let reader_handle = tokio::spawn(async move {
            let mut received = Vec::with_capacity(stream_size);
            let mut buf = vec![0u8; 65536];
            while received.len() < stream_size {
                let to_read = std::cmp::min(buf.len(), stream_size - received.len());
                let n = reader.read(&mut buf[..to_read]).await.expect("Read failed");
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            received
        });

        let writer_handle = tokio::spawn(async move {
            let chunk_size = 65536;
            let mut sent = 0;
            let mut chunk = vec![0u8; chunk_size];
            while sent < stream_size {
                let this_chunk = std::cmp::min(chunk_size, stream_size - sent);
                for j in 0..this_chunk {
                    chunk[j] = ((sent + j) % 251) as u8;
                }
                writer
                    .write_all(&chunk[..this_chunk])
                    .await
                    .expect("Write failed");
                sent += this_chunk;
            }
            writer.flush().await.expect("Flush failed");
        });

        let (_, recv_res) = tokio::join!(writer_handle, reader_handle);
        let received = recv_res.expect("Reader panicked");
        assert_eq!(
            received.len(),
            stream_size,
            "Received length must match 10 MB"
        );

        for (idx, &byte) in received.iter().enumerate() {
            let expected = (idx % 251) as u8;
            if byte != expected {
                panic!(
                    "Corruption in HTTP CONNECT stream at byte {}: expected {}, got {}",
                    idx, expected, byte
                );
            }
        }
        println!("[4K Stream] HTTP CONNECT 10 MB verified with 0 corruption");
    }

    // 2. SOCKS5 10 MB Stream on Dedicated Port
    {
        let mut stream = TcpStream::connect(socks5_addr)
            .await
            .expect("Connect to SOCKS5 failed");
        let method = socks5_handshake(&mut stream, &[0x00])
            .await
            .expect("Handshake failed");
        assert_eq!(method, 0x00);

        let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_port)
            .await
            .expect("Connect failed");
        assert_eq!(rep, 0x00);

        let (mut reader, mut writer) = tokio::io::split(stream);

        let reader_handle = tokio::spawn(async move {
            let mut received = Vec::with_capacity(stream_size);
            let mut buf = vec![0u8; 65536];
            while received.len() < stream_size {
                let to_read = std::cmp::min(buf.len(), stream_size - received.len());
                let n = reader.read(&mut buf[..to_read]).await.expect("Read failed");
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            received
        });

        let writer_handle = tokio::spawn(async move {
            let chunk_size = 65536;
            let mut sent = 0;
            let mut chunk = vec![0u8; chunk_size];
            while sent < stream_size {
                let this_chunk = std::cmp::min(chunk_size, stream_size - sent);
                for j in 0..this_chunk {
                    chunk[j] = ((sent + j) % 241) as u8;
                }
                writer
                    .write_all(&chunk[..this_chunk])
                    .await
                    .expect("Write failed");
                sent += this_chunk;
            }
            writer.flush().await.expect("Flush failed");
        });

        let (_, recv_res) = tokio::join!(writer_handle, reader_handle);
        let received = recv_res.expect("Reader panicked");
        assert_eq!(
            received.len(),
            stream_size,
            "Received length must match 10 MB"
        );

        for (idx, &byte) in received.iter().enumerate() {
            let expected = (idx % 241) as u8;
            if byte != expected {
                panic!(
                    "Corruption in SOCKS5 stream at byte {}: expected {}, got {}",
                    idx, expected, byte
                );
            }
        }
        println!("[4K Stream] SOCKS5 10 MB verified with 0 corruption");
    }
}
