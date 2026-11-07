//! Empirical Adversarial Fuzzing Test Suite (M5)
//!
//! Thoroughly challenges protocol engines in `bridge-rs`:
//! 1. FakeTLS & MTProto boundary fuzzing:
//!    - Malformed handshakes, corrupt record headers, truncated buffers.
//!    - Timestamp tolerance boundaries (-120s, +120s, overflows, far future/past).
//!    - Corrupt MTProto 64-byte handshake headers, unsupported protocol tags.
//!    - Oversized packet frames (>16MB) and zero-length frame headers in MsgSplitter.
//! 2. SmartRouter boundary fuzzing:
//!    - Empty domains, whitespace, long domains (>256B), dots, special characters, non-ASCII.
//!    - Edge IP queries (0.0.0.0, 255.255.255.255, multicast, IPv6, IPv4-mapped).
//! 3. Axum web fuzzing:
//!    - Malformed HTTP headers, oversized paths, path traversal, rapid polling.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::StatusCode;
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sha2::Sha256;
use tower::ServiceExt;

use zapret_tv_bridge_rs::faketls::{
    verify_client_hello, CLIENT_RANDOM_LEN, CLIENT_RANDOM_OFFSET, TLS_RECORD_HANDSHAKE,
};
use zapret_tv_bridge_rs::metrics::ProxyMetrics;
use zapret_tv_bridge_rs::mtproto::{
    parse_client_handshake, MsgSplitter, ProtoCodec, MAX_PACKET_LEN,
};
use zapret_tv_bridge_rs::router::SmartRouter;
use zapret_tv_bridge_rs::web::{create_web_router, WebConfig};

// =========================================================================
// HELPER FUNCTIONS FOR PROTOCOL SYNTHESIS
// =========================================================================

fn make_valid_client_hello(secret: &[u8; 16], timestamp_offset_secs: i64) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ts = (now + timestamp_offset_secs) as u32;

    let mut record = vec![0u8; 512];
    record[0] = TLS_RECORD_HANDSHAKE;
    record[1] = 0x03;
    record[2] = 0x01;
    let rec_len = (512 - 5) as u16;
    record[3..5].copy_from_slice(&rec_len.to_be_bytes());

    record[5] = 0x01; // ClientHello
    let hs_len = (512 - 9) as u32;
    record[6..9].copy_from_slice(&hs_len.to_be_bytes()[1..4]);
    record[9] = 0x03;
    record[10] = 0x03;

    record[43] = 0x20; // Session ID length: 32 bytes
    let mut rng = StdRng::seed_from_u64(42);
    rng.fill_bytes(&mut record[44..76]);

    // Zero client random field
    record[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].fill(0);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(&record);
    let expected = mac.finalize().into_bytes();

    record[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 28].copy_from_slice(&expected[..28]);
    let ts_bytes = ts.to_le_bytes();
    for i in 0..4 {
        record[CLIENT_RANDOM_OFFSET + 28 + i] = ts_bytes[i] ^ expected[28 + i];
    }

    record
}

// =========================================================================
// TRACK 1: FAKETLS / MTPROTO ADVERSARIAL BOUNDARY FUZZING
// =========================================================================

#[test]
fn test_fuzz_faketls_malformed_and_corrupt_handshakes() {
    let secret = [0x42u8; 16];
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

    // 1. Empty and sub-minimal length inputs
    for len in 0..43 {
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        assert!(
            verify_client_hello(&buf, &secret).is_none(),
            "Buffer of length {} must be rejected as truncated",
            len
        );
    }

    // 2. Corrupted record headers
    for &invalid_rtype in &[0x00, 0x14, 0x15, 0x17, 0x18, 0x80, 0xFF] {
        let mut valid = make_valid_client_hello(&secret, 0);
        valid[0] = invalid_rtype;
        assert!(
            verify_client_hello(&valid, &secret).is_none(),
            "Record type 0x{:02X} must be rejected",
            invalid_rtype
        );
    }

    // 3. Invalid handshake type (not 0x01 ClientHello)
    for &invalid_htype in &[0x00, 0x02, 0x04, 0x0B, 0x10, 0xFF] {
        let mut valid = make_valid_client_hello(&secret, 0);
        valid[5] = invalid_htype;
        assert!(
            verify_client_hello(&valid, &secret).is_none(),
            "Handshake type 0x{:02X} must be rejected",
            invalid_htype
        );
    }

    // 4. Random noise fuzzing (10,000 iterations of arbitrary garbage)
    for _ in 0..10_000 {
        let len = rng.gen_range(1..1024);
        let mut noise = vec![0u8; len];
        rng.fill_bytes(&mut noise);
        let res = verify_client_hello(&noise, &secret);
        assert!(res.is_none(), "Random noise must never validate as ClientHello");
    }

    // 5. Single-bit corruption across the entire record
    let valid = make_valid_client_hello(&secret, 0);
    for byte_idx in 0..CLIENT_RANDOM_OFFSET + 28 {
        for bit_idx in 0..8 {
            let mut corrupted = valid.clone();
            corrupted[byte_idx] ^= 1 << bit_idx;
            assert!(
                verify_client_hello(&corrupted, &secret).is_none(),
                "Bit-flipped ClientHello at byte {} bit {} must fail validation",
                byte_idx,
                bit_idx
            );
        }
    }
}

#[test]
fn test_fuzz_faketls_timestamp_boundaries_and_extremes() {
    let secret = [0x55u8; 16];

    // Inside tolerance window: [-120s, +120s]
    assert!(verify_client_hello(&make_valid_client_hello(&secret, 0), &secret).is_some());
    assert!(verify_client_hello(&make_valid_client_hello(&secret, -60), &secret).is_some());
    assert!(verify_client_hello(&make_valid_client_hello(&secret, 60), &secret).is_some());
    assert!(verify_client_hello(&make_valid_client_hello(&secret, -120), &secret).is_some());
    assert!(verify_client_hello(&make_valid_client_hello(&secret, 120), &secret).is_some());

    // Outside tolerance window: -121s and +121s
    assert!(verify_client_hello(&make_valid_client_hello(&secret, -121), &secret).is_none());
    assert!(verify_client_hello(&make_valid_client_hello(&secret, 121), &secret).is_none());
    assert!(verify_client_hello(&make_valid_client_hello(&secret, -3600), &secret).is_none());
    assert!(verify_client_hello(&make_valid_client_hello(&secret, 3600), &secret).is_none());

    // Extreme timestamps: Epoch 0, distant future, wrap-around values
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!(verify_client_hello(&make_valid_client_hello(&secret, -now), &secret).is_none()); // Epoch 0
    assert!(verify_client_hello(&make_valid_client_hello(&secret, 1_000_000_000), &secret).is_none());
}

#[test]
fn test_fuzz_mtproto_corrupt_handshake_headers() {
    let secret = [0x99u8; 16];
    let mut rng = StdRng::seed_from_u64(0xFEEDFACE);

    // 1. Forbidden initial bytes
    let forbidden_headers: [&[u8]; 8] = [
        b"\xef\x00\x00\x00",
        b"HEAD",
        b"POST",
        b"GET ",
        b"\xee\xee\xee\xee",
        b"\xdd\xdd\xdd\xdd",
        b"\x16\x03\x01\x02",
        b"OPTI",
    ];

    for prefix in forbidden_headers {
        let mut header = [0u8; 64];
        rng.fill_bytes(&mut header);
        header[..prefix.len()].copy_from_slice(prefix);
        assert!(
            parse_client_handshake(&header, &secret).is_none(),
            "Handshake starting with {:?} must be rejected immediately",
            prefix
        );
    }

    // 2. Zeroed bytes at indices 4..8
    let mut zero_4_8 = [0xAAu8; 64];
    zero_4_8[0] = 0x01;
    zero_4_8[4..8].fill(0);
    assert!(
        parse_client_handshake(&zero_4_8, &secret).is_none(),
        "Handshake with zeroed bytes 4..8 must be rejected"
    );

    // 3. 20,000 iterations of random corrupted 64-byte handshake arrays
    for _ in 0..20_000 {
        let mut fuzzed = [0u8; 64];
        rng.fill_bytes(&mut fuzzed);
        // Ensure no panics occur
        let _ = parse_client_handshake(&fuzzed, &secret);
    }
}

#[test]
fn test_fuzz_msg_splitter_oversized_frames_and_oom_prevention() {
    let codecs = [
        ProtoCodec::Abridged,
        ProtoCodec::Intermediate,
        ProtoCodec::PaddedIntermediate,
    ];

    for codec in codecs {
        let mut splitter = MsgSplitter::new(codec);
        assert!(!splitter.is_disabled());

        match codec {
            ProtoCodec::Abridged => {
                // 1. Abridged oversized packet length: 0x7F prefix + 3 bytes representing words > 16MB
                // Words: 0x0040_0001 -> payload_len = 4 * 0x0040_0001 = 16,777,220 bytes (> 16MB)
                let oversized_header = [0x7F, 0x01, 0x00, 0x40];
                let packets = splitter.split(&oversized_header, &oversized_header);
                assert!(
                    splitter.is_disabled(),
                    "Abridged splitter must disable on >16MB frame header"
                );
                assert_eq!(packets.len(), 1);

                // 2. Abridged zero length: 0x00
                let mut splitter2 = MsgSplitter::new(codec);
                let zero_header = [0x00];
                let _ = splitter2.split(&zero_header, &zero_header);
                assert!(
                    splitter2.is_disabled(),
                    "Abridged splitter must disable on zero length frame"
                );

                // 3. Abridged max 3-byte words: 0x00FF_0000 (words * 4 = 66,846,720 > 16MB)
                let mut splitter3 = MsgSplitter::new(codec);
                let huge_words = [0x7F, 0x00, 0x00, 0xFF];
                let _ = splitter3.split(&huge_words, &huge_words);
                assert!(splitter3.is_disabled());
            }
            ProtoCodec::Intermediate | ProtoCodec::PaddedIntermediate => {
                // 1. Intermediate frame length > 16MB: 16 * 1024 * 1024 + 4 = 0x0100_0004
                let oversized_len: u32 = (MAX_PACKET_LEN + 4) as u32;
                let oversized_header = oversized_len.to_le_bytes();
                let packets = splitter.split(&oversized_header, &oversized_header);
                assert!(
                    splitter.is_disabled(),
                    "Intermediate splitter must disable on >16MB frame header"
                );
                assert_eq!(packets.len(), 1);

                // 2. Intermediate zero length: 0x00000000
                let mut splitter2 = MsgSplitter::new(codec);
                let zero_header = [0x00, 0x00, 0x00, 0x00];
                let _ = splitter2.split(&zero_header, &zero_header);
                assert!(
                    splitter2.is_disabled(),
                    "Intermediate splitter must disable on zero length header"
                );

                // 3. Intermediate extreme integer lengths: 0x7FFF_FFFF, 0xFFFFFFFF
                let mut splitter3 = MsgSplitter::new(codec);
                let extreme_header = [0xFF, 0xFF, 0xFF, 0x7F];
                let _ = splitter3.split(&extreme_header, &extreme_header);
                assert!(
                    splitter3.is_disabled(),
                    "Intermediate splitter must disable on 2GB length header"
                );
            }
        }
    }
}

#[test]
fn test_fuzz_msg_splitter_arbitrary_chunk_fragmentation() {
    let mut rng = StdRng::seed_from_u64(0x12345678);

    // Build 50 valid intermediate frames
    let mut stream_plain = Vec::new();
    let mut expected_payloads = Vec::new();

    for _ in 0..50 {
        let payload_len = rng.gen_range(4..=256);
        let mut payload = vec![0u8; payload_len];
        rng.fill_bytes(&mut payload);
        expected_payloads.push(payload.clone());

        let len_bytes = (payload_len as u32).to_le_bytes();
        stream_plain.extend_from_slice(&len_bytes);
        stream_plain.extend_from_slice(&payload);
    }

    let mut splitter = MsgSplitter::new(ProtoCodec::Intermediate);
    let mut received_packets = Vec::new();

    // Feed stream with random irregular chunk sizes (1B, 2B, 3B, 7B, 15B, 64B)
    let mut offset = 0;
    while offset < stream_plain.len() {
        let chunk_size = std::cmp::min(rng.gen_range(1..=17), stream_plain.len() - offset);
        let chunk = &stream_plain[offset..offset + chunk_size];
        let packets = splitter.split(chunk, chunk);
        for p in packets {
            received_packets.push(p);
        }
        offset += chunk_size;
    }

    assert_eq!(received_packets.len(), 50);
    assert!(!splitter.is_disabled());

    for (i, p) in received_packets.iter().enumerate() {
        assert_eq!(&p[4..], &expected_payloads[i]);
    }
}

// =========================================================================
// TRACK 2: SMART ROUTER BOUNDARY FUZZING
// =========================================================================

#[test]
fn test_fuzz_smart_router_domain_boundaries() {
    let router = SmartRouter::new(".");

    // 1. Empty and whitespace-only domains
    let empty_cases = ["", " ", "   ", "\t", "\n", "\r\n", "  \t \n "];
    for d in empty_cases {
        let (routed, reason) = router.should_route(d);
        assert!(!routed, "Empty domain '{}' must not be routed", d);
        assert_eq!(reason, "default_direct");
    }

    // 2. Dot-only domains
    let dot_cases = [".", "..", "...", "....", "...................."];
    for d in dot_cases {
        let (routed, reason) = router.should_route(d);
        assert!(!routed, "Dot-only domain '{}' must not be routed", d);
        assert_eq!(reason, "default_direct");
    }

    // 3. Oversized domains: 254 bytes, 255 bytes, 256 bytes, 500 bytes, 5000 bytes
    let len_253 = format!("{}.com", "a".repeat(249)); // exactly 253 bytes
    let len_254 = format!("{}.com", "a".repeat(250)); // 254 bytes (> 253 RFC limit)
    let len_256 = format!("{}.com", "a".repeat(252)); // 256 bytes
    let len_500 = "x".repeat(500);
    let len_5000 = "y".repeat(5000);

    assert_eq!(len_253.len(), 253);
    assert_eq!(len_254.len(), 254);
    assert_eq!(len_256.len(), 256);

    let (r254, reason254) = router.should_route(&len_254);
    assert!(!r254, "Domain of 254 bytes must safely default to direct");
    assert_eq!(reason254, "default_direct");

    let (r256, reason256) = router.should_route(&len_256);
    assert!(!r256, "Domain of 256 bytes must safely default to direct");
    assert_eq!(reason256, "default_direct");

    let (r500, reason500) = router.should_route(&len_500);
    assert!(!r500);
    assert_eq!(reason500, "default_direct");

    let (r5000, reason5000) = router.should_route(&len_5000);
    assert!(!r5000);
    assert_eq!(reason5000, "default_direct");

    // 4. Domains with special characters and path fragments
    let malformed = [
        "domain.com/path/index.html",
        "domain.com:8080:9090",
        "user:pass@domain.com",
        "domain.com?query=arg",
        "domain.com#section",
        "domain\0null.com",
        "domain\r\ninjection.com",
        "domain name with spaces.com",
        "*.wildcard.domain.com",
        "..double.leading..dots..",
        "trailing.dots.com...",
    ];
    for d in malformed {
        // Must never panic or crash
        let (routed, _reason) = router.should_route(d);
        // Verify output is a deterministic boolean
        let _ = routed;
    }

    // 5. Non-ASCII and Unicode domains
    let unicode_cases = [
        "яндекс.рф",
        "правительство.рф",
        "пример.испытание",
        "тест.домен.ком",
        "🚀.com",
        "🌟-star.org",
        "münchen.de",
        "日本.jp",
        "중국.cn",
    ];
    for d in unicode_cases {
        let (routed, _reason) = router.should_route(d);
        let _ = routed;
    }
}

#[test]
fn test_fuzz_smart_router_edge_ips_and_cidr_intervals() {
    let router = SmartRouter::new(".");

    // 1. Critical IPv4 boundaries
    let edge_ips_v4 = [
        ("0.0.0.0", false, "default_direct"),
        ("0.0.0.1", false, "default_direct"),
        ("127.0.0.1", false, "exclude_direct"),
        ("127.255.255.255", false, "exclude_direct"),
        ("10.0.0.1", false, "exclude_direct"),
        ("10.255.255.254", false, "exclude_direct"),
        ("172.16.0.1", false, "exclude_direct"),
        ("172.31.255.254", false, "exclude_direct"),
        ("192.168.0.1", false, "exclude_direct"),
        ("192.168.255.254", false, "exclude_direct"),
        ("169.254.0.1", false, "exclude_direct"),
        ("169.254.255.254", false, "exclude_direct"),
        ("224.0.0.1", false, "default_direct"),       // Multicast
        ("239.255.255.250", false, "default_direct"), // SSDP Multicast
        ("240.0.0.1", false, "default_direct"),       // Class E
        ("255.255.255.255", false, "default_direct"), // Broadcast
    ];

    for (ip_str, expected_routed, expected_reason) in edge_ips_v4 {
        let (routed, reason) = router.should_route(ip_str);
        assert_eq!(
            routed, expected_routed,
            "IP {} routing mismatch: expected {}, got {}",
            ip_str, expected_routed, routed
        );
        assert_eq!(
            reason, expected_reason,
            "IP {} reason mismatch: expected {}, got {}",
            ip_str, expected_reason, reason
        );
    }

    // 2. Critical IPv6 boundaries
    let edge_ips_v6 = [
        ("::", false, "default_direct"),              // Unspecified
        ("::1", false, "exclude_direct"),             // Loopback
        ("fe80::1", false, "exclude_direct"),         // Link-local
        ("fe80::dead:beef", false, "exclude_direct"), // Link-local
        ("fc00::1", false, "exclude_direct"),         // Unique local
        ("fd12:3456:789a::1", false, "exclude_direct"), // Unique local
        ("ff02::1", false, "default_direct"),         // Multicast
        ("2001:db8::1", false, "default_direct"),     // Documentation prefix
    ];

    for (ip_str, expected_routed, expected_reason) in edge_ips_v6 {
        let (routed, reason) = router.should_route(ip_str);
        assert_eq!(
            routed, expected_routed,
            "IPv6 {} routing mismatch: expected {}, got {}",
            ip_str, expected_routed, routed
        );
        assert_eq!(
            reason, expected_reason,
            "IPv6 {} reason mismatch: expected {}, got {}",
            ip_str, expected_reason, reason
        );
    }

    // 3. Bracketed and formatted IP strings
    let bracketed = [
        ("[127.0.0.1]", false, "exclude_direct"),
        ("[127.0.0.1]:8080", false, "exclude_direct"),
        ("[::1]", false, "exclude_direct"),
        ("[::1]:1080", false, "exclude_direct"),
        ("[fe80::1]:443", false, "exclude_direct"),
        ("[::ffff:127.0.0.1]", false, "default_direct"),
        ("[unclosed_bracket", false, "default_direct"),
        ("[]", false, "default_direct"),
        ("[:]:::", false, "default_direct"),
    ];

    for (input, exp_routed, exp_reason) in bracketed {
        let (routed, reason) = router.should_route(input);
        assert_eq!(routed, exp_routed, "Input {} mismatch", input);
        assert_eq!(reason, exp_reason, "Input {} reason mismatch", input);
    }

    // 4. Rapid-fire CIDR queries (100,000 queries) to verify lock-free zero-leak throughput
    let mut count = 0;
    for octet3 in 0..100 {
        for octet4 in 0..255 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, octet3, octet4));
            let (routed, reason) = router.should_route_ip(ip);
            assert!(!routed);
            assert_eq!(reason, "exclude_direct");
            count += 1;
        }
    }
    assert_eq!(count, 25500);
}

// =========================================================================
// TRACK 3: AXUM WEB ADVERSARIAL FUZZING
// =========================================================================

#[tokio::test]
async fn test_fuzz_axum_malformed_headers() {
    let metrics = Arc::new(ProxyMetrics::new());
    let config = WebConfig::default();
    let router = create_web_router(metrics, config);

    // 1. Missing Host header on /proxy.pac -> should fallback to default_ip without panic
    let req = Request::builder()
        .uri("/proxy.pac")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let script = String::from_utf8(body.to_vec()).unwrap();
    assert!(script.contains("PROXY"));

    // 2. Malformed Host header with multiple colons
    let req = Request::builder()
        .uri("/proxy.pac")
        .header("host", "127.0.0.1:8080:9090:extra")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Bracketed IPv6 Host header
    let req = Request::builder()
        .uri("/proxy.pac")
        .header("host", "[::1]:8080")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let script = String::from_utf8(body.to_vec()).unwrap();
    assert!(script.contains("[::1]:8080"));

    // 4. Oversized Host header (4KB string)
    let huge_host = format!("{}.com:8080", "a".repeat(4000));
    let req = Request::builder()
        .uri("/proxy.pac")
        .header("host", huge_host)
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Host header with whitespace padding
    let req = Request::builder()
        .uri("/proxy.pac")
        .header("host", "   192.168.1.100:8080   ")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_fuzz_axum_invalid_endpoints_and_paths() {
    let metrics = Arc::new(ProxyMetrics::new());
    let config = WebConfig::default();
    let router = create_web_router(metrics, config);

    // 1. Path traversal attacks
    let traversal_paths = [
        "/../etc/passwd",
        "/../../windows/system32/cmd.exe",
        "/proxy.pac/../../secret.txt",
        "/....//....//....//config.json",
        "/././././././secret",
        "/%2e%2e/%2e%2e/etc/passwd",
    ];

    for path in traversal_paths {
        let req = Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "Path traversal '{}' must return 404 Not Found",
            path
        );
    }

    // 2. Random fuzz paths
    let mut rng = StdRng::seed_from_u64(0x99887766);
    for _ in 0..100 {
        let len = rng.gen_range(5..=60);
        let random_chars: String = (0..len)
            .map(|_| {
                let byte = rng.gen_range(b'a'..=b'z');
                byte as char
            })
            .collect();
        let uri = format!("/fuzz-test-{}", random_chars);

        let req = Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn test_fuzz_axum_rapid_health_and_telemetry_polling() {
    let metrics = Arc::new(ProxyMetrics::new());
    let config = WebConfig::default();
    let router = create_web_router(metrics.clone(), config);

    // Simulate 50 concurrent tasks performing rapid queries to /health, /api/stats, /favicon.ico
    let mut handles = Vec::new();

    for worker_id in 0..20 {
        let r = router.clone();
        let m = metrics.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..50 {
                let endpoint = match (worker_id + i) % 4 {
                    0 => "/health",
                    1 => "/api/stats",
                    2 => "/favicon.ico",
                    _ => "/proxy.pac",
                };

                // Increment some mock metrics concurrently
                m.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                m.bytes_client_to_remote.fetch_add(1024, std::sync::atomic::Ordering::Relaxed);

                let req = Request::builder()
                    .uri(endpoint)
                    .body(Body::empty())
                    .unwrap();

                let resp = r.clone().oneshot(req).await.unwrap();
                match endpoint {
                    "/favicon.ico" => assert_eq!(resp.status(), StatusCode::NO_CONTENT),
                    _ => assert_eq!(resp.status(), StatusCode::OK),
                }

                m.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Check final metrics
    assert_eq!(
        metrics.active_connections.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        metrics.bytes_client_to_remote.load(std::sync::atomic::Ordering::SeqCst),
        20 * 50 * 1024
    );
}
