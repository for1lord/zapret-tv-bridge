//! End-to-end integration and cryptographic conformance tests for Node 4
//! (FakeTLS / MTProto Gateway on port 1443).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zapret_tv_bridge_rs::faketls::{
    build_server_hello, parse_secret, verify_client_hello, wrap_tls_records, FakeTlsStream,
    TgGatewayConfig, CCS_FRAME, CLIENT_RANDOM_LEN, CLIENT_RANDOM_OFFSET, SESSION_ID_LEN,
    SESSION_ID_OFFSET, TLS_RECORD_APPDATA, TLS_RECORD_HANDSHAKE,
};
use zapret_tv_bridge_rs::metrics::ProxyMetrics;
use zapret_tv_bridge_rs::mtproto::{
    build_crypto_ctx, generate_relay_init, parse_client_handshake, MsgSplitter, ProtoCodec,
    PROTO_TAG_INTERMEDIATE,
};

/// Helper to synthesize a valid FakeTLS ClientHello record for testing.
fn create_test_client_hello(secret: &[u8; 16], timestamp_offset_secs: i64) -> Vec<u8> {
    let mut data = Vec::with_capacity(512);

    // TLS Record Header: Handshake (0x16), TLS 1.0 (0x0301), length 250
    let record_len = 250u16;
    data.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x01]);
    data.extend_from_slice(&record_len.to_be_bytes());

    // Handshake Header: ClientHello (0x01), length 246 (24-bit big endian)
    data.push(0x01);
    data.extend_from_slice(&[0x00, 0x00, 0xF6]);

    // Client Version: TLS 1.2 (0x0303)
    data.extend_from_slice(&[0x03, 0x03]);

    // Client Random placeholder: 32 zeros
    let random_offset = data.len();
    data.extend_from_slice(&[0u8; CLIENT_RANDOM_LEN]);

    // Session ID: length 32 + 32 pseudo-random bytes
    data.push(0x20);
    let mut session_id = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);
    data.extend_from_slice(&session_id);

    // Cipher suites: length 4 + 2 standard suites
    data.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);

    // Compression methods: length 1, null compression
    data.extend_from_slice(&[0x01, 0x00]);

    // Pad with dummy TLS extensions until target length is reached
    while data.len() < (5 + record_len as usize) {
        data.push(0xAA);
    }

    // Calculate HMAC-SHA256 signature over zeroed client random
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("Valid key length");
    mac.update(&data);
    let digest = mac.finalize().into_bytes();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let target_ts = (now + timestamp_offset_secs) as u32;
    let ts_bytes = target_ts.to_le_bytes();

    let mut client_random = [0u8; 32];
    client_random[..28].copy_from_slice(&digest[..28]);
    for i in 0..4 {
        client_random[28 + i] = ts_bytes[i] ^ digest[28 + i];
    }

    // Embed authenticated client random into record
    data[random_offset..random_offset + 32].copy_from_slice(&client_random);
    data
}

#[test]
fn test_faketls_client_hello_verification_valid() {
    let secret = [0x42u8; 16];
    let client_hello = create_test_client_hello(&secret, 0);

    let res = verify_client_hello(&client_hello, &secret);
    assert!(res.is_some(), "Valid ClientHello must verify successfully");

    let verified = res.unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((now - (verified.timestamp as i64)).abs() <= 5);
}

#[test]
fn test_faketls_client_hello_invalid_secret() {
    let secret1 = [0x11u8; 16];
    let secret2 = [0x22u8; 16];
    let client_hello = create_test_client_hello(&secret1, 0);

    let res = verify_client_hello(&client_hello, &secret2);
    assert!(res.is_none(), "Verification with wrong secret must fail");
}

#[test]
fn test_faketls_client_hello_expired_timestamp() {
    let secret = [0x55u8; 16];
    // Timestamp 300 seconds in the past exceeds 120s tolerance window
    let client_hello = create_test_client_hello(&secret, -300);

    let res = verify_client_hello(&client_hello, &secret);
    assert!(res.is_none(), "Expired timestamp must be rejected");
}

#[test]
fn test_faketls_client_hello_tampered() {
    let secret = [0x77u8; 16];
    let mut client_hello = create_test_client_hello(&secret, 0);

    // Tamper with a single byte in the payload
    let last_idx = client_hello.len() - 1;
    client_hello[last_idx] ^= 0xFF;

    let res = verify_client_hello(&client_hello, &secret);
    assert!(
        res.is_none(),
        "Tampered record must fail HMAC authentication"
    );
}

#[test]
fn test_faketls_server_hello_conformance() {
    let secret = [0x88u8; 16];
    let mut client_random = [0u8; 32];
    let mut session_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_random);
    rand::thread_rng().fill_bytes(&mut session_id);

    let server_hello = build_server_hello(&secret, &client_random, &session_id);

    // Must be at least 127 bytes template + 6 bytes CCS + 1900 bytes ApplicationData
    assert!(server_hello.len() >= 127 + 6 + 1900);

    // ServerHello record type Handshake (0x16)
    assert_eq!(server_hello[0], TLS_RECORD_HANDSHAKE);

    // Session ID echoed at offset 44..76
    assert_eq!(
        &server_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN],
        &session_id
    );

    // ChangeCipherSpec frame at offset 127..133
    assert_eq!(&server_hello[127..133], &CCS_FRAME);

    // ApplicationData record type at offset 133
    assert_eq!(server_hello[133], TLS_RECORD_APPDATA);

    // Verify HMAC server random binding
    let server_random =
        &server_hello[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN];
    let mut zeroed_resp = server_hello.clone();
    zeroed_resp[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].fill(0);

    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
    mac.update(&client_random);
    mac.update(&zeroed_resp);
    let expected = mac.finalize().into_bytes();

    assert_eq!(server_random, &expected[..]);
}

#[tokio::test]
async fn test_faketls_stream_wrapping_and_decapsulation() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let mut client_tls = FakeTlsStream::new(client_io);
    let mut server_tls = FakeTlsStream::new(server_io);

    let test_payload = b"MTProto stream encapsulated in TLS ApplicationData records";

    tokio::spawn(async move {
        client_tls.write_all(test_payload).await.unwrap();
        client_tls.flush().await.unwrap();
    });

    let mut received = vec![0u8; test_payload.len()];
    server_tls.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, test_payload);
}

#[test]
fn test_wrap_tls_records_splitting() {
    let small_data = vec![0x11; 100];
    let wrapped_small = wrap_tls_records(&small_data);
    assert_eq!(wrapped_small.len(), 5 + 100);
    assert_eq!(&wrapped_small[0..3], &[TLS_RECORD_APPDATA, 0x03, 0x03]);
    assert_eq!(
        u16::from_be_bytes([wrapped_small[3], wrapped_small[4]]),
        100
    );

    // Payload exceeding 16384 bytes must be chunked into multiple TLS records
    let large_data = vec![0x22; 20000];
    let wrapped_large = wrap_tls_records(&large_data);
    // Chunk 1: 5 + 16384 = 16389; Chunk 2: 5 + 3616 = 3621. Total: 20010 bytes.
    assert_eq!(wrapped_large.len(), 20000 + 10);
    assert_eq!(
        u16::from_be_bytes([wrapped_large[3], wrapped_large[4]]),
        16384
    );
}

#[test]
fn test_secret_parsing_formats() {
    // 1. Raw 32 hex chars
    let raw = "0123456789abcdef0123456789abcdef";
    let (key, domain) = parse_secret(raw).unwrap();
    assert_eq!(hex::encode(key), raw);
    assert!(domain.is_none());

    // 2. "dd" prefixed 34 chars
    let dd = "dd0123456789abcdef0123456789abcdef";
    let (key2, domain2) = parse_secret(dd).unwrap();
    assert_eq!(hex::encode(key2), &dd[2..]);
    assert!(domain2.is_none());

    // 3. "ee" prefixed with hex domain
    let ee = "ee0123456789abcdef0123456789abcdef7777772e676f6f676c652e636f6d";
    let (key3, domain3) = parse_secret(ee).unwrap();
    assert_eq!(hex::encode(key3), "0123456789abcdef0123456789abcdef");
    assert_eq!(domain3.as_deref(), Some("www.google.com"));

    // 4. Invalid length
    assert!(parse_secret("too_short").is_err());
}

/// Helper to create a valid client Obfs2 handshake and matching client-side ciphers.
fn create_test_client_handshake(
    secret: &[u8; 16],
    proto_tag: &[u8; 4],
    dc_idx: i16,
) -> (
    [u8; 64],
    ctr::Ctr128BE<aes::Aes256>,
    ctr::Ctr128BE<aes::Aes256>,
) {
    use aes::Aes256;
    use ctr::cipher::{KeyIvInit, StreamCipher};

    let mut rng = rand::thread_rng();
    let mut rnd = [0u8; 64];
    loop {
        rng.fill_bytes(&mut rnd);
        if rnd[0] != 0xEF
            && &rnd[0..4] != b"HEAD"
            && &rnd[0..4] != b"POST"
            && &rnd[0..4] != b"GET "
            && &rnd[4..8] != [0; 4]
        {
            break;
        }
    }

    let prekey: [u8; 32] = rnd[8..40].try_into().unwrap();
    let iv: [u8; 16] = rnd[40..56].try_into().unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&prekey);
    hasher.update(secret);
    let dec_key: [u8; 32] = hasher.finalize().into();

    let mut enc = ctr::Ctr128BE::<Aes256>::new(&dec_key.into(), &iv.into());

    let mut tail_plain = [0u8; 8];
    tail_plain[0..4].copy_from_slice(proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    rng.fill_bytes(&mut tail_plain[6..8]);

    let mut encrypted_full = rnd;
    enc.apply_keystream(&mut encrypted_full);

    for i in 0..8 {
        let keystream_byte = encrypted_full[56 + i] ^ rnd[56 + i];
        rnd[56 + i] = tail_plain[i] ^ keystream_byte;
    }

    // Client encryptor: sends data to gateway (matches server's clt_dec)
    let mut client_enc = ctr::Ctr128BE::<Aes256>::new(&dec_key.into(), &iv.into());
    client_enc.apply_keystream(&mut [0u8; 64]);

    // Client decryptor: receives data from gateway (matches server's clt_enc)
    let mut rev = [0u8; 48];
    for (i, &b) in rnd[8..56].iter().rev().enumerate() {
        rev[i] = b;
    }
    let mut hasher2 = Sha256::new();
    hasher2.update(&rev[0..32]);
    hasher2.update(secret);
    let enc_key: [u8; 32] = hasher2.finalize().into();
    let client_dec = ctr::Ctr128BE::<Aes256>::new(&enc_key.into(), rev[32..48].into());

    (rnd, client_enc, client_dec)
}

#[test]
fn test_obfs2_handshake_roundtrip_and_aes_ctr() {
    use ctr::cipher::StreamCipher;

    let secret = [0x33u8; 16];
    let proto_tag = PROTO_TAG_INTERMEDIATE;
    let dc_idx: i16 = 2;

    let (client_handshake, mut client_enc, mut client_dec) =
        create_test_client_handshake(&secret, &proto_tag, dc_idx);

    let parsed = parse_client_handshake(&client_handshake, &secret)
        .expect("Client handshake must parse successfully");
    assert_eq!(parsed.proto_tag, proto_tag);
    assert_eq!(parsed.dc_id, 2);

    let relay_init = generate_relay_init(&proto_tag, dc_idx);
    let crypto_ctx = build_crypto_ctx(&parsed.dec_prekey_and_iv, &secret, &relay_init);
    let (mut c2u, mut u2c) = crypto_ctx.split();

    // 1. Client -> Gateway direction
    let original_payload = b"Hello MTProto AES-256-CTR accelerated keystream!";
    let mut client_to_server = original_payload.to_vec();

    client_enc.apply_keystream(&mut client_to_server);
    assert_ne!(&client_to_server, original_payload);

    c2u.decrypt_client_inplace(&mut client_to_server);
    assert_eq!(&client_to_server, original_payload);

    // 2. Gateway -> Client direction
    let reply_payload = b"Server response MTProto encrypted stream";
    let mut server_to_client = reply_payload.to_vec();

    u2c.encrypt_client_inplace(&mut server_to_client);
    assert_ne!(&server_to_client, reply_payload);

    client_dec.apply_keystream(&mut server_to_client);
    assert_eq!(&server_to_client, reply_payload);
}

#[test]
fn test_msg_splitter_abridged_framing() {
    let mut splitter = MsgSplitter::new(ProtoCodec::Abridged);

    // 1-byte length header: word count = 5 (payload = 20 bytes), total packet = 21 bytes
    let mut pkt1 = vec![5u8];
    pkt1.extend_from_slice(&[0xAA; 20]);

    // 4-byte length header: 0x7F + 3 bytes word count = 10 (payload = 40 bytes), total packet = 44 bytes
    let mut pkt2 = vec![0x7Fu8, 10, 0, 0];
    pkt2.extend_from_slice(&[0xBB; 40]);

    let mut stream = Vec::new();
    stream.extend_from_slice(&pkt1);
    stream.extend_from_slice(&pkt2);

    let split_packets = splitter.split(&stream, &stream);
    assert_eq!(split_packets.len(), 2);
    assert_eq!(split_packets[0], Bytes::from(pkt1));
    assert_eq!(split_packets[1], Bytes::from(pkt2));
}

#[test]
fn test_msg_splitter_intermediate_and_padded() {
    let mut splitter = MsgSplitter::new(ProtoCodec::Intermediate);

    // 4-byte LE length header: payload = 32 bytes, total packet = 36 bytes
    let payload_len = 32u32;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&payload_len.to_le_bytes());
    pkt.extend_from_slice(&[0xCC; 32]);

    let split_packets = splitter.split(&pkt, &pkt);
    assert_eq!(split_packets.len(), 1);
    assert_eq!(split_packets[0], Bytes::from(pkt));
}

#[test]
fn test_msg_splitter_fragmentation_across_chunks() {
    let mut splitter = MsgSplitter::new(ProtoCodec::Intermediate);

    // Create a 64-byte payload packet (total 68 bytes with header)
    let payload_len = 64u32;
    let mut complete_pkt = Vec::new();
    complete_pkt.extend_from_slice(&payload_len.to_le_bytes());
    complete_pkt.extend_from_slice(&[0xEE; 64]);

    // Feed the packet 1 byte at a time
    let mut emitted = Vec::new();
    for i in 0..complete_pkt.len() {
        let single_byte = &[complete_pkt[i]];
        let parts = splitter.split(single_byte, single_byte);
        emitted.extend(parts);
        if i < complete_pkt.len() - 1 {
            assert!(
                emitted.is_empty(),
                "Partial packet must not be emitted at byte {}",
                i
            );
        }
    }

    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], Bytes::from(complete_pkt));
}

#[tokio::test]
async fn test_e2e_faketls_mock_relay_loop() {
    use aes::Aes256;
    use ctr::cipher::{KeyIvInit, StreamCipher};

    let secret = [0x99u8; 16];

    // 1. Start a local Mock Telegram Upstream Server on an ephemeral port
    let mock_upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_upstream_addr = mock_upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut upstream_conn, _)) = mock_upstream_listener.accept().await {
            // Read the 64-byte relay_init handshake sent by the gateway
            let mut relay_init = [0u8; 64];
            upstream_conn.read_exact(&mut relay_init).await.unwrap();

            // Upstream decryptor: decrypts incoming traffic from gateway (matches tg_enc)
            let dec_key: [u8; 32] = relay_init[8..40].try_into().unwrap();
            let dec_iv: [u8; 16] = relay_init[40..56].try_into().unwrap();
            let mut up_dec = ctr::Ctr128BE::<Aes256>::new(&dec_key.into(), &dec_iv.into());
            up_dec.apply_keystream(&mut [0u8; 64]);

            // Upstream encryptor: encrypts outgoing traffic to gateway (matches tg_dec)
            let mut rev = [0u8; 48];
            for (i, &b) in relay_init[8..56].iter().rev().enumerate() {
                rev[i] = b;
            }
            let enc_key: [u8; 32] = rev[0..32].try_into().unwrap();
            let enc_iv: [u8; 16] = rev[32..48].try_into().unwrap();
            let mut up_enc = ctr::Ctr128BE::<Aes256>::new(&enc_key.into(), &enc_iv.into());

            // Read packet from gateway, decrypt it, re-encrypt it with up_enc, and echo it back
            let mut buf = [0u8; 4096];
            loop {
                match upstream_conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut plain = buf[..n].to_vec();
                        up_dec.apply_keystream(&mut plain);

                        let mut cipher = plain;
                        up_enc.apply_keystream(&mut cipher);

                        if upstream_conn.write_all(&cipher).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    // 2. Start the FakeTLS Gateway on an ephemeral port with upstream_override
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    drop(gateway_listener); // Release port for run_tg_gateway

    let mut tg_config = TgGatewayConfig::new(gateway_addr, secret, None);
    tg_config.upstream_override = Some(mock_upstream_addr);

    let metrics = Arc::new(ProxyMetrics::new());
    let metrics_clone = Arc::clone(&metrics);

    tokio::spawn(async move {
        let _ = zapret_tv_bridge_rs::faketls::run_tg_gateway(tg_config, metrics_clone).await;
    });

    // Allow gateway to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 3. Connect Client to Gateway
    let mut client = TcpStream::connect(gateway_addr).await.unwrap();

    // Step A: Send FakeTLS ClientHello
    let client_hello = create_test_client_hello(&secret, 0);
    client.write_all(&client_hello).await.unwrap();
    client.flush().await.unwrap();

    // Step B: Read ServerHello response
    let mut server_hello_buf = vec![0u8; 3000];
    let n = client.read(&mut server_hello_buf).await.unwrap();
    assert!(n >= 127 + 6, "Must receive full ServerHello and CCS");
    assert_eq!(server_hello_buf[0], TLS_RECORD_HANDSHAKE);

    // Step C: Wrap client stream in FakeTlsStream
    let mut client_tls = FakeTlsStream::new(client);

    // Step D: Construct and send valid 64-byte Obfs2 client handshake with crypto
    let proto_tag = PROTO_TAG_INTERMEDIATE;
    let dc_idx: i16 = 2;
    let (client_handshake, mut client_enc, mut client_dec) =
        create_test_client_handshake(&secret, &proto_tag, dc_idx);

    client_tls.write_all(&client_handshake).await.unwrap();
    client_tls.flush().await.unwrap();

    // Step E: Send formatted MTProto Intermediate packet through established relay
    let payload = b"Ping payload through end-to-end FakeTLS gateway relay!";
    let mut mtproto_pkt = Vec::with_capacity(4 + payload.len());
    mtproto_pkt.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    mtproto_pkt.extend_from_slice(payload);

    let mut encrypted_pkt = mtproto_pkt.clone();
    client_enc.apply_keystream(&mut encrypted_pkt);

    client_tls.write_all(&encrypted_pkt).await.unwrap();
    client_tls.flush().await.unwrap();

    // Step F: Read echoed data and decrypt with client_dec
    let mut echo_buf = vec![0u8; encrypted_pkt.len()];
    let read_res = tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        client_tls.read_exact(&mut echo_buf),
    )
    .await;

    assert!(
        read_res.is_ok(),
        "Echo data must be received within timeout"
    );
    client_dec.apply_keystream(&mut echo_buf);
    assert_eq!(&echo_buf, &mtproto_pkt);

    // Step G: Verify metrics accounting
    assert!(
        metrics
            .total_connections
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    assert!(
        metrics
            .bytes_client_to_remote
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    assert!(
        metrics
            .bytes_remote_to_client
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
}
