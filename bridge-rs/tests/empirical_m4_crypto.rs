//! Empirical adversarial stress testing and cryptographic verification suite
//! for Milestone 4 (FakeTLS / MTProto Gateway).
//!
//! Areas verified:
//! 1. AES-256-CTR cryptographic stress: multi-megabyte streams, zero keystream drift,
//!    zero corruption, in-place mutation, and concurrent full-duplex execution.
//! 2. FakeTLS validation oracle: exact [-120s, +120s] timestamp window boundaries,
//!    thousands of ClientHello packets with authentic vs fake secrets, bit flips, and truncation.
//! 3. MsgSplitter fuzzing: arbitrary stream fragmentation (1B, 2B, 7B, 15B, 4096B, 65536B,
//!    and random jitter) across Abridged, Intermediate, and Padded Intermediate codecs.
//! 4. MsgSplitter defect detection: empirical verification of the malformed zero-length
//!    header panic defect in `src/mtproto.rs:386`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

use zapret_tv_bridge_rs::faketls::{
    verify_client_hello, CLIENT_RANDOM_LEN, TLS_RECORD_APPDATA, TLS_RECORD_CCS,
    TLS_RECORD_HANDSHAKE,
};
use zapret_tv_bridge_rs::mtproto::{
    build_crypto_ctx, generate_relay_init, parse_client_handshake, Aes256Ctr, MsgSplitter,
    ProtoCodec, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE,
};

// ============================================================================
// PART 1: Cryptographic Stress Tests (AES-256-CTR)
// ============================================================================

#[test]
fn test_crypto_inplace_mutation_and_pointer_preservation() {
    let key = [0x5Au8; 32];
    let iv = [0x3Cu8; 16];
    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());

    let mut buffer = vec![0x42u8; 1024 * 1024]; // 1 MB
    let ptr_before = buffer.as_ptr();

    cipher.apply_keystream(&mut buffer);
    let ptr_after = buffer.as_ptr();

    // Verify in-place mutation without reallocating or moving memory
    assert_eq!(
        ptr_before, ptr_after,
        "Cipher mutation must occur strictly in-place"
    );
    assert_ne!(buffer[0], 0x42, "Buffer contents must be encrypted");

    // Decrypt in-place with a fresh cipher
    let mut decryptor = Aes256Ctr::new(&key.into(), &iv.into());
    decryptor.apply_keystream(&mut buffer);

    assert_eq!(
        buffer.as_ptr(),
        ptr_after,
        "Decryption mutation must be in-place"
    );
    assert_eq!(buffer[0], 0x42, "Buffer must be restored to original value");
    assert_eq!(&buffer[..100], &[0x42u8; 100]);
}

#[test]
fn test_crypto_keystream_zero_drift_varying_chunks() {
    // Generate 4 MB of deterministic pseudo-random reference data
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_0001);
    let size = 4 * 1024 * 1024; // 4,194,304 bytes
    let mut reference_plain = vec![0u8; size];
    rng.fill_bytes(&mut reference_plain);

    let key = [0x88u8; 32];
    let iv = [0x12u8; 16];

    // Reference ciphertext: encrypted in one contiguous 4 MB block
    let mut expected_ciphertext = reference_plain.clone();
    let mut ref_cipher = Aes256Ctr::new(&key.into(), &iv.into());
    ref_cipher.apply_keystream(&mut expected_ciphertext);

    // Test zero keystream drift across unaligned and boundary chunk sizes
    let chunk_sizes = [1, 2, 7, 15, 16, 17, 31, 32, 63, 64, 4096, 4099, 65536];

    for &chunk_size in &chunk_sizes {
        let mut test_stream = reference_plain.clone();
        let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());

        let mut offset = 0;
        while offset < size {
            let end = (offset + chunk_size).min(size);
            cipher.apply_keystream(&mut test_stream[offset..end]);
            offset = end;
        }

        assert_eq!(
            test_stream, expected_ciphertext,
            "Keystream drift detected for chunk size {} bytes! Output does not match reference",
            chunk_size
        );
    }

    // Now test roundtrip decryption across asymmetric chunking:
    // Decrypt the 4 MB ciphertext in 7-byte chunks and verify 100% exact plain recovery
    let mut decrypted_stream = expected_ciphertext.clone();
    let mut decryptor = Aes256Ctr::new(&key.into(), &iv.into());
    let mut offset = 0;
    while offset < size {
        let end = (offset + 7).min(size);
        decryptor.apply_keystream(&mut decrypted_stream[offset..end]);
        offset = end;
    }

    assert_eq!(
        decrypted_stream, reference_plain,
        "Decryption across 7-byte chunks suffered corruption or keystream desynchronization"
    );
}

#[test]
fn test_crypto_multimegabyte_duplex_roundtrip_stress() {
    let secret = [0x77u8; 16];
    let proto_tag = PROTO_TAG_INTERMEDIATE;
    let dc_idx: i16 = 2;

    // Helper to synthesize a valid client handshake header
    let (client_handshake, mut client_enc, mut client_dec) = {
        let mut rng = StdRng::seed_from_u64(0xABCD_1234_5678_0001);
        let mut rnd = [0u8; 64];
        loop {
            rng.fill_bytes(&mut rnd);
            if rnd[0] != 0xef && &rnd[4..8] != b"\x00\x00\x00\x00" {
                break;
            }
        }
        let prekey: [u8; 32] = rnd[8..40].try_into().unwrap();
        let iv: [u8; 16] = rnd[40..56].try_into().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&prekey);
        hasher.update(&secret);
        let dec_key: [u8; 32] = hasher.finalize().into();

        let mut tail_plain = [0u8; 8];
        tail_plain[0..4].copy_from_slice(&proto_tag);
        tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
        rng.fill_bytes(&mut tail_plain[6..8]);

        let mut enc = Aes256Ctr::new(&dec_key.into(), &iv.into());
        let mut encrypted_full = rnd;
        enc.apply_keystream(&mut encrypted_full);

        for i in 0..8 {
            let keystream_byte = encrypted_full[56 + i] ^ rnd[56 + i];
            rnd[56 + i] = tail_plain[i] ^ keystream_byte;
        }

        let mut clt_enc = Aes256Ctr::new(&dec_key.into(), &iv.into());
        clt_enc.apply_keystream(&mut [0u8; 64]);

        let mut rev = [0u8; 48];
        for (i, &b) in rnd[8..56].iter().rev().enumerate() {
            rev[i] = b;
        }
        let mut hasher2 = Sha256::new();
        hasher2.update(&rev[0..32]);
        hasher2.update(&secret);
        let clt_dec_key: [u8; 32] = hasher2.finalize().into();
        let clt_dec = Aes256Ctr::new(&clt_dec_key.into(), rev[32..48].into());

        (rnd, clt_enc, clt_dec)
    };

    let parsed = parse_client_handshake(&client_handshake, &secret)
        .expect("Client handshake must parse successfully");
    let relay_init = generate_relay_init(&proto_tag, dc_idx);
    let crypto_ctx = build_crypto_ctx(&parsed.dec_prekey_and_iv, &secret, &relay_init);
    let (mut c2u, mut u2c) = crypto_ctx.split();

    // Generate 8 MB of upstream client traffic and 8 MB of downstream reply traffic
    let mut rng = StdRng::seed_from_u64(0x9999_8888_7777_6666);
    let stream_size = 8 * 1024 * 1024; // 8 MB
    let mut client_plain = vec![0u8; stream_size];
    let mut server_plain = vec![0u8; stream_size];
    rng.fill_bytes(&mut client_plain);
    rng.fill_bytes(&mut server_plain);

    // 1. Client -> Gateway Direction
    // Client encrypts in chunks of 32,768 bytes
    let mut client_wire = client_plain.clone();
    let mut offset = 0;
    while offset < stream_size {
        let end = (offset + 32768).min(stream_size);
        client_enc.apply_keystream(&mut client_wire[offset..end]);
        offset = end;
    }
    assert_ne!(client_wire[..100], client_plain[..100]);

    // Gateway decrypts in unaligned chunks of 11,111 bytes
    let mut gateway_recovered = client_wire.clone();
    offset = 0;
    while offset < stream_size {
        let end = (offset + 11111).min(stream_size);
        c2u.decrypt_client_inplace(&mut gateway_recovered[offset..end]);
        offset = end;
    }
    assert_eq!(
        gateway_recovered, client_plain,
        "Gateway failed to cleanly decrypt client stream across unaligned chunks"
    );

    // 2. Gateway -> Client Direction
    // Gateway encrypts in chunks of 17,234 bytes
    let mut server_wire = server_plain.clone();
    offset = 0;
    while offset < stream_size {
        let end = (offset + 17234).min(stream_size);
        u2c.encrypt_client_inplace(&mut server_wire[offset..end]);
        offset = end;
    }
    assert_ne!(server_wire[..100], server_plain[..100]);

    // Client decrypts in chunks of 65,536 bytes
    let mut client_recovered = server_wire.clone();
    offset = 0;
    while offset < stream_size {
        let end = (offset + 65536).min(stream_size);
        client_dec.apply_keystream(&mut client_recovered[offset..end]);
        offset = end;
    }
    assert_eq!(
        client_recovered, server_plain,
        "Client failed to cleanly decrypt gateway reply stream across 64KB chunks"
    );
}

#[tokio::test]
async fn test_crypto_concurrent_duplex_multithreaded_stress() {
    let secret = [0x55u8; 16];
    let proto_tag = PROTO_TAG_SECURE;
    let dc_idx: i16 = 4;

    let (client_handshake, mut client_enc, mut client_dec) = {
        let mut rng = StdRng::seed_from_u64(0x5555_4444_3333_2222);
        let mut rnd = [0u8; 64];
        loop {
            rng.fill_bytes(&mut rnd);
            if rnd[0] != 0xef && &rnd[4..8] != b"\x00\x00\x00\x00" {
                break;
            }
        }
        let prekey: [u8; 32] = rnd[8..40].try_into().unwrap();
        let iv: [u8; 16] = rnd[40..56].try_into().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&prekey);
        hasher.update(&secret);
        let dec_key: [u8; 32] = hasher.finalize().into();

        let mut tail_plain = [0u8; 8];
        tail_plain[0..4].copy_from_slice(&proto_tag);
        tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
        rng.fill_bytes(&mut tail_plain[6..8]);

        let mut enc = Aes256Ctr::new(&dec_key.into(), &iv.into());
        let mut encrypted_full = rnd;
        enc.apply_keystream(&mut encrypted_full);

        for i in 0..8 {
            let keystream_byte = encrypted_full[56 + i] ^ rnd[56 + i];
            rnd[56 + i] = tail_plain[i] ^ keystream_byte;
        }

        let mut clt_enc = Aes256Ctr::new(&dec_key.into(), &iv.into());
        clt_enc.apply_keystream(&mut [0u8; 64]);

        let mut rev = [0u8; 48];
        for (i, &b) in rnd[8..56].iter().rev().enumerate() {
            rev[i] = b;
        }
        let mut hasher2 = Sha256::new();
        hasher2.update(&rev[0..32]);
        hasher2.update(&secret);
        let clt_dec_key: [u8; 32] = hasher2.finalize().into();
        let clt_dec = Aes256Ctr::new(&clt_dec_key.into(), rev[32..48].into());

        (rnd, clt_enc, clt_dec)
    };

    let parsed = parse_client_handshake(&client_handshake, &secret).unwrap();
    let relay_init = generate_relay_init(&proto_tag, dc_idx);
    let crypto_ctx = build_crypto_ctx(&parsed.dec_prekey_and_iv, &secret, &relay_init);
    let (mut c2u, mut u2c) = crypto_ctx.split();

    let transfer_len = 8 * 1024 * 1024; // 8 MB per direction

    // Direction 1: Client -> Upstream
    let task_up = tokio::spawn(async move {
        let mut rng = StdRng::seed_from_u64(0x1111_2222_3333_4444);
        let mut plain = vec![0u8; transfer_len];
        rng.fill_bytes(&mut plain);

        let mut wire = plain.clone();
        client_enc.apply_keystream(&mut wire);

        let mut decrypted = wire;
        c2u.decrypt_client_inplace(&mut decrypted);

        assert_eq!(decrypted, plain);
    });

    // Direction 2: Upstream -> Client
    let task_down = tokio::spawn(async move {
        let mut rng = StdRng::seed_from_u64(0x9999_AAAA_BBBB_CCCC);
        let mut plain = vec![0u8; transfer_len];
        rng.fill_bytes(&mut plain);

        let mut wire = plain.clone();
        u2c.encrypt_client_inplace(&mut wire);

        let mut decrypted = wire;
        client_dec.apply_keystream(&mut decrypted);

        assert_eq!(decrypted, plain);
    });

    let (res_up, res_down) = tokio::join!(task_up, task_down);
    res_up.expect("Task up panicked");
    res_down.expect("Task down panicked");
}

// ============================================================================
// PART 2: FakeTLS Validation Oracle
// ============================================================================

/// Helper to synchronize test execution with the beginning of a wall-clock second tick.
/// This prevents boundary race conditions when verifying exact tolerance boundaries (-120s, +120s).
fn sync_to_second_start() {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_millis();
    if millis > 40 {
        std::thread::sleep(Duration::from_millis(1005 - millis as u64));
    }
}

/// Helper to generate a fully compliant FakeTLS ClientHello packet with given secret and target timestamp.
fn generate_client_hello_at_ts(
    secret: &[u8; 16],
    target_ts: u32,
    session_id: &[u8; 32],
    pad_len: usize,
) -> Vec<u8> {
    let record_len = (200 + pad_len) as u16;
    let mut data = Vec::with_capacity(5 + record_len as usize);

    // TLS Record Header: Handshake (0x16), TLS 1.0 (0x0301)
    data.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x01]);
    data.extend_from_slice(&record_len.to_be_bytes());

    // Handshake Header: ClientHello (0x01), length
    let hs_len = (record_len - 4) as u32;
    data.push(0x01);
    data.push(((hs_len >> 16) & 0xFF) as u8);
    data.push(((hs_len >> 8) & 0xFF) as u8);
    data.push((hs_len & 0xFF) as u8);

    // Client Version: TLS 1.2 (0x0303)
    data.extend_from_slice(&[0x03, 0x03]);

    // Client Random placeholder: 32 zeros
    let random_offset = data.len();
    data.extend_from_slice(&[0u8; CLIENT_RANDOM_LEN]);

    // Session ID: length 32 + session_id bytes
    data.push(0x20);
    data.extend_from_slice(session_id);

    // Cipher suites: 2 standard suites
    data.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);

    // Compression methods: length 1, null compression
    data.extend_from_slice(&[0x01, 0x00]);

    // Dummy TLS extensions padding
    while data.len() < (5 + record_len as usize) {
        data.push(0xAB);
    }

    // HMAC-SHA256 signature calculated over zeroed client random
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("Valid secret length");
    mac.update(&data);
    let digest = mac.finalize().into_bytes();

    let ts_bytes = target_ts.to_le_bytes();
    let mut client_random = [0u8; 32];
    client_random[..28].copy_from_slice(&digest[..28]);
    for i in 0..4 {
        client_random[28 + i] = ts_bytes[i] ^ digest[28 + i];
    }

    data[random_offset..random_offset + 32].copy_from_slice(&client_random);
    data
}

#[test]
fn test_faketls_exact_boundary_oracle() {
    let secret = [0x44u8; 16];
    let session_id = [0xEEu8; 32];

    // Boundary offsets: exactly the offsets specified in mission prompt
    // -200s, -121s, -120s, -60s, 0s, +60s, +120s, +121s, +200s
    let test_cases = [
        (-200i64, false), // Expired past
        (-150, false),
        (-125, false),
        (-122, false),
        (-121, false), // Boundary: 1s past tolerance -> REJECT
        (-120, true),  // Boundary: exactly -120s -> ACCEPT
        (-119, true),
        (-60, true),
        (-1, true),
        (0, true), // Current time -> ACCEPT
        (1, true),
        (60, true),
        (119, true),
        (120, true),  // Boundary: exactly +120s -> ACCEPT
        (121, false), // Boundary: 1s future tolerance -> REJECT
        (122, false),
        (125, false),
        (150, false),
        (200, false), // Future drift
    ];

    for (offset, expected_valid) in test_cases {
        sync_to_second_start();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let target_ts = (now + offset) as u32;

        let packet = generate_client_hello_at_ts(&secret, target_ts, &session_id, 30);
        let res = verify_client_hello(&packet, &secret);

        if expected_valid {
            assert!(
                res.is_some(),
                "Oracle failed: expected ACCEPT for timestamp offset {}s, but got None",
                offset
            );
            let verified = res.unwrap();
            assert_eq!(
                verified.timestamp, target_ts,
                "Extracted timestamp mismatch for offset {}s",
                offset
            );
            assert_eq!(verified.session_id, session_id);
        } else {
            assert!(
                res.is_none(),
                "Oracle failed: expected REJECT for timestamp offset {}s, but got Some({:?})",
                offset,
                res
            );
        }
    }
}

#[test]
fn test_faketls_mass_validation_oracle_thousands_samples() {
    let mut rng = StdRng::seed_from_u64(0x7777_6666_5555_4444);

    let authentic_secret = [0x99u8; 16];
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut session_id);

    // 1. Generate 2,000 valid packets with authentic secret and offset in [-120, +120]
    for _ in 0..2000 {
        let offset = rng.gen_range(-120..=120);
        let pad_len = rng.gen_range(10..=60);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let target_ts = (now + offset) as u32;

        let pkt = generate_client_hello_at_ts(&authentic_secret, target_ts, &session_id, pad_len);
        let res = verify_client_hello(&pkt, &authentic_secret);

        assert!(
            res.is_some(),
            "Valid packet within [-120, +120] (offset {}) was unexpectedly rejected",
            offset
        );
        let verified = res.unwrap();
        assert_eq!(verified.timestamp, target_ts);
    }

    // 2. Generate 1,000 expired/out-of-window packets with authentic secret
    for _ in 0..1000 {
        let offset = if rng.gen_bool(0.5) {
            rng.gen_range(-600..=-121)
        } else {
            rng.gen_range(121..=600)
        };
        let pad_len = rng.gen_range(10..=60);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let target_ts = (now + offset) as u32;

        let pkt = generate_client_hello_at_ts(&authentic_secret, target_ts, &session_id, pad_len);
        let res = verify_client_hello(&pkt, &authentic_secret);

        assert!(
            res.is_none(),
            "Out-of-window packet (offset {}) was unexpectedly accepted",
            offset
        );
    }

    // 3. Generate 1,000 packets tested against WRONG secrets (should 100% fail)
    for _ in 0..1000 {
        let mut wrong_secret = [0u8; 16];
        rng.fill_bytes(&mut wrong_secret);
        if wrong_secret == authentic_secret {
            wrong_secret[0] ^= 0xFF;
        }

        let offset = rng.gen_range(-60..=60);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let target_ts = (now + offset) as u32;

        let pkt = generate_client_hello_at_ts(&authentic_secret, target_ts, &session_id, 20);
        let res = verify_client_hello(&pkt, &wrong_secret);

        assert!(
            res.is_none(),
            "Packet verified successfully with an invalid secret! Cryptographic failure"
        );
    }

    // 4. Generate 1,000 packets with 1-bit tamper in various positions
    for _ in 0..1000 {
        let offset = rng.gen_range(-60..=60);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let target_ts = (now + offset) as u32;

        let mut pkt = generate_client_hello_at_ts(&authentic_secret, target_ts, &session_id, 25);

        // Pick a random byte to flip a bit.
        // Bytes 0..39 and 43..pkt.len() are cryptographically bound by HMAC-SHA256.
        // Bytes 39..43 carry the XOR-obfuscated timestamp (client_random[28..32]).
        let flip_idx = if rng.gen_bool(0.8) {
            // 80% test HMAC authenticated bytes
            let idx = rng.gen_range(0..(pkt.len() - 4));
            if idx >= 39 {
                idx + 4
            } else {
                idx
            }
        } else {
            // 20% test timestamp XOR bytes
            rng.gen_range(39..43)
        };

        let bit = 1 << rng.gen_range(0..8);
        pkt[flip_idx] ^= bit;

        let res = verify_client_hello(&pkt, &authentic_secret);
        if flip_idx < 39 || flip_idx >= 43 {
            assert!(
                res.is_none(),
                "Tampered packet in HMAC-covered byte {} passed verification! HMAC validation failed",
                flip_idx
            );
        } else {
            // In timestamp XOR bytes (39..43): either verification rejects (if timestamp pushed outside tolerance),
            // OR if accepted, the extracted timestamp MUST be perturbed
            if let Some(verified) = res {
                assert_ne!(
                    verified.timestamp, target_ts,
                    "Tampered timestamp byte {} failed to alter the timestamp",
                    flip_idx
                );
            }
        }
    }
}

#[test]
fn test_faketls_malformed_and_truncated_records() {
    let secret = [0x22u8; 16];

    // Truncated lengths below minimum 43 bytes
    for len in 0..43 {
        let dummy = vec![TLS_RECORD_HANDSHAKE; len];
        let res = verify_client_hello(&dummy, &secret);
        assert!(
            res.is_none(),
            "Truncated length {} must return None without panic",
            len
        );
    }

    // Corrupt record type (e.g. ApplicationData 0x17 or CCS 0x14)
    let mut valid_pkt = generate_client_hello_at_ts(&secret, 100, &[0u8; 32], 20);
    valid_pkt[0] = TLS_RECORD_APPDATA;
    assert!(verify_client_hello(&valid_pkt, &secret).is_none());

    valid_pkt[0] = TLS_RECORD_CCS;
    assert!(verify_client_hello(&valid_pkt, &secret).is_none());

    // Corrupt handshake type (e.g. 0x02 ServerHello instead of 0x01 ClientHello)
    valid_pkt[0] = TLS_RECORD_HANDSHAKE;
    valid_pkt[5] = 0x02;
    assert!(verify_client_hello(&valid_pkt, &secret).is_none());
}

// ============================================================================
// PART 3: MsgSplitter Fuzzing Across Codecs
// ============================================================================

fn encode_abridged_packet(payload: &[u8]) -> Vec<u8> {
    assert_eq!(
        payload.len() % 4,
        0,
        "Abridged payloads must be 4-byte aligned"
    );
    let words = payload.len() / 4;
    assert!(words > 0, "Payload words must be > 0");

    let mut out = Vec::new();
    if words < 127 {
        out.push(words as u8);
    } else {
        out.push(0x7F);
        let w_bytes = (words as u32).to_le_bytes();
        out.extend_from_slice(&w_bytes[0..3]);
    }
    out.extend_from_slice(payload);
    out
}

fn encode_intermediate_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn encode_padded_intermediate_packet(payload: &[u8], padding: &[u8]) -> Vec<u8> {
    let total_len = payload.len() + padding.len();
    let mut out = Vec::with_capacity(4 + total_len);
    out.extend_from_slice(&(total_len as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(padding);
    out
}

#[test]
fn test_msg_splitter_fuzzing_abridged() {
    let mut rng = StdRng::seed_from_u64(0xABAB_CDCD_1212_3434);

    // Generate diverse packets: small, medium, boundary, large
    let payload_sizes = [
        4, 8, 12, 16, 64, 128, 256, 504, // 126 words (1-byte header)
        508, // 127 words (boundary: transitions to 4-byte header: 0x7F + 3 bytes)
        512, // 128 words (4-byte header)
        1024, 2048, 4096, 16384, 65536,
    ];

    let mut expected_packets = Vec::new();
    let mut stream = Vec::new();

    for &size in &payload_sizes {
        let mut payload = vec![0u8; size];
        rng.fill_bytes(&mut payload);

        let encoded = encode_abridged_packet(&payload);
        expected_packets.push(encoded.clone());
        stream.extend_from_slice(&encoded);
    }

    // Required chunk fragmentation sizes: 1, 2, 7, 15, 4096, 65536 bytes
    let test_chunk_sizes = [1, 2, 7, 15, 4096, 65536];

    for &chunk_size in &test_chunk_sizes {
        let mut splitter = MsgSplitter::new(ProtoCodec::Abridged);
        let mut reconstructed = Vec::new();

        let mut pos = 0;
        while pos < stream.len() {
            let end = (pos + chunk_size).min(stream.len());
            let chunk = &stream[pos..end];
            let parts = splitter.split(chunk, chunk);
            for p in parts {
                reconstructed.push(p.to_vec());
            }
            pos = end;
        }

        assert_eq!(
            reconstructed.len(),
            expected_packets.len(),
            "Abridged framing failed with chunk size {}: expected {} packets, got {}",
            chunk_size,
            expected_packets.len(),
            reconstructed.len()
        );

        for (i, (got, want)) in reconstructed
            .iter()
            .zip(expected_packets.iter())
            .enumerate()
        {
            assert_eq!(
                got, want,
                "Abridged packet {} corrupted with chunk size {}",
                i, chunk_size
            );
        }
    }

    // Randomized chaos chunk sizes
    {
        let mut splitter = MsgSplitter::new(ProtoCodec::Abridged);
        let mut reconstructed = Vec::new();

        let mut pos = 0;
        while pos < stream.len() {
            let chunk_size = rng.gen_range(1..=128);
            let end = (pos + chunk_size).min(stream.len());
            let chunk = &stream[pos..end];
            let parts = splitter.split(chunk, chunk);
            for p in parts {
                reconstructed.push(p.to_vec());
            }
            pos = end;
        }

        assert_eq!(reconstructed.len(), expected_packets.len());
        for (i, (got, want)) in reconstructed
            .iter()
            .zip(expected_packets.iter())
            .enumerate()
        {
            assert_eq!(
                got, want,
                "Chaos fragmentation mismatch on Abridged packet {}",
                i
            );
        }
    }
}

#[test]
fn test_msg_splitter_fuzzing_intermediate() {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_CAFE_BABE);

    let payload_sizes = [
        1, 2, 3, 4, 15, 16, 17, 31, 32, 100, 255, 512, 1024, 4096, 8192, 32768, 65536,
    ];

    let mut expected_packets = Vec::new();
    let mut stream = Vec::new();

    for &size in &payload_sizes {
        let mut payload = vec![0u8; size];
        rng.fill_bytes(&mut payload);

        let encoded = encode_intermediate_packet(&payload);
        expected_packets.push(encoded.clone());
        stream.extend_from_slice(&encoded);
    }

    let test_chunk_sizes = [1, 2, 7, 15, 4096, 65536];

    for &chunk_size in &test_chunk_sizes {
        let mut splitter = MsgSplitter::new(ProtoCodec::Intermediate);
        let mut reconstructed = Vec::new();

        let mut pos = 0;
        while pos < stream.len() {
            let end = (pos + chunk_size).min(stream.len());
            let chunk = &stream[pos..end];
            let parts = splitter.split(chunk, chunk);
            for p in parts {
                reconstructed.push(p.to_vec());
            }
            pos = end;
        }

        assert_eq!(
            reconstructed.len(),
            expected_packets.len(),
            "Intermediate framing failed with chunk size {}",
            chunk_size
        );

        for (i, (got, want)) in reconstructed
            .iter()
            .zip(expected_packets.iter())
            .enumerate()
        {
            assert_eq!(
                got, want,
                "Intermediate packet {} mismatch with chunk size {}",
                i, chunk_size
            );
        }
    }
}

#[test]
fn test_msg_splitter_fuzzing_padded_intermediate() {
    let mut rng = StdRng::seed_from_u64(0x3333_5555_7777_9999);

    let payload_sizes = [4, 7, 16, 23, 64, 128, 256, 512, 1024, 4096, 16384, 65536];

    let mut expected_packets = Vec::new();
    let mut stream = Vec::new();

    for &size in &payload_sizes {
        let mut payload = vec![0u8; size];
        rng.fill_bytes(&mut payload);

        let pad_len = rng.gen_range(0..=15);
        let mut padding = vec![0u8; pad_len];
        rng.fill_bytes(&mut padding);

        let encoded = encode_padded_intermediate_packet(&payload, &padding);
        expected_packets.push(encoded.clone());
        stream.extend_from_slice(&encoded);
    }

    let test_chunk_sizes = [1, 2, 7, 15, 4096, 65536];

    for &chunk_size in &test_chunk_sizes {
        let mut splitter = MsgSplitter::new(ProtoCodec::PaddedIntermediate);
        let mut reconstructed = Vec::new();

        let mut pos = 0;
        while pos < stream.len() {
            let end = (pos + chunk_size).min(stream.len());
            let chunk = &stream[pos..end];
            let parts = splitter.split(chunk, chunk);
            for p in parts {
                reconstructed.push(p.to_vec());
            }
            pos = end;
        }

        assert_eq!(
            reconstructed.len(),
            expected_packets.len(),
            "Padded Intermediate framing failed with chunk size {}",
            chunk_size
        );

        for (i, (got, want)) in reconstructed
            .iter()
            .zip(expected_packets.iter())
            .enumerate()
        {
            assert_eq!(
                got, want,
                "Padded Intermediate packet {} mismatch with chunk size {}",
                i, chunk_size
            );
        }
    }
}

#[test]
fn test_msg_splitter_edge_cases_empty_and_flush() {
    // Empty inputs
    let mut splitter = MsgSplitter::new(ProtoCodec::Intermediate);
    let parts = splitter.split(&[], &[]);
    assert!(parts.is_empty(), "Empty input must return empty vec");

    // Flush on empty splitter returns empty vec
    let flushed = splitter.flush();
    assert!(flushed.is_empty());

    // Flush with partial incomplete packet returns residual tail bytes
    let partial = [10u8, 0, 0, 0, 0xAA, 0xBB]; // requires 10 bytes, only 2 provided
    let _ = splitter.split(&partial, &partial);
    let flushed_tail = splitter.flush();
    assert_eq!(flushed_tail.len(), 1);
    assert_eq!(flushed_tail[0].as_ref(), &partial);
}

#[test]
fn test_msg_splitter_defect_reproduction_malformed_zero_length_panic() {
    // 1. Intermediate codec with 4-byte zero length header [0x00, 0x00, 0x00, 0x00]
    let mut splitter_inter = MsgSplitter::new(ProtoCodec::Intermediate);
    let zero_header = [0u8; 4];

    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        splitter_inter.split(&zero_header, &zero_header)
    }));

    assert!(
        panic_result.is_ok(),
        "MsgSplitter Intermediate must handle malformed zero-length header gracefully without panicking"
    );
    let packets = panic_result.unwrap();
    assert_eq!(
        packets.len(),
        1,
        "Splitter must emit unparsed payload as passthrough"
    );
    assert_eq!(packets[0].as_ref(), &zero_header);
    assert!(splitter_inter.is_disabled());

    // Subsequent chunks pass through directly
    let follow_up = b"arbitrary unformatted follow-up stream";
    let follow_packets = splitter_inter.split(follow_up, follow_up);
    assert_eq!(follow_packets.len(), 1);
    assert_eq!(follow_packets[0].as_ref(), follow_up);

    // 2. PaddedIntermediate codec with 4-byte zero length header [0x00, 0x00, 0x00, 0x00]
    let mut splitter_padded = MsgSplitter::new(ProtoCodec::PaddedIntermediate);
    let panic_padded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        splitter_padded.split(&zero_header, &zero_header)
    }));
    assert!(
        panic_padded.is_ok(),
        "MsgSplitter PaddedIntermediate must handle zero-length header without panicking"
    );
    let packets_padded = panic_padded.unwrap();
    assert_eq!(packets_padded.len(), 1);
    assert_eq!(packets_padded[0].as_ref(), &zero_header);
    assert!(splitter_padded.is_disabled());

    // 3. Abridged codec with 1-byte zero length header [0x00]
    let mut splitter_abridged_1b = MsgSplitter::new(ProtoCodec::Abridged);
    let zero_abridged_1b = [0x00u8];
    let panic_abridged_1b = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        splitter_abridged_1b.split(&zero_abridged_1b, &zero_abridged_1b)
    }));
    assert!(
        panic_abridged_1b.is_ok(),
        "MsgSplitter Abridged (1-byte header) must handle zero length without panicking"
    );
    let packets_abridged_1b = panic_abridged_1b.unwrap();
    assert_eq!(packets_abridged_1b.len(), 1);
    assert_eq!(packets_abridged_1b[0].as_ref(), &zero_abridged_1b);
    assert!(splitter_abridged_1b.is_disabled());

    // 4. Abridged codec with 4-byte extended zero length header [0x7F, 0x00, 0x00, 0x00]
    let mut splitter_abridged_4b = MsgSplitter::new(ProtoCodec::Abridged);
    let zero_abridged_4b = [0x7Fu8, 0x00, 0x00, 0x00];
    let panic_abridged_4b = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        splitter_abridged_4b.split(&zero_abridged_4b, &zero_abridged_4b)
    }));
    assert!(
        panic_abridged_4b.is_ok(),
        "MsgSplitter Abridged (4-byte header) must handle zero length without panicking"
    );
    let packets_abridged_4b = panic_abridged_4b.unwrap();
    assert_eq!(packets_abridged_4b.len(), 1);
    assert_eq!(packets_abridged_4b[0].as_ref(), &zero_abridged_4b);
    assert!(splitter_abridged_4b.is_disabled());

    // 5. Abridged codec with [0x00, 0x00, 0x00, 0x00]
    let mut splitter_abridged_zeros = MsgSplitter::new(ProtoCodec::Abridged);
    let panic_abridged_zeros = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        splitter_abridged_zeros.split(&zero_header, &zero_header)
    }));
    assert!(
        panic_abridged_zeros.is_ok(),
        "MsgSplitter Abridged must handle 4 zero bytes without panicking"
    );
    let packets_abridged_zeros = panic_abridged_zeros.unwrap();
    assert_eq!(packets_abridged_zeros.len(), 1);
    assert_eq!(packets_abridged_zeros[0].as_ref(), &zero_header);
    assert!(splitter_abridged_zeros.is_disabled());
}

#[test]
fn test_msg_splitter_oversized_packet_ceiling() {
    // 1. Intermediate header declaring 2 GB payload (> 16 MB MAX_PACKET_LEN)
    let giant_header = [0xFF, 0xFF, 0xFF, 0x7F];
    let mut splitter_inter = MsgSplitter::new(ProtoCodec::Intermediate);
    let packets = splitter_inter.split(&giant_header, &giant_header);
    assert_eq!(
        packets.len(),
        1,
        "Splitter must reject 2 GB Intermediate packet length and emit passthrough"
    );
    assert_eq!(packets[0].as_ref(), &giant_header);
    assert!(splitter_inter.is_disabled());

    // 2. Intermediate header declaring 16 MB + 1 byte
    let len_16mb_plus_1 = (16 * 1024 * 1024 + 1u32).to_le_bytes();
    let mut splitter_inter_boundary = MsgSplitter::new(ProtoCodec::Intermediate);
    let packets = splitter_inter_boundary.split(&len_16mb_plus_1, &len_16mb_plus_1);
    assert_eq!(
        packets.len(),
        1,
        "Splitter must reject 16MB+1 Intermediate packet length"
    );
    assert_eq!(packets[0].as_ref(), &len_16mb_plus_1);
    assert!(splitter_inter_boundary.is_disabled());

    // 3. PaddedIntermediate header declaring 2 GB
    let mut splitter_padded = MsgSplitter::new(ProtoCodec::PaddedIntermediate);
    let packets = splitter_padded.split(&giant_header, &giant_header);
    assert_eq!(
        packets.len(),
        1,
        "Splitter must reject 2 GB PaddedIntermediate packet length"
    );
    assert_eq!(packets[0].as_ref(), &giant_header);
    assert!(splitter_padded.is_disabled());

    // 4. PaddedIntermediate header declaring 16 MB + 1 byte
    let mut splitter_padded_boundary = MsgSplitter::new(ProtoCodec::PaddedIntermediate);
    let packets = splitter_padded_boundary.split(&len_16mb_plus_1, &len_16mb_plus_1);
    assert_eq!(
        packets.len(),
        1,
        "Splitter must reject 16MB+1 PaddedIntermediate packet length"
    );
    assert_eq!(packets[0].as_ref(), &len_16mb_plus_1);
    assert!(splitter_padded_boundary.is_disabled());

    // 5. Abridged 4-byte header claiming 17 MB
    let mut abridged_splitter = MsgSplitter::new(ProtoCodec::Abridged);
    let words = (17 * 1024 * 1024 / 4) as u32; // 4,456,448 words
    let words_bytes = words.to_le_bytes();
    let abridged_header_17mb = [0x7F, words_bytes[0], words_bytes[1], words_bytes[2]];
    let abridged_packets = abridged_splitter.split(&abridged_header_17mb, &abridged_header_17mb);
    assert_eq!(
        abridged_packets.len(),
        1,
        "Splitter must reject 17MB Abridged packet length"
    );
    assert_eq!(abridged_packets[0].as_ref(), &abridged_header_17mb);
    assert!(abridged_splitter.is_disabled());

    // 6. Abridged 4-byte header claiming 16 MB + 4 bytes
    let words_boundary = ((16 * 1024 * 1024) / 4 + 1u32).to_le_bytes();
    let abridged_header_boundary = [
        0x7F,
        words_boundary[0],
        words_boundary[1],
        words_boundary[2],
    ];
    let mut abridged_splitter_boundary = MsgSplitter::new(ProtoCodec::Abridged);
    let abridged_packets_boundary =
        abridged_splitter_boundary.split(&abridged_header_boundary, &abridged_header_boundary);
    assert_eq!(
        abridged_packets_boundary.len(),
        1,
        "Splitter must reject 16MB+4B Abridged packet length"
    );
    assert_eq!(
        abridged_packets_boundary[0].as_ref(),
        &abridged_header_boundary
    );
    assert!(abridged_splitter_boundary.is_disabled());
}

#[test]
fn test_msg_splitter_zero_length_after_valid_packets() {
    // 1. Intermediate: 3 valid packets followed by zero-length header
    let mut splitter = MsgSplitter::new(ProtoCodec::Intermediate);
    let mut stream = Vec::new();

    // Packet 1: 4 bytes payload
    let p1_len = 4u32;
    stream.extend_from_slice(&p1_len.to_le_bytes());
    stream.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);

    // Packet 2: 8 bytes payload
    let p2_len = 8u32;
    stream.extend_from_slice(&p2_len.to_le_bytes());
    stream.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34]);

    // Packet 3: 4 bytes payload
    let p3_len = 4u32;
    stream.extend_from_slice(&p3_len.to_le_bytes());
    stream.extend_from_slice(&[0x99, 0x88, 0x77, 0x66]);

    // Packet 4: malformed zero-length header
    stream.extend_from_slice(&[0u8; 4]);

    let packets = splitter.split(&stream, &stream);
    assert_eq!(
        packets.len(),
        4,
        "Must emit 3 valid packets and 1 passthrough packet for zero header"
    );
    assert_eq!(&packets[0][4..], &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(
        &packets[1][4..],
        &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34]
    );
    assert_eq!(&packets[2][4..], &[0x99, 0x88, 0x77, 0x66]);
    assert_eq!(packets[3].as_ref(), &[0u8; 4]);
    assert!(splitter.is_disabled());

    // 2. PaddedIntermediate: valid packet followed by zero-length header
    let mut splitter_padded = MsgSplitter::new(ProtoCodec::PaddedIntermediate);
    let mut stream_padded = Vec::new();
    stream_padded.extend_from_slice(&4u32.to_le_bytes());
    stream_padded.extend_from_slice(&[0x10, 0x20, 0x30, 0x40]);
    stream_padded.extend_from_slice(&[0u8; 4]);

    let packets_padded = splitter_padded.split(&stream_padded, &stream_padded);
    assert_eq!(packets_padded.len(), 2);
    assert_eq!(&packets_padded[0][4..], &[0x10, 0x20, 0x30, 0x40]);
    assert_eq!(packets_padded[1].as_ref(), &[0u8; 4]);
    assert!(splitter_padded.is_disabled());

    // 3. Abridged: valid 1-byte packet, then valid 4-byte packet, then zero header
    let mut splitter_abridged = MsgSplitter::new(ProtoCodec::Abridged);
    let mut stream_abridged = Vec::new();
    // Packet 1: 1 word (4 bytes payload), header = 0x01
    stream_abridged.push(0x01);
    stream_abridged.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    // Packet 2: 2 words (8 bytes payload), extended header = [0x7F, 0x02, 0x00, 0x00]
    stream_abridged.extend_from_slice(&[0x7F, 0x02, 0x00, 0x00]);
    stream_abridged.extend_from_slice(&[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]);
    // Packet 3: malformed zero length [0x00]
    stream_abridged.push(0x00);

    let packets_abridged = splitter_abridged.split(&stream_abridged, &stream_abridged);
    assert_eq!(packets_abridged.len(), 3);
    assert_eq!(&packets_abridged[0][1..], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        &packets_abridged[1][4..],
        &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]
    );
    assert_eq!(packets_abridged[2].as_ref(), &[0x00]);
    assert!(splitter_abridged.is_disabled());

    // 4. Intermediate: valid packet followed by oversized header
    let mut splitter_oversized = MsgSplitter::new(ProtoCodec::Intermediate);
    let mut stream_oversized = Vec::new();
    stream_oversized.extend_from_slice(&4u32.to_le_bytes());
    stream_oversized.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    stream_oversized.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]); // 2 GB

    let packets_oversized = splitter_oversized.split(&stream_oversized, &stream_oversized);
    assert_eq!(packets_oversized.len(), 2);
    assert_eq!(&packets_oversized[0][4..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(packets_oversized[1].as_ref(), &[0xFF, 0xFF, 0xFF, 0x7F]);
    assert!(splitter_oversized.is_disabled());

    // 5. Byte-by-byte incremental delivery of valid packet followed by zero header
    let mut splitter_incremental = MsgSplitter::new(ProtoCodec::Intermediate);
    let mut inc_stream = Vec::new();
    inc_stream.extend_from_slice(&4u32.to_le_bytes());
    inc_stream.extend_from_slice(&[0x55, 0x66, 0x77, 0x88]);
    inc_stream.extend_from_slice(&[0u8; 4]);

    let mut collected = Vec::new();
    for byte in &inc_stream {
        let single = [*byte];
        let res = splitter_incremental.split(&single, &single);
        collected.extend(res);
    }
    assert_eq!(
        collected.len(),
        2,
        "Byte-by-byte streaming must produce valid packet then zero header"
    );
    assert_eq!(&collected[0][4..], &[0x55, 0x66, 0x77, 0x88]);
    assert_eq!(collected[1].as_ref(), &[0u8; 4]);
    assert!(splitter_incremental.is_disabled());
}
