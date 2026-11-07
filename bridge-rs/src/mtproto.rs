//! MTProto Obfs2 cryptographic engine, MsgSplitter transport framing,
//! DC routing, and upstream relaying for Telegram client traffic.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use aes::Aes256;
use bytes::{Bytes, BytesMut};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::metrics::ProxyMetrics;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
pub const PROTO_TAG_SECURE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

pub const PROTO_ABRIDGED_INT: u32 = 0xEFEFEFEF;
pub const PROTO_INTERMEDIATE_INT: u32 = 0xEEEEEEEE;
pub const PROTO_PADDED_INTERMEDIATE_INT: u32 = 0xDDDDDDDD;

pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8;
pub const PREKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

/// Parsed client Obfs2 handshake parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedHandshake {
    pub dc_id: usize,
    pub is_media: bool,
    pub is_test_dc: bool,
    pub proto_tag: [u8; 4],
    pub dec_prekey_and_iv: [u8; 48],
}

/// Transport protocol framing variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoCodec {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl ProtoCodec {
    pub fn from_tag(tag: &[u8; 4]) -> Option<Self> {
        if tag == &PROTO_TAG_ABRIDGED {
            Some(ProtoCodec::Abridged)
        } else if tag == &PROTO_TAG_INTERMEDIATE {
            Some(ProtoCodec::Intermediate)
        } else if tag == &PROTO_TAG_SECURE {
            Some(ProtoCodec::PaddedIntermediate)
        } else {
            None
        }
    }

    pub fn to_tag(self) -> [u8; 4] {
        match self {
            ProtoCodec::Abridged => PROTO_TAG_ABRIDGED,
            ProtoCodec::Intermediate => PROTO_TAG_INTERMEDIATE,
            ProtoCodec::PaddedIntermediate => PROTO_TAG_SECURE,
        }
    }
}

/// Full cryptographic state holding independent stream ciphers for client and upstream communication.
pub struct MtprotoCryptoCtx {
    pub clt_dec: Aes256Ctr,
    pub clt_enc: Aes256Ctr,
    pub tg_enc: Aes256Ctr,
    pub tg_dec: Aes256Ctr,
}

pub struct ClientToUpstreamCrypto {
    pub clt_dec: Aes256Ctr,
    pub tg_enc: Aes256Ctr,
}

impl ClientToUpstreamCrypto {
    #[inline]
    pub fn decrypt_client_inplace(&mut self, buf: &mut [u8]) {
        self.clt_dec.apply_keystream(buf);
    }

    #[inline]
    pub fn encrypt_tg_inplace(&mut self, buf: &mut [u8]) {
        self.tg_enc.apply_keystream(buf);
    }
}

pub struct UpstreamToClientCrypto {
    pub clt_enc: Aes256Ctr,
    pub tg_dec: Aes256Ctr,
}

impl UpstreamToClientCrypto {
    #[inline]
    pub fn encrypt_client_inplace(&mut self, buf: &mut [u8]) {
        self.clt_enc.apply_keystream(buf);
    }

    #[inline]
    pub fn decrypt_tg_inplace(&mut self, buf: &mut [u8]) {
        self.tg_dec.apply_keystream(buf);
    }
}

impl MtprotoCryptoCtx {
    #[inline]
    pub fn decrypt_client_inplace(&mut self, buf: &mut [u8]) {
        self.clt_dec.apply_keystream(buf);
    }

    #[inline]
    pub fn encrypt_client_inplace(&mut self, buf: &mut [u8]) {
        self.clt_enc.apply_keystream(buf);
    }

    #[inline]
    pub fn encrypt_tg_inplace(&mut self, buf: &mut [u8]) {
        self.tg_enc.apply_keystream(buf);
    }

    #[inline]
    pub fn decrypt_tg_inplace(&mut self, buf: &mut [u8]) {
        self.tg_dec.apply_keystream(buf);
    }

    pub fn split(self) -> (ClientToUpstreamCrypto, UpstreamToClientCrypto) {
        (
            ClientToUpstreamCrypto {
                clt_dec: self.clt_dec,
                tg_enc: self.tg_enc,
            },
            UpstreamToClientCrypto {
                clt_enc: self.clt_enc,
                tg_dec: self.tg_dec,
            },
        )
    }
}

/// Parses the 64-byte client Obfs2 handshake header and validates the protocol tag.
pub fn parse_client_handshake(
    handshake: &[u8; 64],
    secret: &[u8; 16],
) -> Option<ParsedHandshake> {
    if handshake[0] == 0xef {
        return None;
    }
    let start4 = &handshake[0..4];
    if start4 == b"HEAD"
        || start4 == b"POST"
        || start4 == b"GET "
        || start4 == b"\xee\xee\xee\xee"
        || start4 == b"\xdd\xdd\xdd\xdd"
        || start4 == b"\x16\x03\x01\x02"
        || start4 == b"OPTI"
    {
        return None;
    }
    if &handshake[4..8] == b"\x00\x00\x00\x00" {
        return None;
    }

    let mut dec_prekey_and_iv = [0u8; 48];
    dec_prekey_and_iv.copy_from_slice(&handshake[8..56]);
    let dec_prekey = &dec_prekey_and_iv[0..32];
    let dec_iv = &dec_prekey_and_iv[32..48];

    let mut hasher = Sha256::new();
    hasher.update(dec_prekey);
    hasher.update(secret);
    let dec_key: [u8; 32] = hasher.finalize().into();

    let mut decryptor = Aes256Ctr::new(&dec_key.into(), dec_iv.into());
    let mut decrypted = *handshake;
    decryptor.apply_keystream(&mut decrypted);

    let proto_tag = [
        decrypted[PROTO_TAG_POS],
        decrypted[PROTO_TAG_POS + 1],
        decrypted[PROTO_TAG_POS + 2],
        decrypted[PROTO_TAG_POS + 3],
    ];

    if proto_tag != PROTO_TAG_ABRIDGED
        && proto_tag != PROTO_TAG_INTERMEDIATE
        && proto_tag != PROTO_TAG_SECURE
    {
        return None;
    }

    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);
    let mut dc_id = dc_idx.unsigned_abs() as usize;
    let is_media = dc_idx < 0;

    let is_test_dc = dc_id >= 10000;
    if is_test_dc {
        dc_id -= 10000;
    }

    Some(ParsedHandshake {
        dc_id,
        is_media,
        is_test_dc,
        proto_tag,
        dec_prekey_and_iv,
    })
}

/// Generates a valid 64-byte obfuscated relay handshake header for upstream Telegram Data Centers.
pub fn generate_relay_init(proto_tag: &[u8; 4], dc_idx: i16) -> [u8; 64] {
    let mut rng = rand::thread_rng();
    let mut rnd = [0u8; 64];

    loop {
        rng.fill_bytes(&mut rnd);
        if rnd[0] == 0xef {
            continue;
        }
        let start4 = &rnd[0..4];
        if start4 == b"HEAD"
            || start4 == b"POST"
            || start4 == b"GET "
            || start4 == b"\xee\xee\xee\xee"
            || start4 == b"\xdd\xdd\xdd\xdd"
            || start4 == b"\x16\x03\x01\x02"
            || start4 == b"OPTI"
        {
            continue;
        }
        if &rnd[4..8] == b"\x00\x00\x00\x00" {
            continue;
        }
        break;
    }

    let enc_key: [u8; 32] = rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN].try_into().unwrap();
    let enc_iv: [u8; 16] = rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].try_into().unwrap();

    let mut tail_plain = [0u8; 8];
    tail_plain[0..4].copy_from_slice(proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    rng.fill_bytes(&mut tail_plain[6..8]);

    let mut cipher = Aes256Ctr::new(&enc_key.into(), &enc_iv.into());
    let mut encrypted_full = rnd;
    cipher.apply_keystream(&mut encrypted_full);

    for i in 0..8 {
        let keystream_byte = encrypted_full[56 + i] ^ rnd[56 + i];
        rnd[56 + i] = tail_plain[i] ^ keystream_byte;
    }

    rnd
}

/// Derives AES-256-CTR keystreams for client decryption/encryption and upstream relay.
pub fn build_crypto_ctx(
    client_dec_prekey_and_iv: &[u8; 48],
    secret: &[u8; 16],
    relay_init: &[u8; 64],
) -> MtprotoCryptoCtx {
    // 1. Client Decryptor
    let clt_dec_prekey = &client_dec_prekey_and_iv[0..32];
    let clt_dec_iv = &client_dec_prekey_and_iv[32..48];

    let mut hasher = Sha256::new();
    hasher.update(clt_dec_prekey);
    hasher.update(secret);
    let clt_dec_key: [u8; 32] = hasher.finalize().into();

    let mut clt_dec = Aes256Ctr::new(&clt_dec_key.into(), clt_dec_iv.into());
    // Fast-forward client decryptor past the initial 64-byte handshake
    clt_dec.apply_keystream(&mut [0u8; 64]);

    // 2. Client Encryptor
    let mut clt_enc_prekey_iv = [0u8; 48];
    for (i, &b) in client_dec_prekey_and_iv.iter().rev().enumerate() {
        clt_enc_prekey_iv[i] = b;
    }
    let clt_enc_prekey = &clt_enc_prekey_iv[0..32];
    let clt_enc_iv = &clt_enc_prekey_iv[32..48];

    let mut hasher2 = Sha256::new();
    hasher2.update(clt_enc_prekey);
    hasher2.update(secret);
    let clt_enc_key: [u8; 32] = hasher2.finalize().into();

    let clt_enc = Aes256Ctr::new(&clt_enc_key.into(), clt_enc_iv.into());

    // 3. Upstream Telegram Encryptor (Standard obfuscation without secret hash)
    let tg_enc_key: [u8; 32] = relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN].try_into().unwrap();
    let tg_enc_iv: [u8; 16] = relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].try_into().unwrap();

    let mut tg_enc = Aes256Ctr::new(&tg_enc_key.into(), &tg_enc_iv.into());
    // Fast-forward upstream encryptor past the initial 64-byte handshake sent to DC
    tg_enc.apply_keystream(&mut [0u8; 64]);

    // 4. Upstream Telegram Decryptor
    let mut relay_dec_prekey_iv = [0u8; 48];
    for (i, &b) in relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].iter().rev().enumerate() {
        relay_dec_prekey_iv[i] = b;
    }
    let tg_dec_key: [u8; 32] = relay_dec_prekey_iv[0..32].try_into().unwrap();
    let tg_dec_iv: [u8; 16] = relay_dec_prekey_iv[32..48].try_into().unwrap();

    let tg_dec = Aes256Ctr::new(&tg_dec_key.into(), &tg_dec_iv.into());

    MtprotoCryptoCtx {
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
    }
}

/// Maximum MTProto transport packet length (16 MB). Packets exceeding this size are rejected as malformed.
pub const MAX_PACKET_LEN: usize = 16 * 1024 * 1024;

/// Slices continuous TCP byte streams into discrete MTProto transport packets.
pub struct MsgSplitter {
    codec: ProtoCodec,
    cipher_buf: BytesMut,
    plain_buf: BytesMut,
    disabled: bool,
}

impl MsgSplitter {
    pub fn new(codec: ProtoCodec) -> Self {
        Self {
            codec,
            cipher_buf: BytesMut::with_capacity(16384),
            plain_buf: BytesMut::with_capacity(16384),
            disabled: false,
        }
    }

    /// Returns true if the splitter has disabled framing due to malformed payload headers.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Splits incoming ciphertext/plaintext byte chunks into complete MTProto packets.
    pub fn split(&mut self, chunk: &[u8], plain: &[u8]) -> Vec<Bytes> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![Bytes::copy_from_slice(chunk)];
        }

        self.cipher_buf.extend_from_slice(chunk);
        self.plain_buf.extend_from_slice(plain);

        let mut packets = Vec::new();

        while !self.cipher_buf.is_empty() {
            let avail = self.cipher_buf.len();
            let packet_len = self.next_packet_len(0, avail);

            match packet_len {
                None => break, // Need more bytes to complete packet header/payload
                Some(0) => {
                    // Malformed packet length or exceeds MAX_PACKET_LEN: disable splitter and pass through
                    self.disabled = true;
                    self.plain_buf.clear();
                    let remaining = self.cipher_buf.split().freeze();
                    if !remaining.is_empty() {
                        packets.push(remaining);
                    }
                    return packets;
                }
                Some(len) => {
                    let packet = self.cipher_buf.split_to(len).freeze();
                    let _ = self.plain_buf.split_to(len);
                    packets.push(packet);
                }
            }
        }

        packets
    }

    /// Flushes any buffered data on stream termination.
    pub fn flush(&mut self) -> Vec<Bytes> {
        if self.cipher_buf.is_empty() {
            Vec::new()
        } else {
            let tail = self.cipher_buf.split().freeze();
            self.plain_buf.clear();
            vec![tail]
        }
    }

    fn next_packet_len(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail == 0 {
            return None;
        }

        match self.codec {
            ProtoCodec::Abridged => {
                let first = self.plain_buf[offset];
                let (header_len, payload_len) = if (first & 0x7F) == 0x7F {
                    if avail < 4 {
                        return None;
                    }
                    let words = u32::from_le_bytes([
                        self.plain_buf[offset + 1],
                        self.plain_buf[offset + 2],
                        self.plain_buf[offset + 3],
                        0,
                    ]) as usize;
                    (4, words * 4)
                } else {
                    let words = (first & 0x7F) as usize;
                    (1, words * 4)
                };

                if payload_len == 0 || payload_len > MAX_PACKET_LEN {
                    Some(0)
                } else {
                    let total = header_len + payload_len;
                    if avail < total {
                        None
                    } else {
                        Some(total)
                    }
                }
            }
            ProtoCodec::Intermediate | ProtoCodec::PaddedIntermediate => {
                if avail < 4 {
                    return None;
                }
                let raw_len = u32::from_le_bytes([
                    self.plain_buf[offset],
                    self.plain_buf[offset + 1],
                    self.plain_buf[offset + 2],
                    self.plain_buf[offset + 3],
                ]);
                let payload_len = (raw_len & 0x7FFF_FFFF) as usize;

                if payload_len == 0 || payload_len > MAX_PACKET_LEN {
                    Some(0)
                } else {
                    let total = 4 + payload_len;
                    if avail < total {
                        None
                    } else {
                        Some(total)
                    }
                }
            }
        }
    }
}

/// Resolves official Telegram Data Center IP endpoints.
pub fn get_dc_address(dc_id: usize, is_test: bool) -> SocketAddr {
    if is_test {
        match dc_id {
            1 => "149.154.175.10:443".parse().unwrap(),
            2 => "149.154.167.40:443".parse().unwrap(),
            3 => "149.154.175.117:443".parse().unwrap(),
            _ => "149.154.167.40:443".parse().unwrap(),
        }
    } else {
        match dc_id {
            1 => "149.154.175.50:443".parse().unwrap(),
            2 => "149.154.167.51:443".parse().unwrap(),
            3 => "149.154.175.100:443".parse().unwrap(),
            4 => "149.154.167.91:443".parse().unwrap(),
            5 => "149.154.171.5:443".parse().unwrap(),
            203 => "91.105.192.100:443".parse().unwrap(),
            _ => "149.154.167.51:443".parse().unwrap(),
        }
    }
}

/// Resolves the WebSocket hostname for Telegram DCs.
pub fn get_dc_ws_host(dc_id: usize, is_media: bool) -> String {
    let dc = if dc_id == 203 { 2 } else { dc_id };
    if is_media {
        format!("kws{}-1.web.telegram.org", dc)
    } else {
        format!("kws{}.web.telegram.org", dc)
    }
}

/// Minimalist, non-blocking RFC 6455 WebSocket client wrapper over TCP.
pub struct RawWebSocket {
    stream: TcpStream,
    read_buf: BytesMut,
}

impl RawWebSocket {
    /// Establishes an RFC 6455 WebSocket connection on the given TCP stream.
    pub async fn connect(mut stream: TcpStream, host: &str, path: &str) -> io::Result<Self> {
        let mut key_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let ws_key = hex::encode(key_bytes);

        let request = format!(
            "GET {path} HTTP/1.1\r\n\
            Host: {host}\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: {ws_key}\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Protocol: binary\r\n\r\n"
        );

        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        // Read HTTP 101 response
        let mut header_buf = [0u8; 1024];
        let mut total_read = 0;
        let mut status_ok = false;

        while total_read < header_buf.len() {
            let n = stream.read(&mut header_buf[total_read..total_read + 1]).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "WebSocket handshake EOF"));
            }
            total_read += 1;
            if total_read >= 4 && &header_buf[total_read - 4..total_read] == b"\r\n\r\n" {
                let resp_str = String::from_utf8_lossy(&header_buf[..total_read]);
                if resp_str.starts_with("HTTP/1.1 101") || resp_str.starts_with("HTTP/1.0 101") {
                    status_ok = true;
                }
                break;
            }
        }

        if !status_ok {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "WebSocket upgrade rejected by upstream",
            ));
        }

        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(32768),
        })
    }

    /// Sends a binary WebSocket frame with 4-byte client XOR masking (RFC 6455 Section 5.3).
    pub async fn send_binary(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut mask_key = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask_key);

        let mut frame_hdr = Vec::with_capacity(14);
        frame_hdr.push(0x82); // FIN + Opcode 0x2 (Binary)

        let len = payload.len();
        if len < 126 {
            frame_hdr.push(0x80 | (len as u8));
        } else if len < 65536 {
            frame_hdr.push(0x80 | 126);
            frame_hdr.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame_hdr.push(0x80 | 127);
            frame_hdr.extend_from_slice(&(len as u64).to_be_bytes());
        }

        frame_hdr.extend_from_slice(&mask_key);

        let mut masked_payload = payload.to_vec();
        for (i, byte) in masked_payload.iter_mut().enumerate() {
            *byte ^= mask_key[i % 4];
        }

        self.stream.write_all(&frame_hdr).await?;
        self.stream.write_all(&masked_payload).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads the next binary payload frame from the WebSocket stream.
    pub async fn read_binary(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            // Read 2-byte minimum header
            while self.read_buf.len() < 2 {
                let mut buf = [0u8; 8192];
                let n = self.stream.read(&mut buf).await?;
                if n == 0 {
                    return Ok(None);
                }
                self.read_buf.extend_from_slice(&buf[..n]);
            }

            let b0 = self.read_buf[0];
            let b1 = self.read_buf[1];
            let opcode = b0 & 0x0F;
            let is_masked = (b1 & 0x80) != 0;
            let mut payload_len = (b1 & 0x7F) as usize;
            let mut hdr_size = 2;

            if payload_len == 126 {
                hdr_size += 2;
                while self.read_buf.len() < hdr_size {
                    let mut buf = [0u8; 8192];
                    let n = self.stream.read(&mut buf).await?;
                    if n == 0 {
                        return Ok(None);
                    }
                    self.read_buf.extend_from_slice(&buf[..n]);
                }
                payload_len = u16::from_be_bytes([self.read_buf[2], self.read_buf[3]]) as usize;
            } else if payload_len == 127 {
                hdr_size += 8;
                while self.read_buf.len() < hdr_size {
                    let mut buf = [0u8; 8192];
                    let n = self.stream.read(&mut buf).await?;
                    if n == 0 {
                        return Ok(None);
                    }
                    self.read_buf.extend_from_slice(&buf[..n]);
                }
                payload_len = u64::from_be_bytes(self.read_buf[2..10].try_into().unwrap()) as usize;
            }

            let mask_size = if is_masked { 4 } else { 0 };
            let total_frame_size = hdr_size + mask_size + payload_len;

            while self.read_buf.len() < total_frame_size {
                let mut buf = [0u8; 8192];
                let n = self.stream.read(&mut buf).await?;
                if n == 0 {
                    return Ok(None);
                }
                self.read_buf.extend_from_slice(&buf[..n]);
            }

            let frame = self.read_buf.split_to(total_frame_size);
            let mut payload = frame[hdr_size + mask_size..].to_vec();

            if is_masked {
                let mask = &frame[hdr_size..hdr_size + 4];
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= mask[i % 4];
                }
            }

            if opcode == 0x8 {
                // OP_CLOSE
                return Ok(None);
            } else if opcode == 0x9 {
                // OP_PING -> Send OP_PONG (0x8A)
                let pong_hdr = [0x8A, 0x00];
                let _ = self.stream.write_all(&pong_hdr).await;
                let _ = self.stream.flush().await;
                continue;
            } else if opcode == 0xA {
                // OP_PONG -> Continue
                continue;
            } else if opcode == 0x2 || opcode == 0x1 || opcode == 0x0 {
                // Binary or Continuation payload
                return Ok(Some(payload));
            }
        }
    }
}

/// Connects upstream and executes bidirectional traffic relay between client and Telegram Data Center.
pub async fn handle_mtproto_stream<S>(
    client_stream: S,
    handshake: [u8; 64],
    secret: [u8; 16],
    upstream_override: Option<SocketAddr>,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let parsed = match parse_client_handshake(&handshake, &secret) {
        Some(p) => p,
        None => {
            metrics.inc_errors();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Malformed MTProto Obfs2 client handshake header",
            ));
        }
    };

    let codec = ProtoCodec::from_tag(&parsed.proto_tag)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Unsupported MTProto protocol tag"))?;

    let dc_idx: i16 = if parsed.is_media {
        -(parsed.dc_id as i16)
    } else {
        parsed.dc_id as i16
    };

    let relay_init = generate_relay_init(&parsed.proto_tag, dc_idx);
    let crypto_ctx = build_crypto_ctx(&parsed.dec_prekey_and_iv, &secret, &relay_init);
    let (mut c2u_crypto, mut u2c_crypto) = crypto_ctx.split();

    let target_addr = upstream_override.unwrap_or_else(|| get_dc_address(parsed.dc_id, parsed.is_test_dc));

    // Attempt direct TCP upstream relay first
    let mut upstream = match TcpStream::connect(target_addr).await {
        Ok(s) => s,
        Err(e) => {
            metrics.inc_errors();
            return Err(e);
        }
    };

    crate::proxy::tune_socket(&mut upstream);

    // Send the 64-byte relay_init handshake to the upstream server
    upstream.write_all(&relay_init).await?;
    upstream.flush().await?;

    // Execute duplex streaming with in-place keystream encryption/decryption
    let (mut client_reader, mut client_writer) = tokio::io::split(client_stream);
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    let mut splitter = MsgSplitter::new(codec);

    // Task 1: Client -> Upstream
    let m1 = Arc::clone(&metrics);
    let client_to_upstream = async move {
        let mut buf = [0u8; 16384];
        let mut cipher_buf = [0u8; 16384];
        loop {
            let n = client_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            m1.add_bytes_up(n as u64);

            c2u_crypto.decrypt_client_inplace(&mut buf[..n]);

            cipher_buf[..n].copy_from_slice(&buf[..n]);
            c2u_crypto.encrypt_tg_inplace(&mut cipher_buf[..n]);

            let packets = splitter.split(&cipher_buf[..n], &buf[..n]);
            for pkt in packets {
                upstream_writer.write_all(&pkt).await?;
            }
            upstream_writer.flush().await?;
        }
        let tail = splitter.flush();
        for pkt in tail {
            upstream_writer.write_all(&pkt).await?;
        }
        upstream_writer.flush().await?;
        upstream_writer.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    // Task 2: Upstream -> Client
    let m2 = Arc::clone(&metrics);
    let upstream_to_client = async move {
        let mut buf = [0u8; 16384];
        loop {
            let n = upstream_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            m2.add_bytes_down(n as u64);

            u2c_crypto.decrypt_tg_inplace(&mut buf[..n]);
            u2c_crypto.encrypt_client_inplace(&mut buf[..n]);

            client_writer.write_all(&buf[..n]).await?;
            client_writer.flush().await?;
        }
        client_writer.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        r1 = client_to_upstream => {
            if let Err(e) = r1 {
                metrics.inc_errors();
                return Err(e);
            }
        }
        r2 = upstream_to_client => {
            if let Err(e) = r2 {
                metrics.inc_errors();
                return Err(e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto_codec_conversions() {
        assert_eq!(ProtoCodec::from_tag(&PROTO_TAG_ABRIDGED), Some(ProtoCodec::Abridged));
        assert_eq!(ProtoCodec::from_tag(&PROTO_TAG_INTERMEDIATE), Some(ProtoCodec::Intermediate));
        assert_eq!(ProtoCodec::from_tag(&PROTO_TAG_SECURE), Some(ProtoCodec::PaddedIntermediate));
        assert_eq!(ProtoCodec::from_tag(&[0, 1, 2, 3]), None);

        assert_eq!(ProtoCodec::Abridged.to_tag(), PROTO_TAG_ABRIDGED);
        assert_eq!(ProtoCodec::Intermediate.to_tag(), PROTO_TAG_INTERMEDIATE);
        assert_eq!(ProtoCodec::PaddedIntermediate.to_tag(), PROTO_TAG_SECURE);
    }

    #[test]
    fn test_dc_routing_endpoints() {
        assert_eq!(get_dc_address(1, false).to_string(), "149.154.175.50:443");
        assert_eq!(get_dc_address(2, false).to_string(), "149.154.167.51:443");
        assert_eq!(get_dc_address(3, false).to_string(), "149.154.175.100:443");
        assert_eq!(get_dc_address(4, false).to_string(), "149.154.167.91:443");
        assert_eq!(get_dc_address(5, false).to_string(), "149.154.171.5:443");

        assert_eq!(get_dc_ws_host(2, false), "kws2.web.telegram.org");
        assert_eq!(get_dc_ws_host(2, true), "kws2-1.web.telegram.org");
    }

    #[test]
    fn test_relay_init_constraints() {
        let tag = PROTO_TAG_INTERMEDIATE;
        let init = generate_relay_init(&tag, 2);
        assert_ne!(init[0], 0xEF);
        assert_ne!(&init[0..4], b"HEAD");
        assert_ne!(&init[0..4], b"POST");
        assert_ne!(&init[0..4], b"GET ");
        assert_ne!(&init[4..8], &[0, 0, 0, 0]);
    }
}

