//! FakeTLS record layer parsing, HMAC-SHA256 authentication, ServerHello synthesis,
//! and TLS ApplicationData stream wrapping for Telegram client traffic.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::metrics::ProxyMetrics;

pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

pub const CLIENT_RANDOM_OFFSET: usize = 11;
pub const CLIENT_RANDOM_LEN: usize = 32;
pub const SESSION_ID_OFFSET: usize = 44;
pub const SESSION_ID_LEN: usize = 32;

pub const TIMESTAMP_TOLERANCE: i64 = 120; // 120 seconds tolerance window
pub const TLS_APPDATA_MAX: usize = 16384;

/// 127-byte TLS 1.2 / TLS 1.3 ServerHello template conforming to standard MTProto FakeTLS.
pub const SERVER_HELLO_TEMPLATE: [u8; 127] = [
    // Record Header: Handshake (0x16), TLS 1.2 (0x0303), length 122 (0x007a)
    0x16, 0x03, 0x03, 0x00, 0x7a,
    // Handshake Header: ServerHello (0x02), length 118 (0x000076)
    0x02, 0x00, 0x00, 0x76,
    // Version: TLS 1.2 (0x0303)
    0x03, 0x03,
    // Server Random placeholder: 32 zeros (offset 11..43)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // Session ID Length: 32 (0x20)
    0x20,
    // Session ID placeholder: 32 zeros (offset 44..76)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301), Compression: null (0x00)
    0x13, 0x01, 0x00,
    // Extensions Length: 46 (0x002e)
    0x00, 0x2e,
    // Extension: key_share (0x0033), length 36 (0x0024), group X25519 (0x001d), key_exchange length 32 (0x0020)
    0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
    // Ephemeral public key placeholder: 32 zeros (offset 89..121)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // Extension: supported_versions (0x002b), length 2 (0x0002), selected TLS 1.3 (0x0304)
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
];

pub const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// Configuration for the Telegram Gateway listener.
#[derive(Clone, Debug)]
pub struct TgGatewayConfig {
    pub listen_addr: SocketAddr,
    pub secret: [u8; 16],
    pub masking_domain: Option<String>,
    pub upstream_override: Option<SocketAddr>,
}

impl TgGatewayConfig {
    pub fn new(listen_addr: SocketAddr, secret: [u8; 16], masking_domain: Option<String>) -> Self {
        Self {
            listen_addr,
            secret,
            masking_domain,
            upstream_override: None,
        }
    }
}

/// Parsed and cryptographically validated ClientHello fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedClientHello {
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
    pub timestamp: u32,
}

/// Parses secrets in standard hex, "dd"-prefixed, or "ee"-prefixed (FakeTLS with masking domain) formats.
pub fn parse_secret(input: &str) -> Result<([u8; 16], Option<String>), String> {
    let clean = input.trim();
    if clean.starts_with("dd") || clean.starts_with("DD") {
        if clean.len() != 34 {
            return Err("Invalid dd secret length: must be 34 hex characters".to_string());
        }
        let mut key = [0u8; 16];
        hex::decode_to_slice(&clean[2..34], &mut key)
            .map_err(|e| format!("Invalid hex in dd secret: {e}"))?;
        Ok((key, None))
    } else if clean.starts_with("ee") || clean.starts_with("EE") {
        if clean.len() < 34 {
            return Err("Invalid ee secret length: must be at least 34 hex characters".to_string());
        }
        let mut key = [0u8; 16];
        hex::decode_to_slice(&clean[2..34], &mut key)
            .map_err(|e| format!("Invalid hex in ee secret: {e}"))?;
        let domain_bytes = hex::decode(&clean[34..])
            .map_err(|e| format!("Invalid masking domain hex: {e}"))?;
        let domain = String::from_utf8(domain_bytes)
            .map_err(|e| format!("Masking domain is not valid UTF-8: {e}"))?;
        Ok((key, Some(domain)))
    } else if clean.len() == 32 {
        let mut key = [0u8; 16];
        hex::decode_to_slice(clean, &mut key)
            .map_err(|e| format!("Invalid hex in 32-character secret: {e}"))?;
        Ok((key, None))
    } else {
        Err("Secret must be 32 hex chars, dd+32 hex, or ee+32 hex+domain hex".to_string())
    }
}

/// Verifies a ClientHello TLS record against the 16-byte shared secret.
/// Enforces HMAC-SHA256 signature verification over the zeroed random field and 120s timestamp window.
pub fn verify_client_hello(data: &[u8], secret: &[u8; 16]) -> Option<VerifiedClientHello> {
    if data.len() < 43 || data[0] != TLS_RECORD_HANDSHAKE || data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].fill(0);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if expected[..28].ct_eq(&client_random[..28]).unwrap_u8() != 1 {
        return None;
    }

    let mut ts_xor = [0u8; 4];
    for i in 0..4 {
        ts_xor[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_xor);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if (now - (timestamp as i64)).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some(VerifiedClientHello {
        client_random,
        session_id,
        timestamp,
    })
}

/// Synthesizes a valid TLS ServerHello response matching client random and session parameters.
pub fn build_server_hello(secret: &[u8; 16], client_random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut sh = SERVER_HELLO_TEMPLATE.to_vec();
    sh[44..76].copy_from_slice(session_id);

    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut sh[89..121]);

    let ccs = CCS_FRAME;
    let encrypted_size = rng.gen_range(1900..=2100);
    let mut encrypted_data = vec![0u8; encrypted_size];
    rng.fill_bytes(&mut encrypted_data);

    let mut app_record = Vec::with_capacity(5 + encrypted_size);
    app_record.extend_from_slice(&[TLS_RECORD_APPDATA, 0x03, 0x03]);
    app_record.extend_from_slice(&(encrypted_size as u16).to_be_bytes());
    app_record.extend_from_slice(&encrypted_data);

    let mut response = Vec::with_capacity(sh.len() + ccs.len() + app_record.len());
    response.extend_from_slice(&sh);
    response.extend_from_slice(&ccs);
    response.extend_from_slice(&app_record);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("Valid secret length");
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();

    response[11..43].copy_from_slice(&server_random);
    response
}

/// Encapsulates raw MTProto stream chunks into TLS ApplicationData records (`0x17, 0x03, 0x03`).
pub fn wrap_tls_records(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len() + (data.len() / TLS_APPDATA_MAX + 1) * 5);
    let mut offset = 0;
    while offset < data.len() {
        let chunk_len = std::cmp::min(data.len() - offset, TLS_APPDATA_MAX);
        let chunk = &data[offset..offset + chunk_len];
        out.extend_from_slice(&[TLS_RECORD_APPDATA, 0x03, 0x03]);
        out.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        out.extend_from_slice(chunk);
        offset += chunk_len;
    }
    out
}

/// Transparent stream wrapper decapsulating incoming TLS records and encapsulating outgoing payload chunks.
pub struct FakeTlsStream<S> {
    inner: S,
    read_buf: BytesMut,
    decapsulated: BytesMut,
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl<S> FakeTlsStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: BytesMut::with_capacity(32768),
            decapsulated: BytesMut::with_capacity(32768),
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FakeTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 1. Drain any already decapsulated payload bytes
            if !self.decapsulated.is_empty() {
                let to_copy = std::cmp::min(buf.remaining(), self.decapsulated.len());
                buf.put_slice(&self.decapsulated[..to_copy]);
                self.decapsulated.advance(to_copy);
                return Poll::Ready(Ok(()));
            }

            // 2. Parse complete TLS records from read_buf
            let mut parsed_record = false;
            while self.read_buf.len() >= 5 {
                let rtype = self.read_buf[0];
                let rec_len = u16::from_be_bytes([self.read_buf[3], self.read_buf[4]]) as usize;
                let total_rec_len = 5 + rec_len;

                if self.read_buf.len() < total_rec_len {
                    // Incomplete record, need to read more bytes
                    break;
                }

                // Complete record available
                let rec = self.read_buf.split_to(total_rec_len);
                parsed_record = true;

                if rtype == TLS_RECORD_CCS {
                    // Ignore ChangeCipherSpec frames
                    continue;
                } else if rtype == TLS_RECORD_APPDATA {
                    // Extract ApplicationData payload
                    self.decapsulated.extend_from_slice(&rec[5..]);
                    let to_copy = std::cmp::min(buf.remaining(), self.decapsulated.len());
                    buf.put_slice(&self.decapsulated[..to_copy]);
                    self.decapsulated.advance(to_copy);
                    return Poll::Ready(Ok(()));
                } else {
                    // Unexpected record type encountered in stream
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unexpected TLS record type: 0x{:02X}", rtype),
                    )));
                }
            }

            // 3. Read more raw bytes from the underlying stream
            let mut stack_buf = [0u8; 16384];
            let mut read_buf_wrapper = ReadBuf::new(&mut stack_buf);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf_wrapper) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf_wrapper.filled().len();
                    if bytes_read == 0 {
                        // EOF reached
                        return Poll::Ready(Ok(()));
                    }
                    self.read_buf.extend_from_slice(&stack_buf[..bytes_read]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if parsed_record && !self.decapsulated.is_empty() {
                        let to_copy = std::cmp::min(buf.remaining(), self.decapsulated.len());
                        buf.put_slice(&self.decapsulated[..to_copy]);
                        self.decapsulated.advance(to_copy);
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FakeTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        // Flush any previously buffered TLS records first
        while this.write_pos < this.write_buf.len() {
            let pending_slice = &this.write_buf[this.write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, pending_slice) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf.clear();
        this.write_pos = 0;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Encapsulate input payload into TLS records
        let wrapped = wrap_tls_records(buf);
        this.write_buf = wrapped;

        // Attempt initial write of the newly wrapped buffer
        while this.write_pos < this.write_buf.len() {
            let pending_slice = &this.write_buf[this.write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, pending_slice) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        // All input buffer bytes accepted for encapsulation
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.write_pos < this.write_buf.len() {
            let pending_slice = &this.write_buf[this.write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, pending_slice) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.write_buf.clear();
        this.write_pos = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.as_mut().poll_flush(cx);
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Active probe defense: transparently proxies client connection to the configured masking domain on port 443.
pub async fn proxy_to_masking_domain(
    mut client: TcpStream,
    initial_data: &[u8],
    domain: &str,
) -> io::Result<()> {
    let target = format!("{}:443", domain);
    let mut upstream = TcpStream::connect(&target).await?;

    if !initial_data.is_empty() {
        upstream.write_all(initial_data).await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Runs the Telegram FakeTLS Gateway listener on port 1443 (or configured address).
pub async fn run_tg_gateway(
    config: TgGatewayConfig,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    let listener = TcpListener::bind(config.listen_addr).await?;

    loop {
        let (client_stream, remote_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                metrics.inc_errors();
                eprintln!("[TgGateway] Error accepting client connection: {e}");
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        let metrics_clone = Arc::clone(&metrics);
        let config_clone = config.clone();

        tokio::spawn(async move {
            let _guard = metrics_clone.connection_guard();
            if let Err(e) = handle_inbound_connection(client_stream, remote_addr, config_clone, metrics_clone).await {
                eprintln!("[TgGateway] Connection {remote_addr} ended with notice: {e}");
            }
        });
    }
}

/// Handles an incoming TCP connection on the Telegram Gateway port.
async fn handle_inbound_connection(
    mut stream: TcpStream,
    _remote_addr: SocketAddr,
    config: TgGatewayConfig,
    metrics: Arc<ProxyMetrics>,
) -> io::Result<()> {
    crate::proxy::tune_socket(&mut stream);

    // Read the initial byte with a 10s handshake timeout
    let mut initial_byte = [0u8; 1];
    let res = tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        stream.read_exact(&mut initial_byte),
    )
    .await;

    if res.is_err() || res.unwrap().is_err() {
        return Ok(());
    }

    if initial_byte[0] == TLS_RECORD_HANDSHAKE {
        // 1. Inbound TLS Record: Read remaining 4 header bytes
        let mut hdr_rest = [0u8; 4];
        stream.read_exact(&mut hdr_rest).await?;
        let rec_len = u16::from_be_bytes([hdr_rest[2], hdr_rest[3]]) as usize;

        let mut rec_body = vec![0u8; rec_len];
        stream.read_exact(&mut rec_body).await?;

        let mut client_hello = Vec::with_capacity(5 + rec_len);
        client_hello.push(initial_byte[0]);
        client_hello.extend_from_slice(&hdr_rest);
        client_hello.extend_from_slice(&rec_body);

        match verify_client_hello(&client_hello, &config.secret) {
            Some(verified) => {
                // Cryptographically validated ClientHello: Synthesize ServerHello
                let server_hello = build_server_hello(&config.secret, &verified.client_random, &verified.session_id);
                stream.write_all(&server_hello).await?;
                stream.flush().await?;

                // Wrap stream in FakeTlsStream
                let mut tls_stream = FakeTlsStream::new(stream);

                // Read 64-byte Obfs2 handshake header
                let mut obfs_hdr = [0u8; 64];
                tls_stream.read_exact(&mut obfs_hdr).await?;

                // Relay into MTProto handler
                crate::mtproto::handle_mtproto_stream(
                    tls_stream,
                    obfs_hdr,
                    config.secret,
                    config.upstream_override,
                    metrics,
                )
                .await
            }
            None => {
                // Invalid or unauthenticated FakeTLS signature: Route to masking domain
                if let Some(masking) = config.masking_domain {
                    proxy_to_masking_domain(stream, &client_hello, &masking).await
                } else {
                    Ok(())
                }
            }
        }
    } else if let Some(masking) = config.masking_domain {
        // Non-TLS initial byte (e.g. plain HTTP GET/POST): Send HTTP 301 Redirect
        let redirect_response = format!(
            "HTTP/1.1 301 Moved Permanently\r\n\
            Location: https://{masking}/\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\r\n"
        );
        let _ = stream.write_all(redirect_response.as_bytes()).await;
        let _ = stream.flush().await;
        Ok(())
    } else {
        // Plain direct MTProto Obfs2 connection without FakeTLS wrapper
        let mut rest_handshake = [0u8; 63];
        stream.read_exact(&mut rest_handshake).await?;
        let mut full_handshake = [0u8; 64];
        full_handshake[0] = initial_byte[0];
        full_handshake[1..].copy_from_slice(&rest_handshake);

        crate::mtproto::handle_mtproto_stream(
            stream,
            full_handshake,
            config.secret,
            config.upstream_override,
            metrics,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_parser() {
        let raw = "abcdef0123456789abcdef0123456789";
        let (k, d) = parse_secret(raw).unwrap();
        assert_eq!(hex::encode(k), raw);
        assert!(d.is_none());

        let dd = "ddabcdef0123456789abcdef0123456789";
        let (k2, d2) = parse_secret(dd).unwrap();
        assert_eq!(hex::encode(k2), &dd[2..]);
        assert!(d2.is_none());

        let ee = "eeabcdef0123456789abcdef0123456789676f6f676c652e636f6d";
        let (k3, d3) = parse_secret(ee).unwrap();
        assert_eq!(hex::encode(k3), "abcdef0123456789abcdef0123456789");
        assert_eq!(d3.as_deref(), Some("google.com"));
    }

    #[test]
    fn test_wrap_records_header() {
        let payload = vec![0x55; 50];
        let wrapped = wrap_tls_records(&payload);
        assert_eq!(wrapped[0], TLS_RECORD_APPDATA);
        assert_eq!(wrapped[1..3], [0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([wrapped[3], wrapped[4]]), 50);
        assert_eq!(&wrapped[5..], &payload[..]);
    }
}

