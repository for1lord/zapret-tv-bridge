use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::access::upstream_allowed;

/// Default time-to-live for cached DNS entries (10 minutes).
pub const DEFAULT_DNS_TTL: Duration = Duration::from_secs(600);

/// Maximum cache capacity to prevent unbounded memory growth.
pub const MAX_DNS_CACHE_CAPACITY: usize = 4096;

/// Entry stored in the in-memory DNS cache.
#[derive(Debug, Clone, Copy)]
pub struct DnsCacheEntry {
    pub ip: IpAddr,
    pub expires_at: Instant,
}

impl DnsCacheEntry {
    pub fn new(ip: IpAddr, ttl: Duration) -> Self {
        Self {
            ip,
            expires_at: Instant::now() + ttl,
        }
    }

    #[inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Thread-safe in-memory DNS cache with TTL expiration and bounded capacity.
pub struct DnsCache {
    entries: RwLock<HashMap<String, DnsCacheEntry>>,
    default_ttl: Duration,
    max_capacity: usize,
}

impl DnsCache {
    pub fn new(default_ttl: Duration, max_capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
            max_capacity,
        }
    }

    /// Looks up an unexpired IP for the specified hostname.
    pub fn get(&self, hostname: &str) -> Option<IpAddr> {
        let now = Instant::now();
        let guard = self.entries.read();
        if let Some(entry) = guard.get(&hostname.to_ascii_lowercase()) {
            if !entry.is_expired(now) {
                return Some(entry.ip);
            }
        }
        None
    }

    /// Stores an IP for the given hostname with the default TTL.
    pub fn insert(&self, hostname: &str, ip: IpAddr) {
        self.insert_with_ttl(hostname, ip, self.default_ttl);
    }

    /// Stores an IP for the given hostname with a custom TTL.
    pub fn insert_with_ttl(&self, hostname: &str, ip: IpAddr, ttl: Duration) {
        let now = Instant::now();
        let entry = DnsCacheEntry::new(ip, ttl);
        let mut guard = self.entries.write();

        // Evict expired entries if cache exceeds capacity threshold
        if guard.len() >= self.max_capacity {
            guard.retain(|_, v| !v.is_expired(now));
        }

        // If still full after pruning expired, drop one item to bound memory
        if guard.len() >= self.max_capacity {
            if let Some(key_to_remove) = guard.keys().next().cloned() {
                guard.remove(&key_to_remove);
            }
        }

        guard.insert(hostname.to_ascii_lowercase(), entry);
    }

    /// Removes an entry from the cache.
    pub fn remove(&self, hostname: &str) -> Option<IpAddr> {
        let mut guard = self.entries.write();
        guard.remove(&hostname.to_ascii_lowercase()).map(|e| e.ip)
    }

    /// Returns the number of entries currently in cache.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Checks whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Prunes expired entries from the cache, returning the number of removed entries.
    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.entries.write();
        let original_len = guard.len();
        guard.retain(|_, v| !v.is_expired(now));
        original_len.saturating_sub(guard.len())
    }
}

/// Global DNS cache initialized lazily using `std::sync::LazyLock`.
///
/// Replaces legacy `lazy_static` with zero external crate dependencies.
pub static GLOBAL_DNS_CACHE: LazyLock<DnsCache> = LazyLock::new(|| {
    DnsCache::new(DEFAULT_DNS_TTL, MAX_DNS_CACHE_CAPACITY)
});

/// Validates whether a candidate IP address is routable and valid.
pub fn is_valid_candidate_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Filter 0.0.0.0/8, 127.0.0.0/8
            if octets[0] == 0 || octets[0] == 127 {
                return false;
            }
            // Explicit filter of known unroutable IPs from legacy reference
            if v4 == std::net::Ipv4Addr::new(94, 190, 64, 51)
                || v4 == std::net::Ipv4Addr::new(151, 101, 195, 6)
                || v4 == std::net::Ipv4Addr::new(129, 134, 30, 12)
            {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}

const DNS_QUERY_ID: u16 = 0x1234;

/// One address to try, and whether it may be cached before any payload arrives.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    ip: IpAddr,
    /// System-resolver answers (ISP GGC) are cached only after downstream bytes.
    confirm_before_cache: bool,
}

/// Successful outbound TCP connection.
pub struct Outbound {
    pub stream: TcpStream,
    pub ip: IpAddr,
    /// When true, the caller caches `ip` only after the remote sends data.
    pub confirm_cache: bool,
}

fn build_dns_query(hostname: &str) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&DNS_QUERY_ID.to_be_bytes());
    // RD=1, one question.
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for part in hostname.split('.') {
        let b = part.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return None;
        }
        packet.push(b.len() as u8);
        packet.extend_from_slice(b);
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    Some(packet)
}

/// Skips a domain name. A compression pointer ends the name on the wire.
fn skip_dns_name(buf: &[u8], mut idx: usize) -> Option<usize> {
    let mut hops = 0;
    loop {
        if idx >= buf.len() || hops > 32 {
            return None;
        }
        let len = buf[idx];
        if len == 0 {
            return idx.checked_add(1);
        }
        if len & 0xC0 == 0xC0 {
            if idx + 1 >= buf.len() {
                return None;
            }
            return idx.checked_add(2);
        }
        if len & 0xC0 != 0 || len > 63 {
            return None;
        }
        idx = idx.checked_add(1 + len as usize)?;
        hops += 1;
    }
}

/// Parses A records. The question is walked in the response, and the id must match.
pub fn parse_dns_a_answers(buf: &[u8], expected_id: u16) -> Option<Vec<Ipv4Addr>> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = flags & 0x8000 != 0;
    let rcode = flags & 0x000F;
    if !qr || rcode != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut idx = 12usize;
    for _ in 0..qdcount {
        idx = skip_dns_name(buf, idx)?;
        idx = idx.checked_add(4)?;
        if idx > buf.len() {
            return None;
        }
    }
    let mut ips = Vec::new();
    for _ in 0..ancount {
        idx = skip_dns_name(buf, idx)?;
        if idx + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let rdlen = u16::from_be_bytes([buf[idx + 8], buf[idx + 9]]) as usize;
        idx += 10;
        if idx + rdlen > buf.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            ips.push(Ipv4Addr::new(buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]));
        }
        idx += rdlen;
    }
    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

/// Queries a public DNS server directly over TCP (RFC 7766) for IPv4 (A) records.
/// Avoids ISP UDP 53 interception and spoofed NXDOMAIN / blackhole responses.
pub async fn query_dns_tcp(server_ip: &str, hostname: &str) -> Option<Vec<Ipv4Addr>> {
    let packet = build_dns_query(hostname)?;
    let target = format!("{server_ip}:53");
    let mut stream = timeout(Duration::from_millis(1500), TcpStream::connect(&target)).await.ok()?.ok()?;

    let len = packet.len() as u16;
    let mut tcp_msg = Vec::with_capacity(2 + packet.len());
    tcp_msg.extend_from_slice(&len.to_be_bytes());
    tcp_msg.extend_from_slice(&packet);

    timeout(Duration::from_millis(1500), stream.write_all(&tcp_msg)).await.ok()?.ok()?;

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_millis(2000), stream.read_exact(&mut len_buf)).await.ok()?.ok()?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len < 12 || resp_len > 4096 {
        return None;
    }

    let mut buf = vec![0u8; resp_len];
    timeout(Duration::from_millis(2000), stream.read_exact(&mut buf)).await.ok()?.ok()?;
    parse_dns_a_answers(&buf, DNS_QUERY_ID)
}

/// Queries a public DNS server directly over UDP for IPv4 (A) records.
pub async fn query_dns_udp(server_ip: &str, hostname: &str) -> Option<Vec<Ipv4Addr>> {
    let packet = build_dns_query(hostname)?;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let target = format!("{server_ip}:53");
    socket.send_to(&packet, &target).await.ok()?;

    let mut buf = [0u8; 1024];
    let (len, _) = timeout(Duration::from_millis(1500), socket.recv_from(&mut buf)).await.ok()?.ok()?;
    if len < 12 {
        return None;
    }
    parse_dns_a_answers(&buf[..len], DNS_QUERY_ID)
}

fn push_candidate(out: &mut Vec<Candidate>, ip: IpAddr, confirm_before_cache: bool, allow_local: bool) {
    if !upstream_allowed(ip, allow_local) || out.iter().any(|c| c.ip == ip) {
        return;
    }
    out.push(Candidate {
        ip,
        confirm_before_cache,
    });
}

async fn lookup_system(hostname: &str, allow_local: bool, out: &mut Vec<Candidate>) {
    let addr_str = format!("{hostname}:443");
    if let Ok(Ok(addrs)) = timeout(Duration::from_millis(1500), tokio::net::lookup_host(addr_str)).await {
        for sa in addrs {
            // ISP answers stay uncached until the connection actually carries data.
            push_candidate(out, sa.ip(), true, allow_local);
        }
    }
}

async fn lookup_public(hostname: &str, allow_local: bool, out: &mut Vec<Candidate>) {
    for pub_dns in &["1.1.1.1", "8.8.8.8"] {
        if let Some(ips) = query_dns_tcp(pub_dns, hostname).await {
            for ip4 in ips {
                push_candidate(out, IpAddr::V4(ip4), false, allow_local);
            }
            if out.iter().any(|c| !c.confirm_before_cache) {
                return;
            }
        }
    }
    for pub_dns in &["1.1.1.1", "8.8.8.8"] {
        if let Some(ips) = query_dns_udp(pub_dns, hostname).await {
            for ip4 in ips {
                push_candidate(out, IpAddr::V4(ip4), false, allow_local);
            }
            if out.iter().any(|c| !c.confirm_before_cache) {
                return;
            }
        }
    }
}

/// Resolves candidate IP addresses for a given hostname.
///
/// Public resolvers over TCP are preferred for the long-lived cache.
/// The system resolver is included so a nearby CDN node can still win the race,
/// but those addresses are not stored until payload bytes arrive.
pub async fn resolve_candidate_ips(hostname: &str) -> Vec<IpAddr> {
    resolve_candidates(hostname, true)
        .await
        .into_iter()
        .map(|c| c.ip)
        .collect()
}

async fn resolve_candidates(hostname: &str, allow_local: bool) -> Vec<Candidate> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let mut out = Vec::new();
        push_candidate(&mut out, ip, false, allow_local);
        return out;
    }

    let mut candidates = Vec::new();
    if let Some(cached_ip) = GLOBAL_DNS_CACHE.get(hostname) {
        push_candidate(&mut candidates, cached_ip, false, allow_local);
    }

    let streaming = hostname.contains("googlevideo")
        || hostname.contains("youtube")
        || hostname.contains("ytimg")
        || hostname.contains("ggpht");
    if streaming {
        lookup_system(hostname, allow_local, &mut candidates).await;
    }
    lookup_public(hostname, allow_local, &mut candidates).await;
    if !candidates.iter().any(|c| !c.confirm_before_cache) {
        lookup_system(hostname, allow_local, &mut candidates).await;
    }
    candidates
}

pub const SOCKET_BUF_SIZE: usize = 128 * 1024; // 128 KB OS socket buffer

/// Configures socket options: TCP_NODELAY and 128 KB receive/send buffers.
pub fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = sock.set_send_buffer_size(SOCKET_BUF_SIZE);
}

async fn connect_one(ip: IpAddr, port: u16) -> Option<TcpStream> {
    let target = SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(2500), TcpStream::connect(target)).await {
        Ok(Ok(stream)) => {
            tune_socket(&stream);
            Some(stream)
        }
        _ => None,
    }
}

/// Connects to a remote host across candidate IPs at once.
///
/// `allow_local` permits a loopback upstream. Private and link-local addresses
/// stay closed. Public-resolver answers are cached immediately. System-resolver
/// answers set `confirm_cache` so the caller stores them only after data flows.
pub async fn connect_to_remote(hostname: &str, port: u16, allow_local: bool) -> Option<Outbound> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        if !upstream_allowed(ip, allow_local) {
            return None;
        }
        let stream = connect_one(ip, port).await?;
        return Some(Outbound {
            stream,
            ip,
            confirm_cache: false,
        });
    }

    let mut candidates = resolve_candidates(hostname, allow_local).await;
    if candidates.is_empty() {
        return None;
    }
    candidates.truncate(6);

    let mut pending = JoinSet::new();
    for candidate in candidates {
        pending.spawn(async move {
            let stream = connect_one(candidate.ip, port).await?;
            Some((stream, candidate))
        });
    }

    while let Some(joined) = pending.join_next().await {
        if let Ok(Some((stream, candidate))) = joined {
            pending.abort_all();
            if !candidate.confirm_before_cache {
                GLOBAL_DNS_CACHE.insert(hostname, candidate.ip);
            } else {
                GLOBAL_DNS_CACHE.remove(hostname);
            }
            return Some(Outbound {
                stream,
                ip: candidate.ip,
                confirm_cache: candidate.confirm_before_cache,
            });
        }
    }

    GLOBAL_DNS_CACHE.remove(hostname);
    None
}

pub fn remember_confirmed_ip(hostname: &str, ip: IpAddr) {
    if upstream_allowed(ip, false) {
        GLOBAL_DNS_CACHE.insert_with_ttl(hostname, ip, Duration::from_secs(45));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_dns_cache_ttl_and_eviction() {
        let cache = DnsCache::new(Duration::from_millis(50), 2);
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "8.8.8.8".parse().unwrap();
        let ip3: IpAddr = "9.9.9.9".parse().unwrap();

        cache.insert("example1.com", ip1);
        cache.insert("example2.com", ip2);
        assert_eq!(cache.get("example1.com"), Some(ip1));
        assert_eq!(cache.get("example2.com"), Some(ip2));
        assert_eq!(cache.len(), 2);

        // Third entry triggers eviction due to capacity = 2
        cache.insert("example3.com", ip3);
        assert_eq!(cache.len(), 2);

        // Sleep to test TTL expiration
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cache.get("example3.com"), None);
    }

    #[test]
    fn test_is_valid_candidate_ip() {
        assert!(!is_valid_candidate_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_valid_candidate_ip("0.0.0.0".parse().unwrap()));
        assert!(!is_valid_candidate_ip("94.190.64.51".parse().unwrap()));
        assert!(!is_valid_candidate_ip("::1".parse().unwrap()));
        assert!(!is_valid_candidate_ip("::".parse().unwrap()));
        assert!(is_valid_candidate_ip("1.1.1.1".parse().unwrap()));
        assert!(is_valid_candidate_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_dns_cache_prune() {
        let cache = DnsCache::new(Duration::from_millis(50), 10);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.insert("expired.com", ip);
        cache.insert_with_ttl("valid.com", ip, Duration::from_secs(60));
        assert_eq!(cache.len(), 2);

        std::thread::sleep(Duration::from_millis(60));
        let pruned = cache.prune_expired();
        assert_eq!(pruned, 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("valid.com"), Some(ip));
        assert_eq!(cache.get("expired.com"), None);
    }
}
