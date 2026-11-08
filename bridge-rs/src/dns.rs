use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tokio::net::TcpStream;
use tokio::time::timeout;

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

/// Queries a public DNS server directly over UDP for IPv4 (A) records.
pub async fn query_dns_udp(server_ip: &str, hostname: &str) -> Option<Vec<Ipv4Addr>> {
    let mut packet = Vec::with_capacity(512);
    // Header: Transaction ID (0x1234), Flags (0x0100 standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    packet.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for part in hostname.split('.') {
        let b = part.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return None;
        }
        packet.push(b.len() as u8);
        packet.extend_from_slice(b);
    }
    packet.push(0x00);
    // QTYPE: 1 (A), QCLASS: 1 (IN)
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let target = format!("{server_ip}:53");
    socket.send_to(&packet, &target).await.ok()?;

    let mut buf = [0u8; 1024];
    let (len, _) = timeout(Duration::from_millis(1500), socket.recv_from(&mut buf)).await.ok()?.ok()?;
    if len < packet.len() || len < 12 {
        return None;
    }

    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 {
        return None;
    }

    let mut idx = packet.len();
    let mut ips = Vec::new();

    for _ in 0..ancount {
        if idx >= len {
            break;
        }
        if (buf[idx] & 0xC0) == 0xC0 {
            idx += 2;
        } else {
            while idx < len && buf[idx] != 0 {
                idx += (buf[idx] as usize) + 1;
            }
            idx += 1;
        }

        if idx + 10 > len {
            break;
        }

        let rtype = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let rdlen = u16::from_be_bytes([buf[idx + 8], buf[idx + 9]]) as usize;
        idx += 10;

        if rtype == 1 && rdlen == 4 && idx + 4 <= len {
            let ipv4 = Ipv4Addr::new(buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]);
            ips.push(ipv4);
        }
        idx += rdlen;
    }

    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

/// Resolves candidate IP addresses for a given hostname.
///
/// Checks in-memory DNS cache first. On miss, resolves via direct public DNS and system resolver.
pub async fn resolve_candidate_ips(hostname: &str) -> Vec<IpAddr> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return if is_valid_candidate_ip(ip) { vec![ip] } else { Vec::new() };
    }

    let mut candidates = Vec::new();

    // 1. Check in-memory DNS cache first for instant connection
    if let Some(cached_ip) = GLOBAL_DNS_CACHE.get(hostname) {
        if is_valid_candidate_ip(cached_ip) {
            candidates.push(cached_ip);
        }
    }

    // 2. Query direct public DNS resolvers (1.1.1.1, 8.8.8.8) for unpoisoned fast CDN endpoints
    for pub_dns in &["1.1.1.1", "8.8.8.8"] {
        if let Some(ips) = query_dns_udp(pub_dns, hostname).await {
            for ip4 in ips {
                let ip = IpAddr::V4(ip4);
                if is_valid_candidate_ip(ip) && !candidates.contains(&ip) {
                    candidates.push(ip);
                }
            }
            if !candidates.is_empty() {
                break;
            }
        }
    }

    // 3. Fallback to system resolver via lookup_host for LAN/intranet or other domains
    let addr_str = format!("{hostname}:443");
    if let Ok(Ok(addrs)) = timeout(Duration::from_millis(2500), tokio::net::lookup_host(&addr_str)).await {
        for sa in addrs {
            let ip = sa.ip();
            if is_valid_candidate_ip(ip) && !candidates.contains(&ip) {
                candidates.push(ip);
            }
        }
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

/// Connects to a remote host with fast failover across candidate IPs and socket tuning.
///
/// Upon successful connection, caches the working IP address in `GLOBAL_DNS_CACHE`
/// and configures `TCP_NODELAY` and 128 KB socket buffers via `socket2`.
pub async fn connect_to_remote(hostname: &str, port: u16) -> Option<(TcpStream, IpAddr)> {
    // If hostname is already an IP address, connect directly with fast timeout
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let target_addr = SocketAddr::new(ip, port);
        if let Ok(Ok(stream)) = timeout(Duration::from_millis(3500), TcpStream::connect(target_addr)).await {
            tune_socket(&stream);
            return Some((stream, ip));
        }
        return None;
    }

    let candidates = resolve_candidate_ips(hostname).await;
    let connect_timeout = Duration::from_millis(3000);

    for tip in &candidates {
        let target_addr = SocketAddr::new(*tip, port);
        match timeout(connect_timeout, TcpStream::connect(target_addr)).await {
            Ok(Ok(stream)) => {
                tune_socket(&stream);
                GLOBAL_DNS_CACHE.insert(hostname, *tip);
                return Some((stream, *tip));
            }
            _ => continue,
        }
    }

    // Evict stale or unreachable IP from cache
    GLOBAL_DNS_CACHE.remove(hostname);

    // Direct fallback lookup by host:port
    let addr_str = format!("{hostname}:{port}");
    if let Ok(Ok(stream)) = timeout(Duration::from_millis(4000), TcpStream::connect(&addr_str)).await {
        tune_socket(&stream);
        if let Ok(peer) = stream.peer_addr() {
            let ip = peer.ip();
            if is_valid_candidate_ip(ip) {
                GLOBAL_DNS_CACHE.insert(hostname, ip);
            }
            return Some((stream, ip));
        }
    }

    None
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
