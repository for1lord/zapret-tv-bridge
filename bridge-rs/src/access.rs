//! Who may use the LAN proxy, and which upstream addresses it may open.
//!
//! Clients must sit on an on-link subnet of this machine (or on loopback).
//! Upstreams must be public unicast. Loopback upstream is allowed only when
//! the client itself is loopback, so local tests keep working and a TV cannot
//! open the machine's own services through the proxy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::sync::LazyLock;

#[derive(Clone, Debug)]
struct V4Net {
    network: u32,
    mask: u32,
}

#[derive(Clone, Debug)]
struct Snapshot {
    taken_at: Instant,
    v4: Vec<V4Net>,
    local_v4: Vec<Ipv4Addr>,
}

static SNAPSHOT: LazyLock<Mutex<Option<Snapshot>>> = LazyLock::new(|| Mutex::new(None));

const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

fn snapshot() -> Snapshot {
    let mut guard = SNAPSHOT.lock().unwrap_or_else(|e| e.into_inner());
    let fresh = guard
        .as_ref()
        .map(|s| s.taken_at.elapsed() < SNAPSHOT_TTL)
        .unwrap_or(false);
    if !fresh {
        *guard = Some(read_snapshot());
    }
    guard.as_ref().cloned().unwrap_or_else(read_snapshot)
}

fn read_snapshot() -> Snapshot {
    let (v4, local_v4) = read_ipv4_routes();
    Snapshot {
        taken_at: Instant::now(),
        v4,
        local_v4,
    }
}

/// Windows stores IPv4 in a DWORD whose first memory byte is the first octet.
fn ipv4_dword(ip: Ipv4Addr) -> u32 {
    u32::from_le_bytes(ip.octets())
}

fn dword_ipv4(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(value.to_le_bytes())
}

#[cfg(windows)]
fn read_ipv4_routes() -> (Vec<V4Net>, Vec<Ipv4Addr>) {
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIpForwardTable(table: *mut u8, size: *mut u32, order: i32) -> u32;
    }

    let mut size: u32 = 0;
    let _ = unsafe { GetIpForwardTable(std::ptr::null_mut(), &mut size, 0) };
    if size < 4 || size > 2 * 1024 * 1024 {
        return (Vec::new(), Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { GetIpForwardTable(buf.as_mut_ptr(), &mut size, 0) };
    if rc != 0 || buf.len() < 4 {
        return (Vec::new(), Vec::new());
    }
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    let mut nets = Vec::new();
    let mut locals = Vec::new();
    for i in 0..count {
        let off = 4 + i * 56;
        if off + 24 > buf.len() {
            break;
        }
        let dest = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let mask = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let kind = u32::from_le_bytes(buf[off + 20..off + 24].try_into().unwrap());
        // MIB_IPROUTE_TYPE_DIRECT = 3. Skip the default route and off-link entries.
        if kind != 3 || mask == 0 {
            continue;
        }
        let ip = dword_ipv4(dest);
        let octet0 = ip.octets()[0];
        if octet0 >= 224 {
            continue;
        }
        if mask == u32::MAX && !ip.is_broadcast() && !ip.is_unspecified() {
            locals.push(ip);
        }
        nets.push(V4Net {
            network: dest & mask,
            mask,
        });
    }
    (nets, locals)
}

#[cfg(not(windows))]
fn read_ipv4_routes() -> (Vec<V4Net>, Vec<Ipv4Addr>) {
    (
        vec![V4Net {
            network: ipv4_dword(Ipv4Addr::new(127, 0, 0, 0)),
            mask: ipv4_dword(Ipv4Addr::new(255, 0, 0, 0)),
        }],
        vec![Ipv4Addr::LOCALHOST],
    )
}

/// True when `peer` is loopback or belongs to an on-link subnet of this host.
pub fn peer_allowed(peer: SocketAddr) -> bool {
    match peer.ip() {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return true;
            }
            let snap = snapshot();
            if snap.v4.is_empty() {
                return is_rfc1918(v4);
            }
            let dword = ipv4_dword(v4);
            snap.v4.iter().any(|net| dword & net.mask == net.network)
        }
        IpAddr::V6(v6) => v6.is_loopback() || is_unicast_link_local_v6(v6) || is_ula(v6),
    }
}

pub fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
    let mut addrs = snapshot().local_v4;
    if !addrs.iter().any(|ip| ip.is_loopback()) {
        addrs.push(Ipv4Addr::LOCALHOST);
    }
    addrs
}

pub fn is_local_host(host: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']);
    let host = host.split('%').next().unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_unspecified() || local_ipv4_addrs().contains(&v4)
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        Err(_) => false,
    }
}

/// Public unicast destinations. Loopback is reachable only from a loopback client.
pub fn upstream_allowed(ip: IpAddr, allow_loopback: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return allow_loopback;
            }
            !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !is_link_local_v4(v4)
                && !is_rfc1918(v4)
                && !is_cgnat(v4)
                && !is_documentation_v4(v4)
                && !is_reserved_v4(v4)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return allow_loopback;
            }
            !v6.is_unspecified()
                && !v6.is_multicast()
                && !is_unicast_link_local_v6(v6)
                && !is_ula(v6)
                && !is_documentation_v6(v6)
        }
    }
}

fn is_link_local_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 169 && o[1] == 254
}

fn is_rfc1918(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

fn is_documentation_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 0 || o[0] >= 240
}

fn is_unicast_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ula(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

fn is_documentation_v6(v6: Ipv6Addr) -> bool {
    v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_policy() {
        assert!(!upstream_allowed("127.0.0.1".parse().unwrap(), false));
        assert!(upstream_allowed("127.0.0.1".parse().unwrap(), true));
        assert!(!upstream_allowed("192.168.1.1".parse().unwrap(), true));
        assert!(!upstream_allowed("10.1.1.1".parse().unwrap(), false));
        assert!(!upstream_allowed("172.16.0.1".parse().unwrap(), false));
        assert!(!upstream_allowed("169.254.1.1".parse().unwrap(), false));
        assert!(!upstream_allowed("100.64.0.1".parse().unwrap(), false));
        assert!(!upstream_allowed("0.0.0.0".parse().unwrap(), true));
        assert!(!upstream_allowed("224.0.0.1".parse().unwrap(), false));
        assert!(upstream_allowed("1.1.1.1".parse().unwrap(), false));
        assert!(upstream_allowed("149.154.167.51".parse().unwrap(), false));
        assert!(is_local_host("localhost"));
        assert!(is_local_host("127.0.0.1"));
        assert!(!is_local_host("1.1.1.1"));
    }

    #[test]
    fn loopback_peer_is_allowed() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(peer_allowed(peer));
    }
}
