//! Dynamic Proxy Auto-Configuration (PAC) Script Generator.
//! Suffix lists match the router. Unlisted names stay DIRECT.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::router::{self, DIRECT_SUFFIXES, PROXY_SUFFIXES};

struct PacTables {
    stamp: String,
    targets: String,
    excludes: String,
}

static PAC_TABLES: Mutex<Option<PacTables>> = Mutex::new(None);

/// Generates a PAC from the built-in suffix lists. Unlisted hosts stay DIRECT.
pub fn generate_pac_script(proxy_host: &str, proxy_port: u16) -> String {
    let host = usable_proxy_host(proxy_host, "127.0.0.1");
    render_pac(&host, proxy_port, "", "")
}

/// Same policy as [`generate_pac_script`], plus the on-disk anticensority lists.
pub fn generate_served_pac(proxy_host: &str, proxy_port: u16, base_dir: &Path) -> String {
    let host = usable_proxy_host(proxy_host, "127.0.0.1");
    let lists = base_dir.join("lists");
    let stamp = format!(
        "{}|{}",
        list_stamp(&lists.join("list-general.txt")),
        list_stamp(&lists.join("list-general-user.txt"))
    );
    let (targets, excludes) = cached_tables(&lists, &stamp);
    render_pac(&host, proxy_port, &targets, &excludes)
}

fn cached_tables(lists: &Path, stamp: &str) -> (String, String) {
    if let Ok(guard) = PAC_TABLES.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached.stamp == stamp {
                return (cached.targets.clone(), cached.excludes.clone());
            }
        }
    }
    let (targets, excludes) = load_list_tables(lists);
    if let Ok(mut guard) = PAC_TABLES.lock() {
        *guard = Some(PacTables {
            stamp: stamp.to_string(),
            targets: targets.clone(),
            excludes: excludes.clone(),
        });
    }
    (targets, excludes)
}

fn usable_proxy_host(host: &str, default: &str) -> String {
    let host = host.trim();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        if inner.parse::<std::net::Ipv6Addr>().is_ok() {
            return host.to_string();
        }
    }
    if !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return host.to_string();
    }
    default.to_string()
}

fn render_pac(host: &str, port: u16, target_object: &str, exclude_object: &str) -> String {
    let mut script = String::new();
    script.push_str(&js_array("BRIDGE_PROXY_SUFFIXES", PROXY_SUFFIXES));
    script.push_str(&js_array("BRIDGE_DIRECT_SUFFIXES", DIRECT_SUFFIXES));
    script.push_str("var BRIDGE_FILE_TARGETS = {");
    script.push_str(target_object);
    script.push_str("};\nvar BRIDGE_FILE_EXCLUDES = {");
    script.push_str(exclude_object);
    script.push_str("};\n");
    script.push_str(&format!(
        r#"function FindProxyForURL(url, host) {{
    var proxy = "PROXY {host}:{port}; DIRECT";
    var h = String(host).toLowerCase();
    if (bridgePlain(h) || bridgeEnds(h, ".local") || bridgeEnds(h, ".lan") || bridgeEnds(h, ".internal") || h === "localhost") return "DIRECT";
    if (bridgePrivate(h)) return "DIRECT";
    if (bridgeListed(h, BRIDGE_DIRECT_SUFFIXES) || bridgeObj(h, BRIDGE_FILE_EXCLUDES)) return "DIRECT";
    if (bridgeListed(h, BRIDGE_PROXY_SUFFIXES) || bridgeObj(h, BRIDGE_FILE_TARGETS)) return proxy;
    return "DIRECT";
}}
function bridgePlain(h) {{ return h.indexOf(".") < 0 && h.indexOf(":") < 0; }}
function bridgeEnds(h, suf) {{ return h.length >= suf.length && h.substring(h.length - suf.length) === suf; }}
function bridgeListed(h, list) {{
    var i, item, suf;
    for (i = 0; i < list.length; i++) {{
        item = list[i];
        if (h === item) return true;
        suf = "." + item;
        if (h.length > suf.length && h.substring(h.length - suf.length) === suf) return true;
    }}
    return false;
}}
function bridgeObj(h, table) {{
    if (table[h]) return true;
    var i = 0;
    while ((i = h.indexOf(".", i)) >= 0) {{
        i++;
        if (table[h.substring(i)]) return true;
    }}
    return false;
}}
function bridgePrivate(h) {{
    var p = h.split(".");
    if (p.length !== 4) return false;
    var a = parseInt(p[0], 10), b = parseInt(p[1], 10);
    if (isNaN(a) || isNaN(b)) return false;
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
}}
"#
    ));
    script
}

fn js_array(name: &str, items: &[&str]) -> String {
    let mut out = format!("var {name} = [");
    let mut first = true;
    for item in items {
        if !js_token_ok(item) {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(item);
        out.push('"');
    }
    out.push_str("];\n");
    out
}

fn js_token_ok(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn list_stamp(path: &Path) -> String {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|| "0".to_string())
}

fn load_list_tables(lists: &Path) -> (String, String) {
    let mut targets = HashSet::new();
    let mut excludes = HashSet::new();
    read_domain_file(&lists.join("list-google.txt"), &mut targets);
    read_domain_file(&lists.join("list-general-user.txt"), &mut targets);
    read_domain_file(&lists.join("list-exclude.txt"), &mut excludes);
    read_domain_file(&lists.join("list-exclude-user.txt"), &mut excludes);
    targets.retain(|d| !router::host_matches_any(d, DIRECT_SUFFIXES));
    (
        js_object(&minimize_suffixes(targets)),
        js_object(&minimize_suffixes(excludes)),
    )
}

fn read_domain_file(path: &Path, into: &mut HashSet<String>) {
    let Ok(file) = fs::File::open(path) else {
        return;
    };
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            continue;
        };
        let trimmed = line.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        let norm = trimmed
            .strip_prefix("*.")
            .or_else(|| trimmed.strip_prefix('.'))
            .unwrap_or(&trimmed)
            .trim_matches('.');
        if js_token_ok(norm) && norm.contains('.') {
            into.insert(norm.to_string());
        }
    }
}

fn minimize_suffixes(domains: HashSet<String>) -> Vec<String> {
    let mut ordered: Vec<String> = domains.into_iter().collect();
    ordered.sort_by_key(|d| d.len());
    let mut kept = HashSet::new();
    for domain in ordered {
        if suffix_covered(&domain, &kept) {
            continue;
        }
        kept.insert(domain);
    }
    let mut out: Vec<String> = kept.into_iter().collect();
    out.sort();
    out
}

fn suffix_covered(domain: &str, kept: &HashSet<String>) -> bool {
    let mut rest = domain;
    while let Some((_, parent)) = rest.split_once('.') {
        if kept.contains(parent) {
            return true;
        }
        rest = parent;
    }
    false
}

fn js_object(domains: &[String]) -> String {
    let mut out = String::new();
    for (i, domain) in domains.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(domain);
        out.push_str("\":1");
    }
    out
}

/// Helper function to parse host and port from a Host header or fallback cascade.
pub fn resolve_proxy_target(
    host_header: Option<&str>,
    local_socket_addr: Option<std::net::SocketAddr>,
    default_ip: &str,
    default_port: u16,
) -> (String, u16) {
    if let Some(h) = host_header {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            // Bracketed IPv6: [2001:db8::1]:8080 or [2001:db8::1]
            if trimmed.starts_with('[') {
                if let Some(end_bracket) = trimmed.find(']') {
                    let host = &trimmed[..=end_bracket];
                    let rest = &trimmed[end_bracket + 1..];
                    let port = if rest.starts_with(':') {
                        rest[1..].parse::<u16>().unwrap_or(default_port)
                    } else {
                        default_port
                    };
                    return (host.to_string(), port);
                }
            }

            // Normal host:port or just host
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() == 2 {
                let host = parts[0].trim();
                let port = parts[1].trim().parse::<u16>().unwrap_or(default_port);
                if !host.is_empty() && host != "0.0.0.0" {
                    return (host.to_string(), port);
                }
            } else if parts.len() == 1 {
                let host = parts[0].trim();
                if !host.is_empty() && host != "0.0.0.0" {
                    return (host.to_string(), default_port);
                }
            } else if parts.len() > 2 {
                // Malformed (e.g. 127.0.0.1:8080:9090) -> take first part, second as port
                let host = parts[0].trim();
                let port = parts[1].trim().parse::<u16>().unwrap_or(default_port);
                if !host.is_empty() && host != "0.0.0.0" {
                    return (host.to_string(), port);
                }
            }
        }
    }

    // Fallback to local socket address if available and not unspecified
    if let Some(addr) = local_socket_addr {
        let ip = addr.ip();
        if !ip.is_unspecified() {
            let host = if ip.is_ipv6() {
                format!("[{}]", ip)
            } else {
                ip.to_string()
            };
            return (host, addr.port());
        }
    }

    // Default fallback
    (default_ip.to_string(), default_port)
}

/// Discovers primary local LAN interface IP via UDP connect probe.
pub fn get_local_ip() -> String {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                let ip = addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return ip.to_string();
                }
            }
        }
    }
    "127.0.0.1".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_generation_dynamic_injection() {
        let script = generate_pac_script("192.168.1.150", 8080);
        assert!(script.contains("PROXY 192.168.1.150:8080; DIRECT"));
        assert!(script.contains("function FindProxyForURL(url, host)"));
        assert!(script.contains("\"googlevideo.com\""));
        assert!(script.contains("\"youtube.com\""));
        assert!(script.contains("\"twitch.tv\""));
        assert!(script.contains("\"x.com\""));
        assert!(script.contains("return \"DIRECT\";"));
        assert!(!script.contains("*x.com*"));
    }

    #[test]
    fn test_resolve_proxy_target_variations() {
        // Standard host:port
        assert_eq!(
            resolve_proxy_target(Some("192.168.1.100:8080"), None, "127.0.0.1", 8080),
            ("192.168.1.100".to_string(), 8080)
        );

        // Host without port
        assert_eq!(
            resolve_proxy_target(Some("my-tv-bridge.lan"), None, "127.0.0.1", 8080),
            ("my-tv-bridge.lan".to_string(), 8080)
        );

        // Whitespace padding
        assert_eq!(
            resolve_proxy_target(Some("   10.0.0.5:9090   "), None, "127.0.0.1", 8080),
            ("10.0.0.5".to_string(), 9090)
        );

        // Bracketed IPv6 with port
        assert_eq!(
            resolve_proxy_target(Some("[2001:db8::1]:8080"), None, "127.0.0.1", 8080),
            ("[2001:db8::1]".to_string(), 8080)
        );

        // Bracketed IPv6 without port
        assert_eq!(
            resolve_proxy_target(Some("[2001:db8::1]"), None, "127.0.0.1", 8080),
            ("[2001:db8::1]".to_string(), 8080)
        );

        // Malformed with extra colons
        assert_eq!(
            resolve_proxy_target(Some("127.0.0.1:8080:9090"), None, "127.0.0.1", 8080),
            ("127.0.0.1".to_string(), 8080)
        );

        // Missing host header -> fallback to default
        assert_eq!(
            resolve_proxy_target(None, None, "192.168.1.1", 8080),
            ("192.168.1.1".to_string(), 8080)
        );

        // 0.0.0.0 -> fallback to default
        assert_eq!(
            resolve_proxy_target(Some("0.0.0.0:8080"), None, "192.168.1.1", 8080),
            ("192.168.1.1".to_string(), 8080)
        );
    }

    #[test]
    fn test_get_local_ip_returns_valid_string() {
        let ip = get_local_ip();
        assert!(!ip.is_empty());
        assert!(ip.parse::<std::net::IpAddr>().is_ok());
    }
}
