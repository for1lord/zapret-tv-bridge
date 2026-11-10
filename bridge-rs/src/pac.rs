//! Dynamic Proxy Auto-Configuration (PAC) Script Generator.
//! Directs targeted streaming video, communication, and media traffic
//! through the acceleration proxy, while domestic services, developer platforms,
//! operating system services, and local subnets connect DIRECT.

/// Generates an RFC-compliant PAC autoconfig script directing selected domains
/// through the proxy tunnel, and domestic/LAN services to DIRECT.
pub fn generate_pac_script(proxy_host: &str, proxy_port: u16) -> String {
    format!(
r#"function FindProxyForURL(url, host) {{
    var proxy = "PROXY {host}:{port}; DIRECT";
    var hostLower = host.toLowerCase();

    // 1. Streaming Video & Media Platforms
    if (shExpMatch(hostLower, "*googlevideo.com*") ||
        shExpMatch(hostLower, "*youtube.com*") ||
        shExpMatch(hostLower, "*ytimg.com*") ||
        shExpMatch(hostLower, "*ggpht.com*") ||
        shExpMatch(hostLower, "*youtu.be*") ||
        shExpMatch(hostLower, "*gstatic.com*") ||
        shExpMatch(hostLower, "*youtubei.googleapis.com*") ||
        shExpMatch(hostLower, "*fonts.googleapis.com*") ||
        shExpMatch(hostLower, "*jnn-pa.googleapis.com*") ||
        shExpMatch(hostLower, "*twitch.tv*") ||
        shExpMatch(hostLower, "*ttvnw.net*") ||
        shExpMatch(hostLower, "*jtvnw.net*") ||
        shExpMatch(hostLower, "*twitchcdn.net*") ||
        shExpMatch(hostLower, "*ext-twitch.tv*") ||
        shExpMatch(hostLower, "*live-video.net*") ||
        shExpMatch(hostLower, "*pornhub*") ||
        shExpMatch(hostLower, "*phncdn*") ||
        shExpMatch(hostLower, "*phprcdn*") ||
        shExpMatch(hostLower, "*phnstatic*") ||
        shExpMatch(hostLower, "*mainhub*") ||
        shExpMatch(hostLower, "*etahub*") ||
        shExpMatch(hostLower, "*aylo*") ||
        shExpMatch(hostLower, "*nsimg*") ||
        shExpMatch(hostLower, "*geekadm*") ||
        shExpMatch(hostLower, "*rncdn7*") ||
        shExpMatch(hostLower, "*trafficjunky*") ||
        shExpMatch(hostLower, "*xhamster*") ||
        shExpMatch(hostLower, "*xhcdn*") ||
        shExpMatch(hostLower, "*xvideos*") ||
        shExpMatch(hostLower, "*xv-cdn*") ||
        shExpMatch(hostLower, "*youporn*") ||
        shExpMatch(hostLower, "*ypncdn*") ||
        shExpMatch(hostLower, "*redtube*") ||
        shExpMatch(hostLower, "*redtubecdn*") ||
        shExpMatch(hostLower, "*eporner*") ||
        shExpMatch(hostLower, "*tube8*") ||
        shExpMatch(hostLower, "*spankwire*") ||
        shExpMatch(hostLower, "*hwcdn*") ||
        shExpMatch(hostLower, "*futanari*")) {{
        return proxy;
    }}

    // 2. Gaming Services -> Direct (managed via dedicated configuration profiles)
    if (shExpMatch(hostLower, "*supercell*") ||
        shExpMatch(hostLower, "*clashroyale*") ||
        shExpMatch(hostLower, "*brawlstars*") ||
        shExpMatch(hostLower, "*clashofclans*")) {{
        return "DIRECT";
    }}

    // 3. Social Media & Communication Services
    if (shExpMatch(hostLower, "*instagram*") ||
        shExpMatch(hostLower, "*cdninstagram*") ||
        shExpMatch(hostLower, "*fbcdn*") ||
        shExpMatch(hostLower, "*facebook*") ||
        shExpMatch(hostLower, "*threads*") ||
        shExpMatch(hostLower, "*meta.com*") ||
        shExpMatch(hostLower, "*ig.me*") ||
        shExpMatch(hostLower, "*fbsbx*") ||
        shExpMatch(hostLower, "*discord*") ||
        shExpMatch(hostLower, "*discordapp*") ||
        shExpMatch(hostLower, "*storage.googleapis.com*") ||
        shExpMatch(hostLower, "*twitter*") ||
        shExpMatch(hostLower, "*x.com*")) {{
        return proxy;
    }}

    // 4. Developer & Cloud Platforms -> DIRECT
    if (shExpMatch(hostLower, "*cloudcode-pa.googleapis.com*") ||
        shExpMatch(hostLower, "*daily-cloudcode-pa.googleapis.com*") ||
        shExpMatch(hostLower, "*google.com*") ||
        shExpMatch(hostLower, "*gvt1.com*") ||
        shExpMatch(hostLower, "*chatgpt.com*") ||
        shExpMatch(hostLower, "*openai.com*") ||
        shExpMatch(hostLower, "*anthropic.com*") ||
        shExpMatch(hostLower, "*claude.ai*") ||
        shExpMatch(hostLower, "*geohide.ru*") ||
        shExpMatch(hostLower, "*dns-ai.ru*")) {{
        return "DIRECT";
    }}

    // 5. Operating System Core Services -> DIRECT
    if (shExpMatch(hostLower, "*apple.com*") ||
        shExpMatch(hostLower, "*itunes.com*") ||
        shExpMatch(hostLower, "*mzstatic.com*") ||
        shExpMatch(hostLower, "*icloud.com*") ||
        shExpMatch(hostLower, "*aaplimg.com*") ||
        shExpMatch(hostLower, "*akadns.net*") ||
        shExpMatch(hostLower, "*windowsupdate*") ||
        shExpMatch(hostLower, "*microsoft.com*")) {{
        return "DIRECT";
    }}

    // 6. Local & Intranet Subnets -> DIRECT
    if (isPlainHostName(host) ||
        shExpMatch(hostLower, "*.local") ||
        shExpMatch(hostLower, "*.lan") ||
        shExpMatch(hostLower, "10.*") ||
        shExpMatch(hostLower, "172.16.*") ||
        shExpMatch(hostLower, "172.17.*") ||
        shExpMatch(hostLower, "172.18.*") ||
        shExpMatch(hostLower, "172.19.*") ||
        shExpMatch(hostLower, "172.2*") ||
        shExpMatch(hostLower, "172.3*") ||
        shExpMatch(hostLower, "192.168.*") ||
        shExpMatch(hostLower, "127.*")) {{
        return "DIRECT";
    }}

    // 7. Domestic Services & Portals -> DIRECT
    if (shExpMatch(hostLower, "*.ru") &&
        (shExpMatch(hostLower, "*yandex*") ||
         shExpMatch(hostLower, "*vk.com*") ||
         shExpMatch(hostLower, "*gosuslugi*") ||
         shExpMatch(hostLower, "*sber*") ||
         shExpMatch(hostLower, "*ozon*") ||
         shExpMatch(hostLower, "*wildberries*") ||
         shExpMatch(hostLower, "*tinkoff*") ||
         shExpMatch(hostLower, "*mail.ru*"))) {{
        return "DIRECT";
    }}

    // 8. Media Portals & Trackers
    if (shExpMatch(hostLower, "*rutracker*") ||
        shExpMatch(hostLower, "*rutor*") ||
        shExpMatch(hostLower, "*nnmclub*") ||
        shExpMatch(hostLower, "*flibusta*")) {{
        return proxy;
    }}

    // Default: Direct connection for remaining unlisted destinations
    return "DIRECT";
}}
"#,
        host = proxy_host,
        port = proxy_port
    )
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
        assert!(script.contains("*googlevideo.com*"));
        assert!(script.contains("*youtube.com*"));
        assert!(script.contains("*twitch.tv*"));
        assert!(script.contains("*ttvnw.net*"));
        assert!(script.contains("*jtvnw.net*"));
        assert!(script.contains("*twitchcdn.net*"));
        assert!(script.contains("*discord*"));
        assert!(script.contains("return \"DIRECT\";"));
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
