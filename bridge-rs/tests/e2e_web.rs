//! Comprehensive 4-Tier Automated Test Suite for Milestone 3
//! Node 3: Embedded Web Server & PAC Engine (Features F15–F19)

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::{http_connect_tunnel, socks5_connect_ipv4, socks5_handshake, MockEchoServer, MockHttpServer};
use zapret_tv_bridge_rs::metrics::ProxyMetrics;
use zapret_tv_bridge_rs::proxy;
use zapret_tv_bridge_rs::router::SmartRouter;
use zapret_tv_bridge_rs::web::{create_web_router, HealthResponse, StatsResponse, WebConfig};

/// Test harness running an in-process protocol autodetect proxy with Axum web server
/// bound to an ephemeral loopback port.
pub struct WebTestServer {
    pub addr: SocketAddr,
    pub metrics: Arc<ProxyMetrics>,
    pub router: Arc<SmartRouter>,
    pub config: WebConfig,
}

impl WebTestServer {
    pub async fn start() -> Self {
        Self::start_with_base_dir(PathBuf::from("d:\\projects\\zapret-tv-bridge")).await
    }

    pub async fn start_with_base_dir(base_dir: PathBuf) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral test port");
        let addr = listener.local_addr().expect("Failed to get local addr");
        drop(listener);
        tokio::task::yield_now().await;

        let router = Arc::new(SmartRouter::new(&base_dir));
        let metrics = Arc::new(ProxyMetrics::new());
        let config = WebConfig::new(
            addr.port(),
            "127.0.0.1".to_string(),
            base_dir,
            1443,
            "00000000000000000000000000000000".to_string(),
            std::time::Instant::now(),
        );

        let web_router = create_web_router(Arc::clone(&metrics), config.clone());

        let r = Arc::clone(&router);
        let m = Arc::clone(&metrics);
        let wr = web_router.clone();
        tokio::spawn(async move {
            let _ = proxy::run_proxy_listener_with_web(addr, r, m, wr).await;
        });

        // Await server readiness
        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        Self {
            addr,
            metrics,
            router,
            config,
        }
    }

    /// Executes raw HTTP request and returns (status_code, headers_map, body_bytes).
    pub async fn request(
        &self,
        raw_request: &str,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| format!("Connect failed: {e}"))?;

        stream
            .write_all(raw_request.as_bytes())
            .await
            .map_err(|e| format!("Write failed: {e}"))?;

        let mut buf = Vec::new();
        let mut temp = [0u8; 4096];
        loop {
            match stream.read(&mut temp).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&temp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header_part = String::from_utf8_lossy(&buf[..pos]);
                        let mut cl = None;
                        for line in header_part.lines() {
                            if line.to_ascii_lowercase().starts_with("content-length:") {
                                if let Some(val) = line.split(':').nth(1) {
                                    cl = val.trim().parse::<usize>().ok();
                                }
                            }
                        }
                        if let Some(len) = cl {
                            if buf.len() >= pos + 4 + len {
                                break;
                            }
                        }
                    }
                }
                Err(e) => return Err(format!("Read failed: {e}")),
            }
        }

        parse_http_response(&buf)
    }
}

fn parse_http_response(buf: &[u8]) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let split_pos = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Incomplete HTTP response headers".to_string())?;

    let header_str = String::from_utf8_lossy(&buf[..split_pos]);
    let body = buf[split_pos + 4..].to_vec();

    let mut lines = header_str.lines();
    let status_line = lines.next().ok_or("Empty response")?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("Malformed status line: {status_line}"));
    }
    let status_code = parts[1]
        .parse::<u16>()
        .map_err(|e| format!("Invalid status code: {e}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Ok((status_code, headers, body))
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// =========================================================================
// TIER 1: FEATURE ISOLATION TESTS (F15–F19)
// =========================================================================

/// T1.1: Root path returns responsive dark-theme HTML status dashboard.
#[tokio::test]
async fn test_tier1_web_root_dashboard_html() {
    let server = WebTestServer::start().await;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        server.addr.port()
    );
    let (status, headers, body) = server.request(&req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("text/html"));

    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("<title>Zapret TV & Mobile Bridge</title>"));
    assert!(html.contains("РАБОТАЕТ"));
    assert!(html.contains("/proxy.pac"));
}

/// T1.2: Favicon endpoint returns HTTP 204 No Content with 0 body bytes.
#[tokio::test]
async fn test_tier1_web_favicon_204_no_content() {
    let server = WebTestServer::start().await;
    let req = "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 204);
    assert_eq!(body.len(), 0);
}

/// T1.3: Unregistered subpath returns clean HTTP 404 Not Found.
#[tokio::test]
async fn test_tier1_web_unknown_path_returns_404() {
    let server = WebTestServer::start().await;
    let req = "GET /unregistered_subpath_test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 404);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("404 Not Found"));
}

/// T1.4: Query string in local route request is stripped cleanly.
#[tokio::test]
async fn test_tier1_web_query_string_stripping() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac?version=1.0&client=smarttv HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("application/x-ns-proxy-autoconfig"));
    assert!(String::from_utf8_lossy(&body).contains("FindProxyForURL"));
}

/// T1.5: Trailing slash in endpoint URI is handled cleanly.
#[tokio::test]
async fn test_tier1_web_trailing_slash_normalization() {
    let server = WebTestServer::start().await;
    let req = "GET /health/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("application/json"));
    let json: HealthResponse = serde_json::from_slice(&body).expect("Valid HealthResponse JSON");
    assert_eq!(json.status, "ok");
}

/// T1.6: PAC script response headers and MIME type compliance.
#[tokio::test]
async fn test_tier1_pac_mime_type_and_headers() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, _body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("application/x-ns-proxy-autoconfig"));

    let cc = find_header(&headers, "cache-control").expect("Missing Cache-Control");
    assert!(cc.contains("no-cache"));
    assert!(cc.contains("no-store"));

    let pragma = find_header(&headers, "pragma").expect("Missing Pragma");
    assert_eq!(pragma, "no-cache");

    let expires = find_header(&headers, "expires").expect("Missing Expires");
    assert_eq!(expires, "0");
}

/// T1.7: PAC script syntax and JavaScript structural validation.
#[tokio::test]
async fn test_tier1_pac_javascript_syntax_structure() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("function FindProxyForURL(url, host)"));
    assert!(script.contains("var hostLower = host.toLowerCase();"));
    assert!(script.contains("return \"DIRECT\";"));

    // Verify balanced curly braces
    let open_braces = script.chars().filter(|c| *c == '{').count();
    let close_braces = script.chars().filter(|c| *c == '}').count();
    assert_eq!(open_braces, close_braces);
}

/// T1.8: Dynamic host and port injection into PAC script from Host header.
#[tokio::test]
async fn test_tier1_pac_dynamic_host_injection() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: 192.168.1.150:8080\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("var proxy = \"PROXY 192.168.1.150:8080; DIRECT\";"));
}

/// T1.9: PAC script media and streaming platform domain rules.
#[tokio::test]
async fn test_tier1_pac_streaming_domains_routing() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("*googlevideo.com*"));
    assert!(script.contains("*youtube.com*"));
    assert!(script.contains("*ytimg.com*"));
    assert!(script.contains("*ggpht.com*"));
    assert!(script.contains("*youtu.be*"));
    assert!(script.contains("*twitch.tv*"));
    assert!(script.contains("*discord*"));
}

/// T1.10: PAC script domestic, intranet, and operating system direct routing rules.
#[tokio::test]
async fn test_tier1_pac_domestic_and_lan_direct() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("isPlainHostName(host)"));
    assert!(script.contains("192.168.*"));
    assert!(script.contains("10.*"));
    assert!(script.contains("172.16.*"));
    assert!(script.contains("*yandex*"));
    assert!(script.contains("*vk.com*"));
    assert!(script.contains("*gosuslugi*"));
    assert!(script.contains("*sber*"));
    assert!(script.contains("*apple.com*"));
    assert!(script.contains("*microsoft.com*"));
}

/// T1.11: Health endpoint returns HTTP 200 OK with application/json MIME type.
#[tokio::test]
async fn test_tier1_health_status_200_and_mime() {
    let server = WebTestServer::start().await;
    let req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, _body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("application/json"));
}

/// T1.12: Health endpoint JSON schema validation.
#[tokio::test]
async fn test_tier1_health_json_schema_validation() {
    let server = WebTestServer::start().await;
    let req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let json: HealthResponse = serde_json::from_slice(&body).expect("Valid JSON");
    assert_eq!(json.status, "ok");
    assert_eq!(json.service, "ZapretTVBridge");
    assert_eq!(json.version, env!("CARGO_PKG_VERSION"));
    assert!(json.uptime_seconds < 86400);
}

/// T1.13: Health endpoint telemetry metrics fields present.
#[tokio::test]
async fn test_tier1_health_metrics_fields_present() {
    let server = WebTestServer::start().await;
    let req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("Valid JSON Value");
    assert!(json["metrics"]["active_connections"].is_number());
    assert!(json["metrics"]["total_connections"].is_number());
    assert!(json["metrics"]["bytes_client_to_remote"].is_number());
    assert!(json["metrics"]["bytes_remote_to_client"].is_number());
    assert!(json["metrics"]["errors_count"].is_number());
}

/// T1.14: Health endpoint initial metric counters are zero.
#[tokio::test]
async fn test_tier1_health_initial_metric_zeroes() {
    let server = WebTestServer::start().await;
    let req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let json: HealthResponse = serde_json::from_slice(&body).expect("Valid HealthResponse");
    assert_eq!(json.metrics.bytes_client_to_remote, 0);
    assert_eq!(json.metrics.bytes_remote_to_client, 0);
    assert_eq!(json.metrics.errors_count, 0);
}

/// T1.15: Health endpoint uptime monotonically increases across sequential calls.
#[tokio::test]
async fn test_tier1_health_uptime_monotonic_increase() {
    let server = WebTestServer::start().await;
    let req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    let (_, _, body1) = server.request(req).await.expect("Call 1 failed");
    let json1: HealthResponse = serde_json::from_slice(&body1).expect("JSON 1");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let (_, _, body2) = server.request(req).await.expect("Call 2 failed");
    let json2: HealthResponse = serde_json::from_slice(&body2).expect("JSON 2");

    assert!(json2.uptime_seconds >= json1.uptime_seconds);
}

/// T1.16: Supercell MobileConfig endpoint headers and attachment disposition.
#[tokio::test]
async fn test_tier1_mobileconfig_supercell_endpoint() {
    let server = WebTestServer::start().await;
    let req = "GET /supercell.mobileconfig HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, _body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("application/x-apple-aspen-config"));

    let cd = find_header(&headers, "content-disposition").expect("Missing Content-Disposition");
    assert!(cd.contains("attachment"));
    assert!(cd.contains("Supercell_Gaming_COMSS.mobileconfig"));
}

/// T1.17: Supercell MobileConfig XML plist structural validation.
#[tokio::test]
async fn test_tier1_mobileconfig_supercell_xml_plist() {
    let server = WebTestServer::start().await;
    let req = "GET /supercell.mobileconfig HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("<plist version=\"1.0\">"));
    assert!(xml.contains("com.supercell.gaming.dns.profile"));
    assert!(xml.contains("https://dns.comss.one/dns-query"));
}

/// T1.18: Null's Proxy MobileConfig endpoint headers and attachment disposition.
#[tokio::test]
async fn test_tier1_mobileconfig_nullsproxy_endpoint() {
    let server = WebTestServer::start().await;
    let req = "GET /nullsproxy.mobileconfig HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, _body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("application/x-apple-aspen-config"));

    let cd = find_header(&headers, "content-disposition").expect("Missing Content-Disposition");
    assert!(cd.contains("attachment"));
    assert!(cd.contains("NullsProxy_Gaming.mobileconfig"));
}

/// T1.19: Null's Proxy MobileConfig XML plist structural validation.
#[tokio::test]
async fn test_tier1_mobileconfig_nullsproxy_xml_plist() {
    let server = WebTestServer::start().await;
    let req = "GET /nullsproxy.mobileconfig HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("<plist version=\"1.0\">"));
    assert!(xml.contains("dns.nullsproxy.com"));
    assert!(xml.contains("<string>TLS</string>"));
}

/// T1.20: MobileConfig disk override with fallback to embedded template.
#[tokio::test]
async fn test_tier1_mobileconfig_disk_override() {
    let temp_dir = std::env::temp_dir().join(format!("m3_override_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let custom_profile = "<?xml version=\"1.0\"?><plist><dict><key>Custom</key><string>Active</string></dict></plist>";
    std::fs::write(temp_dir.join("supercell.mobileconfig"), custom_profile).unwrap();

    let server = WebTestServer::start_with_base_dir(temp_dir.clone()).await;
    let req = "GET /supercell.mobileconfig HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), custom_profile);

    // Remove file and verify fallback to default embedded
    let _ = std::fs::remove_file(temp_dir.join("supercell.mobileconfig"));
    let (status2, _headers2, body2) = server.request(req).await.expect("Request 2 failed");
    assert_eq!(status2, 200);
    assert!(String::from_utf8_lossy(&body2).contains("dns.comss.one"));

    let _ = std::fs::remove_dir_all(temp_dir);
}

/// T1.21: Dashboard HTML includes copyable PAC and proxy connection widgets.
#[tokio::test]
async fn test_tier1_dashboard_copyable_widgets() {
    let server = WebTestServer::start().await;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: 192.168.0.50:{}\r\nConnection: close\r\n\r\n",
        server.addr.port()
    );
    let (status, _headers, body) = server.request(&req).await.expect("Request failed");

    assert_eq!(status, 200);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(&format!("http://192.168.0.50:{}/proxy.pac", server.addr.port())));
    assert!(html.contains("192.168.0.50"));
    assert!(html.contains("Копировать"));
}

/// T1.22: Dashboard HTML contains mobileconfig profile download buttons.
#[tokio::test]
async fn test_tier1_dashboard_mobileconfig_links() {
    let server = WebTestServer::start().await;
    let req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("href=\"/supercell.mobileconfig\""));
    assert!(html.contains("href=\"/nullsproxy.mobileconfig\""));
}

/// T1.23: Dashboard HTML contains service active indicator badge.
#[tokio::test]
async fn test_tier1_dashboard_service_status_badge() {
    let server = WebTestServer::start().await;
    let req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("РАБОТАЕТ"));
    assert!(html.contains("badge"));
}

/// T1.24: Telemetry endpoint /api/stats returns valid JSON snapshot.
#[tokio::test]
async fn test_tier1_api_stats_json_endpoint() {
    let server = WebTestServer::start().await;
    let req = "GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
    assert!(ct.contains("application/json"));

    let stats: StatsResponse = serde_json::from_slice(&body).expect("Valid StatsResponse");
    assert_eq!(stats.errors_count, 0);
    assert_eq!(stats.bytes_client_to_remote, 0);
}

/// T1.25: Telemetry stats numeric consistency with ProxyMetrics snapshot.
#[tokio::test]
async fn test_tier1_api_stats_numeric_consistency() {
    let server = WebTestServer::start().await;
    server.metrics.add_bytes_up(12345);
    server.metrics.add_bytes_down(67890);
    server.metrics.inc_errors();

    let req = "GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let stats: StatsResponse = serde_json::from_slice(&body).expect("Valid StatsResponse");
    assert_eq!(stats.bytes_client_to_remote, 12345);
    assert_eq!(stats.bytes_remote_to_client, 67890);
    assert_eq!(stats.errors_count, 1);
}

// =========================================================================
// TIER 2: BOUNDARY & CORNER CASES (F15–F19)
// =========================================================================

/// T2.1: Missing Host header falls back to default bind IP and port.
#[tokio::test]
async fn test_tier2_pac_missing_host_header() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.0\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains(&format!("PROXY 127.0.0.1:{}; DIRECT", server.addr.port())));
}

/// T2.2: Malformed Host header with extra colons is safely handled.
#[tokio::test]
async fn test_tier2_pac_malformed_host_extra_colons() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1:8080:9090\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("PROXY 127.0.0.1:8080; DIRECT"));
}

/// T2.3: Bracketed IPv6 address in Host header is preserved.
#[tokio::test]
async fn test_tier2_pac_ipv6_bracketed_host() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("PROXY [2001:db8::1]:8080; DIRECT"));
}

/// T2.4: Whitespace padded Host header is trimmed cleanly.
#[tokio::test]
async fn test_tier2_pac_whitespace_padded_host() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost:    10.0.0.5:8080   \r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("PROXY 10.0.0.5:8080; DIRECT"));
}

/// T2.5: FQDN hostname with custom port in Host header.
#[tokio::test]
async fn test_tier2_pac_fqdn_custom_port() {
    let server = WebTestServer::start().await;
    let req = "GET /proxy.pac HTTP/1.1\r\nHost: my-tv-bridge.lan:9090\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let script = String::from_utf8_lossy(&body);
    assert!(script.contains("PROXY my-tv-bridge.lan:9090; DIRECT"));
}

/// T2.6: Case-insensitive PAC path aliases (/PROXY.PAC, /Proxy.Pac).
#[tokio::test]
async fn test_tier2_pac_case_insensitive_aliases() {
    let server = WebTestServer::start().await;
    for alias in &["/PROXY.PAC", "/Proxy.Pac"] {
        let req = format!("GET {alias} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        let (status, _headers, body) = server.request(&req).await.expect("Request failed");
        assert_eq!(status, 200, "Failed for {alias}");
        assert!(String::from_utf8_lossy(&body).contains("FindProxyForURL"));
    }
}

/// T2.7: Legacy PAC path aliases (/anticensority.pac, /pac, /wpad.dat).
#[tokio::test]
async fn test_tier2_pac_legacy_path_aliases() {
    let server = WebTestServer::start().await;
    let aliases = ["/anticensority.pac", "/pac", "/wpad.dat"];
    for alias in aliases {
        let req = format!("GET {alias} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        let (status, _headers, body) = server.request(&req).await.expect("Request failed");
        assert_eq!(status, 200, "Failed for alias: {alias}");
        assert!(String::from_utf8_lossy(&body).contains("FindProxyForURL"));
    }
}

/// T2.8: MobileConfig path aliases (/brawlstars.mobileconfig, /clashroyale.mobileconfig, /comss.mobileconfig).
#[tokio::test]
async fn test_tier2_mobileconfig_path_aliases() {
    let server = WebTestServer::start().await;
    let aliases = ["/brawlstars.mobileconfig", "/clashroyale.mobileconfig", "/comss.mobileconfig"];
    for alias in aliases {
        let req = format!("GET {alias} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        let (status, headers, body) = server.request(&req).await.expect("Request failed");
        assert_eq!(status, 200, "Failed for alias: {alias}");
        let ct = find_header(&headers, "content-type").expect("Missing Content-Type");
        assert!(ct.contains("application/x-apple-aspen-config"));
        assert!(String::from_utf8_lossy(&body).contains("dns.comss.one"));
    }
}

/// T2.9: Path traversal attempts return HTTP 404 and never leak files.
#[tokio::test]
async fn test_tier2_path_traversal_sanitization() {
    let server = WebTestServer::start().await;
    let traversal_paths = ["/../../supercell.mobileconfig", "/../Cargo.toml", "/..%2f..%2fCargo.toml"];
    for path in traversal_paths {
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        let (status, _headers, _body) = server.request(&req).await.expect("Request failed");
        assert_eq!(status, 404, "Expected 404 for traversal path: {path}");
    }
}

/// T2.10: Deep nested unknown route returns clean 404.
#[tokio::test]
async fn test_tier2_deep_nested_unknown_route() {
    let server = WebTestServer::start().await;
    let req = "GET /api/v1/nested/unknown/deep/path HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 404);
    assert!(String::from_utf8_lossy(&body).contains("404 Not Found"));
}

/// T2.11: HTTP/1.0 request without Host header is processed and closed cleanly.
#[tokio::test]
async fn test_tier2_http10_request_handling() {
    let server = WebTestServer::start().await;
    let req = "GET /health HTTP/1.0\r\n\r\n";
    let (status, _headers, body) = server.request(req).await.expect("Request failed");

    assert_eq!(status, 200);
    let json: HealthResponse = serde_json::from_slice(&body).expect("Valid JSON");
    assert_eq!(json.status, "ok");
}

/// T2.12: HTTP HEAD requests return identical status and zero body bytes.
#[tokio::test]
async fn test_tier2_head_method_request() {
    let server = WebTestServer::start().await;
    for endpoint in &["/proxy.pac", "/health", "/favicon.ico", "/"] {
        let req = format!("HEAD {endpoint} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        let (status, _headers, body) = server.request(&req).await.expect("HEAD request failed");
        if *endpoint == "/favicon.ico" {
            assert_eq!(status, 204);
        } else {
            assert_eq!(status, 200, "HEAD failed for {endpoint}");
        }
        assert_eq!(body.len(), 0, "HEAD response must have 0 body bytes for {endpoint}");
    }
}

/// T2.13: Unsupported HTTP methods (POST, PUT, DELETE) on GET endpoints.
#[tokio::test]
async fn test_tier2_unsupported_http_methods() {
    let server = WebTestServer::start().await;
    for method in &["POST", "PUT", "DELETE"] {
        let req = format!("{method} /health HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let (status, _headers, _body) = server.request(&req).await.expect("Request failed");
        assert!(
            status == 405 || status == 404,
            "Expected 405 or 404 for {method}, got {status}"
        );
    }
}

/// T2.14: Requests with large valid headers up to 60 KB are processed normally.
#[tokio::test]
async fn test_tier2_headers_near_64kb_limit() {
    let server = WebTestServer::start().await;
    let mut padding = String::new();
    for i in 0..150 {
        padding.push_str(&format!("X-Custom-Header-{}: {}\r\n", i, "a".repeat(350)));
    }
    let req = format!(
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Connection: close\r\n\r\n",
        padding
    );
    let (status, _headers, body) = server.request(&req).await.expect("Request failed");
    assert_eq!(status, 200);
    let json: HealthResponse = serde_json::from_slice(&body).expect("Valid JSON");
    assert_eq!(json.status, "ok");
}

/// T2.15: Requests exceeding 64 KB header limit return HTTP 431 cleanly.
#[tokio::test]
async fn test_tier2_headers_exceeding_64kb_limit() {
    let server = WebTestServer::start().await;
    let mut oversized = String::new();
    for i in 0..190 {
        oversized.push_str(&format!("X-Oversized-Header-{}: {}\r\n", i, "x".repeat(350)));
    }
    let req = format!(
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Connection: close\r\n\r\n",
        oversized
    );
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let _ = stream.write_all(req.as_bytes()).await;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    let (status, _headers, _body) = parse_http_response(&buf).expect("Expected valid HTTP response");
    assert_eq!(status, 431, "Expected HTTP 431 for headers > 64 KB");
}

/// T2.16: Abrupt disconnect after sending GET does not panic or leak connection guard.
#[tokio::test]
async fn test_tier2_abrupt_disconnect_after_get() {
    let server = WebTestServer::start().await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    stream.write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n").await.unwrap();
    // Drop immediately
    drop(stream);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(server.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// T2.17: Absolute URI addressed to self is handled as local route.
#[tokio::test]
async fn test_tier2_absolute_uri_addressed_to_self() {
    let server = WebTestServer::start().await;
    let req = format!(
        "GET http://127.0.0.1:{}/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        server.addr.port(),
        server.addr.port()
    );
    let (status, _headers, body) = server.request(&req).await.expect("Request failed");

    assert_eq!(status, 200);
    let json: HealthResponse = serde_json::from_slice(&body).expect("Valid JSON");
    assert_eq!(json.status, "ok");
}

// =========================================================================
// TIER 3: CROSS-FEATURE COMBINATIONS & CONCURRENCY
// =========================================================================

/// T3.1: Heavy HTTP CONNECT load with concurrent web requests.
#[tokio::test]
async fn test_tier3_concurrent_connect_and_web_load() {
    let server = WebTestServer::start().await;
    let echo = MockEchoServer::start().await;

    // 10 concurrent HTTP CONNECT tunnels streaming 100 KB each
    let mut connect_tasks = Vec::new();
    for _ in 0..10 {
        let proxy_addr = server.addr;
        let echo_port = echo.port();
        connect_tasks.push(tokio::spawn(async move {
            let (mut tunnel, status, _) = http_connect_tunnel(proxy_addr, "127.0.0.1", echo_port)
                .await
                .expect("CONNECT tunnel failed");
            assert_eq!(status, 200);

            let data = vec![0x33u8; 100 * 1024];
            tunnel.write_all(&data).await.expect("Write to tunnel failed");
            let mut echo_buf = vec![0u8; data.len()];
            tunnel.read_exact(&mut echo_buf).await.expect("Read from tunnel failed");
            assert_eq!(echo_buf, data);
        }));
    }

    // 30 parallel GET /proxy.pac and /health requests
    let mut web_tasks = Vec::new();
    for i in 0..30 {
        let s_addr = server.addr;
        web_tasks.push(tokio::spawn(async move {
            let req_str = if i % 2 == 0 {
                "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            } else {
                "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            };
            let mut stream = TcpStream::connect(s_addr).await.unwrap();
            stream.write_all(req_str.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            let (status, _, _) = parse_http_response(&buf).unwrap();
            assert_eq!(status, 200);
        }));
    }

    for t in connect_tasks {
        t.await.unwrap();
    }
    for t in web_tasks {
        t.await.unwrap();
    }
}

/// T3.2: Dedicated SOCKS5 load with concurrent web telemetry.
#[tokio::test]
async fn test_tier3_socks5_load_with_concurrent_telemetry() {
    let server = WebTestServer::start().await;
    let echo = MockEchoServer::start().await;

    // Simulate SOCKS5 handshake & connect on the proxy port (autodetect)
    let mut socks5_tasks = Vec::new();
    for _ in 0..5 {
        let proxy_addr = server.addr;
        let echo_port = echo.port();
        socks5_tasks.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
            let auth = socks5_handshake(&mut stream, &[0x00]).await.unwrap();
            assert_eq!(auth, 0x00);
            let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_port)
                .await
                .unwrap();
            assert_eq!(rep, 0x00);

            let payload = vec![0x77u8; 32768];
            stream.write_all(&payload).await.unwrap();
            let mut buf = vec![0u8; 32768];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload);
        }));
    }

    // Simultaneously poll /api/stats
    let mut stats_tasks = Vec::new();
    for _ in 0..20 {
        let proxy_addr = server.addr;
        stats_tasks.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
            stream
                .write_all(b"GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            let (status, _, body) = parse_http_response(&buf).unwrap();
            assert_eq!(status, 200);
            let stats: StatsResponse = serde_json::from_slice(&body).unwrap();
            assert!(stats.total_connections > 0);
        }));
    }

    for t in socks5_tasks {
        t.await.unwrap();
    }
    for t in stats_tasks {
        t.await.unwrap();
    }
}

/// T3.3: Port 8080 autodetection multiplexing stress.
#[tokio::test]
async fn test_tier3_autodetect_multiplexing_stress() {
    let server = WebTestServer::start().await;
    let echo = MockEchoServer::start().await;

    let mut tasks = Vec::new();
    for i in 0..60 {
        let s_addr = server.addr;
        let echo_port = echo.port();
        tasks.push(tokio::spawn(async move {
            match i % 3 {
                0 => {
                    // SOCKS5 (first byte 0x05)
                    let mut stream = TcpStream::connect(s_addr).await.unwrap();
                    let auth = socks5_handshake(&mut stream, &[0x00]).await.unwrap();
                    assert_eq!(auth, 0x00);
                    let rep = socks5_connect_ipv4(&mut stream, [127, 0, 0, 1], echo_port).await.unwrap();
                    assert_eq!(rep, 0x00);
                }
                1 => {
                    // HTTP CONNECT (first byte 'C')
                    let (mut tunnel, status, _) = http_connect_tunnel(s_addr, "127.0.0.1", echo_port)
                        .await
                        .unwrap();
                    assert_eq!(status, 200);
                    tunnel.write_all(b"ping").await.unwrap();
                    let mut buf = [0u8; 4];
                    tunnel.read_exact(&mut buf).await.unwrap();
                    assert_eq!(&buf, b"ping");
                }
                _ => {
                    // Web GET (first byte 'G')
                    let mut stream = TcpStream::connect(s_addr).await.unwrap();
                    stream.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").await.unwrap();
                    let mut buf = Vec::new();
                    stream.read_to_end(&mut buf).await.unwrap();
                    let (status, _, _) = parse_http_response(&buf).unwrap();
                    assert_eq!(status, 200);
                }
            }
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }
}

/// T3.4: Dynamic /health counter integrity verification under streaming.
#[tokio::test]
async fn test_tier3_health_metrics_increment() {
    let server = WebTestServer::start().await;
    let echo = MockEchoServer::start().await;

    // 1. Initial health snapshot
    let (_, _, body1) = server
        .request("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let json1: HealthResponse = serde_json::from_slice(&body1).unwrap();
    let initial_up = json1.metrics.bytes_client_to_remote;
    let initial_down = json1.metrics.bytes_remote_to_client;

    // 2. Transfer 65536 bytes via HTTP CONNECT
    let (mut tunnel, status, _) = http_connect_tunnel(server.addr, "127.0.0.1", echo.port())
        .await
        .unwrap();
    assert_eq!(status, 200);

    let test_data = vec![0xFEu8; 65536];
    tunnel.write_all(&test_data).await.unwrap();
    let mut echo_buf = vec![0u8; 65536];
    tunnel.read_exact(&mut echo_buf).await.unwrap();
    drop(tunnel);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Post-transfer health snapshot
    let (_, _, body2) = server
        .request("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let json2: HealthResponse = serde_json::from_slice(&body2).unwrap();

    assert_eq!(json2.metrics.bytes_client_to_remote, initial_up + 65536);
    assert_eq!(json2.metrics.bytes_remote_to_client, initial_down + 65536);
    assert_eq!(json2.metrics.errors_count, 0);
}

/// T3.5: Error metric accounting in /health on protocol violations.
#[tokio::test]
async fn test_tier3_error_metric_accounting() {
    let server = WebTestServer::start().await;

    // 1. Protocol error: unsupported leading byte 0xFF
    {
        let mut s = TcpStream::connect(server.addr).await.unwrap();
        s.write_all(&[0xFF, 0x01, 0x02]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // 2. HTTP CONNECT missing port
    {
        let mut s = TcpStream::connect(server.addr).await.unwrap();
        s.write_all(b"CONNECT invalid_host HTTP/1.1\r\nHost: invalid\r\n\r\n").await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let (_, _, body) = server
        .request("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let json: HealthResponse = serde_json::from_slice(&body).unwrap();
    assert!(json.metrics.errors_count >= 2);
}

/// T3.6: RAII ConnectionGuard leak test under connection bursts.
#[tokio::test]
async fn test_tier3_raii_guard_leak_test() {
    let server = WebTestServer::start().await;
    let echo = MockEchoServer::start().await;

    // Open 10 active persistent tunnels
    let mut tunnels = Vec::new();
    for _ in 0..10 {
        let (tunnel, status, _) = http_connect_tunnel(server.addr, "127.0.0.1", echo.port())
            .await
            .unwrap();
        assert_eq!(status, 200);
        tunnels.push(tunnel);
    }

    // Verify active connections reflect the open tunnels
    let active = server.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed);
    assert!(active >= 10);

    // Drop all tunnels
    drop(tunnels);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let final_active = server.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(final_active, 0, "All connection guards must return to zero upon drop");
}

// =========================================================================
// TIER 4: REAL-WORLD WORKLOAD SCENARIOS
// =========================================================================

/// Tier 4 Scenario 1: Smart TV PAC Auto-configuration & 4K Streaming Workflow.
#[tokio::test]
async fn test_tier4_smart_tv_pac_autoconfig_and_streaming() {
    let server = WebTestServer::start().await;
    let mock_upstream = MockHttpServer::start_with_body(vec![0xAAu8; 1024 * 1024]).await;

    // 1. Smart TV connects to LAN and retrieves PAC autoconfig
    let req = format!(
        "GET /proxy.pac HTTP/1.1\r\nHost: 192.168.1.100:{}\r\nConnection: close\r\n\r\n",
        server.addr.port()
    );
    let (status, headers, body) = server.request(&req).await.unwrap();
    assert_eq!(status, 200);
    assert!(find_header(&headers, "content-type").unwrap().contains("application/x-ns-proxy-autoconfig"));

    let pac_script = String::from_utf8_lossy(&body);
    let expected_proxy_rule = format!("PROXY 192.168.1.100:{}; DIRECT", server.addr.port());
    assert!(pac_script.contains(&expected_proxy_rule));

    // 2. Smart TV evaluates target media domain: googlevideo.com
    assert!(pac_script.contains("*googlevideo.com*"));

    // 3. Smart TV establishes CONNECT tunnel to proxy
    let (mut tunnel, c_status, _) = http_connect_tunnel(server.addr, "127.0.0.1", mock_upstream.port())
        .await
        .unwrap();
    assert_eq!(c_status, 200);

    // 4. Stream 1 MB 4K chunk through tunnel
    let get_req = format!("GET /video.mp4 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", mock_upstream.port());
    tunnel.write_all(get_req.as_bytes()).await.unwrap();

    let mut response_buf = Vec::new();
    tunnel.read_to_end(&mut response_buf).await.unwrap();
    assert!(response_buf.len() > 1024 * 1024);
    drop(tunnel);

    // 5. Verify domestic banking service resolves to DIRECT in PAC script
    assert!(pac_script.contains("*sber*"));

    // 6. Verify telemetry in /health reflects the 1MB transfer
    let (_, _, h_body) = server
        .request("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let health: HealthResponse = serde_json::from_slice(&h_body).unwrap();
    assert!(health.metrics.bytes_remote_to_client >= 1024 * 1024);
}

/// Tier 4 Scenario 2: iOS MobileConfig Setup & Gaming Configuration Workflow.
#[tokio::test]
async fn test_tier4_ios_mobileconfig_setup_workflow() {
    let server = WebTestServer::start().await;

    // 1. iOS Safari opens root dashboard
    let (status, _, body) = server
        .request("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(status, 200);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("href=\"/supercell.mobileconfig\""));

    // 2. Client downloads Supercell gaming profile
    let (s_status, s_headers, s_body) = server
        .request("GET /supercell.mobileconfig HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(s_status, 200);
    assert_eq!(
        find_header(&s_headers, "content-type").unwrap(),
        "application/x-apple-aspen-config; charset=utf-8"
    );
    let s_xml = String::from_utf8_lossy(&s_body);
    assert!(s_xml.contains("com.supercell.gaming.dns.profile"));
    assert!(s_xml.contains("https://dns.comss.one/dns-query"));

    // 3. Client downloads Null's Proxy gaming profile
    let (n_status, n_headers, n_body) = server
        .request("GET /nullsproxy.mobileconfig HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(n_status, 200);
    assert_eq!(
        find_header(&n_headers, "content-type").unwrap(),
        "application/x-apple-aspen-config; charset=utf-8"
    );
    let n_xml = String::from_utf8_lossy(&n_body);
    assert!(n_xml.contains("dns.nullsproxy.com"));

    // 4. Check health endpoint reports zero errors
    let (_, _, h_body) = server
        .request("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let health: HealthResponse = serde_json::from_slice(&h_body).unwrap();
    assert_eq!(health.metrics.errors_count, 0);
}

/// Tier 4 Scenario 3: Real-Time Web Dashboard & Telemetry Workflow.
#[tokio::test]
async fn test_tier4_realtime_dashboard_and_telemetry_workflow() {
    let server = WebTestServer::start().await;
    let echo = MockEchoServer::start().await;

    // 1. Initial stats query
    let (_, _, s_body1) = server
        .request("GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let stats1: StatsResponse = serde_json::from_slice(&s_body1).unwrap();
    assert_eq!(stats1.bytes_client_to_remote, 0);
    assert_eq!(stats1.bytes_remote_to_client, 0);

    // 2. Traffic generation: 2 HTTP CONNECT tunnels transferring 256 KB each
    let (mut t1, _, _) = http_connect_tunnel(server.addr, "127.0.0.1", echo.port()).await.unwrap();
    let (mut t2, _, _) = http_connect_tunnel(server.addr, "127.0.0.1", echo.port()).await.unwrap();

    let data = vec![0xDDu8; 256 * 1024];
    t1.write_all(&data).await.unwrap();
    t2.write_all(&data).await.unwrap();

    let mut b1 = vec![0u8; data.len()];
    let mut b2 = vec![0u8; data.len()];
    t1.read_exact(&mut b1).await.unwrap();
    t2.read_exact(&mut b2).await.unwrap();
    drop(t1);
    drop(t2);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Post-transfer stats query
    let (_, _, s_body2) = server
        .request("GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let stats2: StatsResponse = serde_json::from_slice(&s_body2).unwrap();
    assert_eq!(stats2.bytes_client_to_remote, 512 * 1024);
    assert_eq!(stats2.bytes_remote_to_client, 512 * 1024);
    assert!(stats2.active_connections <= 1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(server.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed), 0);
}
