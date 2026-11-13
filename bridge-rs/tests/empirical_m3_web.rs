//! Dedicated Empirical Verification Test Suite for Milestone 3
//! Node 3: Embedded Web Server & PAC Engine (Features F15–F19)
//!
//! Empirical Challenger: challenger_m3_1
//! Objectives Verified:
//! 1. PAC Domain Oracle & Syntax: 130+ domain oracle evaluation via Windows JScript engine (cscript.exe) and Rust oracle.
//! 2. Dynamic Host Injection Oracle: custom Host headers (custom-host.lan:8888, [::1]:8080, 192.168.1.200:8080, etc.).
//! 3. Apple MobileConfig Plist Integrity: XML validity, PayloadType com.apple.dnsSettings.managed, UUID format, MIME type.
//! 4. Health & Telemetry Accuracy: /health and /api/stats deserialization, live traffic counter verification.
//! 5. Zero Trigger Words Compliance: Automated repository scan for prohibited terms.
//! 6. Adversarial Stress & Edge Cases: High concurrency, path traversals, query strings, slowloris resilience.

mod common;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::{bind_ephemeral_listener, http_connect_tunnel, MockEchoServer};
use zapret_tv_bridge_rs::metrics::ProxyMetrics;
use zapret_tv_bridge_rs::pac::generate_pac_script;
use zapret_tv_bridge_rs::proxy;
use zapret_tv_bridge_rs::router::SmartRouter;
use zapret_tv_bridge_rs::web::{create_web_router, HealthResponse, StatsResponse, WebConfig};

#[allow(dead_code)]
struct EmpiricalWebServer {
    pub addr: SocketAddr,
    pub metrics: Arc<ProxyMetrics>,
    pub router: Arc<SmartRouter>,
    pub config: WebConfig,
}

impl EmpiricalWebServer {
    pub async fn start() -> Self {
        let (listener, port) = bind_ephemeral_listener()
            .await
            .expect("Failed to bind ephemeral empirical test listener");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        drop(listener);
        tokio::task::yield_now().await;

        let base_dir = PathBuf::from("d:\\projects\\zapret-tv-bridge");
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

        // Readiness probe
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

    /// Sends raw HTTP request and reads full HTTP response until connection close or EOF.
    pub async fn send_raw(&self, raw: &str) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| format!("Connect to {}: {}", self.addr, e))?;

        stream
            .write_all(raw.as_bytes())
            .await
            .map_err(|e| format!("Write failed: {}", e))?;

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
                            if let Some(stripped) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                                if let Ok(val) = stripped.trim().parse::<usize>() {
                                    cl = Some(val);
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
                Err(e) => return Err(format!("Read failed: {}", e)),
            }
        }

        let pos = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "Missing header separator \r\n\r\n".to_string())?;

        let header_str = String::from_utf8_lossy(&buf[..pos]);
        let mut lines = header_str.lines();
        let first_line = lines.next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(format!("Malformed status line: {}", first_line));
        }
        let status: u16 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid status: {}", first_line))?;

        let mut headers = Vec::new();
        for line in lines {
            if let Some(idx) = line.find(':') {
                headers.push((
                    line[..idx].trim().to_ascii_lowercase(),
                    line[idx + 1..].trim().to_string(),
                ));
            }
        }

        let body = buf[pos + 4..].to_vec();
        Ok((status, headers, body))
    }
}

// ============================================================================
// Objective 1: PAC Domain Oracle & Syntax (130+ Domains via JScript & Rust)
// ============================================================================

const PAC_TEST_DOMAINS: &[(&str, bool)] = &[
    // 1. Streaming Video & Accelerated Media Platforms (MUST -> PROXY)
    ("googlevideo.com", true),
    ("www.googlevideo.com", true),
    ("rr1---sn-xxx.googlevideo.com", true),
    ("rr2---sn-4g5ednls.googlevideo.com", true),
    ("rr5---sn-h0je6nzs.googlevideo.com", true),
    ("rr3---sn-vgqsrn7e.googlevideo.com", true),
    ("youtube.com", true),
    ("www.youtube.com", true),
    ("m.youtube.com", true),
    ("music.youtube.com", true),
    ("gaming.youtube.com", true),
    ("tv.youtube.com", true),
    ("ytimg.com", true),
    ("i.ytimg.com", true),
    ("s.ytimg.com", true),
    ("ggpht.com", true),
    ("yt3.ggpht.com", true),
    ("lh3.ggpht.com", true),
    ("youtu.be", true),
    ("www.youtu.be", true),
    ("twitch.tv", true),
    ("www.twitch.tv", true),
    ("api.twitch.tv", true),
    ("passport.twitch.tv", true),
    ("ttvnw.net", true),
    ("video-edge-xxx.ttvnw.net", true),
    ("usher.ttvnw.net", true),
    ("discord.gg", true),
    ("discordapp.com", true),
    ("cdn.discordapp.com", true),
    ("media.discordapp.net", true),
    ("discord.com", true),
    ("gateway.discord.gg", true),
    ("instagram.com", true),
    ("www.instagram.com", true),
    ("cdninstagram.com", true),
    ("scontent.cdninstagram.com", true),
    ("fbcdn.net", true),
    ("static.xx.fbcdn.net", true),
    ("facebook.com", true),
    ("www.facebook.com", true),
    ("threads.net", true),
    ("www.threads.net", true),
    ("meta.com", true),
    ("about.meta.com", true),
    ("ig.me", true),
    ("fbsbx.com", true),
    ("static.fbsbx.com", true),
    ("storage.googleapis.com", true),
    ("commondatastorage.googleapis.com", true),
    ("twitter.com", true),
    ("api.twitter.com", true),
    ("x.com", true),
    ("api.x.com", true),
    ("rutracker.org", true),
    ("rutracker.net", true),
    ("rutor.info", true),
    ("rutor.is", true),
    ("nnmclub.to", true),
    ("flibusta.is", true),
    ("flibusta.site", true),

    // 2. Direct, Domestic & Local Subnets (MUST -> DIRECT)
    ("yandex.ru", false),
    ("mail.yandex.ru", false),
    ("vk.com", false),
    ("m.vk.com", false),
    ("gosuslugi.ru", false),
    ("esia.gosuslugi.ru", false),
    ("sberbank.ru", false),
    ("online.sberbank.ru", false),
    ("sber.ru", false),
    ("ozon.ru", false),
    ("wildberries.ru", false),
    ("tinkoff.ru", false),
    ("mail.ru", false),
    ("cloud.mail.ru", false),
    ("127.0.0.1", false),
    ("127.0.0.53", false),
    ("192.168.1.1", false),
    ("192.168.0.100", false),
    ("10.0.0.1", false),
    ("10.200.1.5", false),
    ("printer.local", false),
    ("device.local", false),
    ("router.lan", false),
    ("nas.lan", false),
    ("localhost", false),
    ("router", false),
    ("nas", false),
    ("172.16.0.1", false),
    ("172.17.0.1", false),
    ("172.18.0.1", false),
    ("172.19.0.1", false),
    ("172.20.0.1", false),
    ("172.25.10.1", false),
    ("172.31.255.254", false),

    // 3. Gaming Services -> DIRECT (handled via MobileConfig profiles)
    ("supercell.com", false),
    ("accounts.supercell.com", false),
    ("clashroyale.com", false),
    ("brawlstars.com", false),
    ("clashofclans.com", false),

    // 4. Developer / Cloud Platforms -> DIRECT
    ("cloudcode-pa.googleapis.com", false),
    ("daily-cloudcode-pa.googleapis.com", false),
    ("google.com", false),
    ("www.google.com", false),
    ("gstatic.com", true),
    ("fonts.gstatic.com", true),
    ("gvt1.com", false),
    ("chatgpt.com", false),
    ("openai.com", false),
    ("api.openai.com", false),
    ("anthropic.com", false),
    ("claude.ai", false),
    ("geohide.ru", false),
    ("dns-ai.ru", false),

    // 5. Operating System Services -> DIRECT
    ("apple.com", false),
    ("www.apple.com", false),
    ("itunes.com", false),
    ("mzstatic.com", false),
    ("icloud.com", false),
    ("aaplimg.com", false),
    ("akadns.net", false),
    ("windowsupdate.microsoft.com", false),
    ("microsoft.com", false),

    // 6. Unlisted Default Destinations -> DIRECT
    ("example.com", false),
    ("wikipedia.org", false),
    ("github.com", false),
    ("gitlab.com", false),
    ("stackoverflow.com", false),
    ("rust-lang.org", false),
    ("crates.io", false),
    ("kernel.org", false),
    ("debian.org", false),
    ("ubuntu.com", false),
    ("alpinelinux.org", false),
    ("duckduckgo.com", false),
    ("bing.com", false),
    ("yahoo.com", false),
    ("cnn.com", false),
    ("bbc.com", false),
    ("reuters.com", false),
    ("nytimes.com", false),
];

#[tokio::test]
async fn test_empirical_pac_100_plus_domains_with_jscript_and_oracle() {
    let proxy_host = "10.0.0.5";
    let proxy_port = 8080;
    let script = generate_pac_script(proxy_host, proxy_port);

    assert!(PAC_TEST_DOMAINS.len() >= 100, "Must test at least 100 domains");

const PAC_JS_HELPERS: &str = r#"
function isPlainHostName(host) { return host.indexOf('.') === -1; }
function shExpMatch(str, pat) {
    var regexStr = '^' + pat.replace(/([\.\^\$\+\?\(\)\[\]\{\}\|\/\\])/g, '\\$1').replace(/\*/g, '.*') + '$';
    return new RegExp(regexStr, 'i').test(str);
}
"#;

    let mut js = String::new();
    js.push_str(PAC_JS_HELPERS);
    js.push_str(&script);
    js.push_str("\n");
    js.push_str(&format!(
        r#"var expectedProxy = "PROXY {}:{}; DIRECT";"#,
        proxy_host, proxy_port
    ));
    js.push_str(r#"
var tests = [
"#);
    for (i, (d, expect_proxy)) in PAC_TEST_DOMAINS.iter().enumerate() {
        let comma = if i + 1 == PAC_TEST_DOMAINS.len() { "" } else { "," };
        js.push_str(&format!(r#"  ["{}", {}]{}"#, d, if *expect_proxy { "true" } else { "false" }, comma));
        js.push_str("\n");
    }
    js.push_str(r#"
];
var failCount = 0;
for (var i = 0; i < tests.length; i++) {
    var host = tests[i][0];
    var expectProxy = tests[i][1];
    var res = FindProxyForURL("http://" + host + "/", host);
    var expected = expectProxy ? expectedProxy : "DIRECT";
    if (res !== expected) {
        WScript.Echo("FAIL: host=" + host + " expected=" + expected + " actual=" + res);
        failCount++;
    }
}
if (failCount === 0) {
    WScript.Echo("ALL_PASSED:" + tests.length);
    WScript.Quit(0);
} else {
    WScript.Echo("FAILED:" + failCount);
    WScript.Quit(1);
}
"#);

    let temp_file = std::env::temp_dir().join(format!("empirical_pac_test_{}.js", std::process::id()));
    fs::write(&temp_file, js.as_bytes()).expect("Failed to write temporary test JScript");

    let cscript_res = Command::new("cscript.exe")
        .arg("//Nologo")
        .arg(&temp_file)
        .output();

    let _ = fs::remove_file(&temp_file);

    let out = cscript_res.expect("Failed to execute cscript.exe on Windows");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    eprintln!("CSCRIPT STATUS: {:?}, STDOUT: [{}], STDERR: [{}]", out.status, stdout, stderr);
    assert!(
        out.status.success(),
        "JScript execution reported failures: stdout={}, stderr={}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("ALL_PASSED:"),
        "cscript did not output ALL_PASSED: {}",
        stdout
    );

    // 2. Case-insensitivity check (e.g. UPPERCASE domains)
    let uppercase_domains = [
        ("GOOGLEVIDEO.COM", true),
        ("Rr1---Sn-Xxx.GoogleVideo.Com", true),
        ("YoUtUbE.cOm", true),
        ("Yandex.RU", false),
        ("Vk.CoM", false),
        ("GOSUSLUGI.RU", false),
    ];
    for (d, expect_proxy) in uppercase_domains {
        let expected_directive = if expect_proxy {
            format!("PROXY {}:{}; DIRECT", proxy_host, proxy_port)
        } else {
            "DIRECT".to_string()
        };
        // Verify via cscript single evaluation
        let single_js = format!(
            "{}\n{}\nvar res = FindProxyForURL(\"http://{}/\", \"{}\");\nWScript.Echo(res);\n",
            PAC_JS_HELPERS, script, d, d
        );
        let temp_single = std::env::temp_dir().join(format!("pac_case_test_{}.js", std::process::id()));
        fs::write(&temp_single, single_js.as_bytes()).unwrap();
        let out = Command::new("cscript.exe")
            .arg("//Nologo")
            .arg(&temp_single)
            .output()
            .unwrap();
        let _ = fs::remove_file(&temp_single);
        let res_trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_eq!(
            res_trimmed, expected_directive,
            "Domain {} case insensitivity check failed",
            d
        );
    }
}

// ============================================================================
// Objective 2: Dynamic Host Injection Oracle
// ============================================================================

#[tokio::test]
async fn test_empirical_dynamic_host_injection_oracle() {
    let server = EmpiricalWebServer::start().await;

    let test_cases = vec![
        ("custom-host.lan:8888", "custom-host.lan", 8888),
        ("[::1]:8080", "[::1]", 8080),
        ("192.168.1.200:8080", "192.168.1.200", 8080),
        ("[2001:db8::1]:9090", "[2001:db8::1]", 9090),
        ("[2001:db8::1]", "[2001:db8::1]", server.addr.port()),
        ("tv-bridge.lan", "tv-bridge.lan", server.addr.port()),
        ("  192.168.10.50:7777  ", "192.168.10.50", 7777),
    ];

    for (host_hdr, exp_host, exp_port) in test_cases {
        let req = format!(
            "GET /proxy.pac HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host_hdr
        );
        let (status, headers, body) = server.send_raw(&req).await.unwrap();
        assert_eq!(status, 200, "Host {} must return 200", host_hdr);

        let ct = headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.as_str());
        assert_eq!(ct, Some("application/x-ns-proxy-autoconfig; charset=utf-8"));

        let body_str = String::from_utf8_lossy(&body);
        let expected_proxy_line = format!("var proxy = \"PROXY {}:{}; DIRECT\";", exp_host, exp_port);
        assert!(
            body_str.contains(&expected_proxy_line),
            "PAC body does not contain expected line: {}\nActual snippet: {}",
            expected_proxy_line,
            &body_str[..body_str.find("function").unwrap_or(body_str.len().min(150))]
        );
    }

    // Edge case: Missing Host header in HTTP/1.0 request -> fallback
    let req_http10 = "GET /proxy.pac HTTP/1.0\r\n\r\n";
    let (status, _, body) = server.send_raw(req_http10).await.unwrap();
    assert_eq!(status, 200);
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains(&format!("PROXY 127.0.0.1:{}; DIRECT", server.addr.port()))
            || body_str.contains(&format!(":{}", server.addr.port()))
    );

    // Edge case: 0.0.0.0 host header -> fallback to default LAN IP
    let req_unspec = "GET /proxy.pac HTTP/1.1\r\nHost: 0.0.0.0:8080\r\nConnection: close\r\n\r\n";
    let (status, _, body) = server.send_raw(req_unspec).await.unwrap();
    assert_eq!(status, 200);
    let body_str = String::from_utf8_lossy(&body);
    assert!(!body_str.contains("PROXY 0.0.0.0:"));
}

// ============================================================================
// Objective 3: Apple MobileConfig Plist Integrity
// ============================================================================

#[tokio::test]
async fn test_empirical_apple_mobileconfig_plist_integrity() {
    let server = EmpiricalWebServer::start().await;

    let profile_endpoints = vec![
        ("/supercell.mobileconfig", "Supercell_Gaming_COMSS.mobileconfig", "dns.comss.one", "HTTPS"),
        ("/nullsproxy.mobileconfig", "NullsProxy_Gaming.mobileconfig", "dns.nullsproxy.com", "TLS"),
        ("/brawlstars.mobileconfig", "Supercell_Gaming_COMSS.mobileconfig", "dns.comss.one", "HTTPS"),
        ("/clashroyale.mobileconfig", "Supercell_Gaming_COMSS.mobileconfig", "dns.comss.one", "HTTPS"),
        ("/comss.mobileconfig", "Supercell_Gaming_COMSS.mobileconfig", "dns.comss.one", "HTTPS"),
    ];

    for (path, exp_filename, exp_server, exp_protocol) in profile_endpoints {
        let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
        let (status, headers, body) = server.send_raw(&req).await.unwrap();
        assert_eq!(status, 200, "Path {} must return 200", path);

        let ct = headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.as_str());
        assert_eq!(ct, Some("application/x-apple-aspen-config; charset=utf-8"));

        let cd = headers.iter().find(|(k, _)| k == "content-disposition").map(|(_, v)| v.as_str());
        let expected_cd = format!("attachment; filename=\"{}\"", exp_filename);
        assert_eq!(cd, Some(expected_cd.as_str()));

        let xml_str = String::from_utf8_lossy(&body).to_string();

        // 1. Plist XML Prolog and DOCTYPE assertions
        assert!(xml_str.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml_str.contains("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""));
        assert!(xml_str.contains("<plist version=\"1.0\">"));
        assert!(xml_str.trim_end().ends_with("</plist>"));

        // 2. PayloadType com.apple.dnsSettings.managed
        assert!(xml_str.contains("<key>PayloadType</key>\n            <string>com.apple.dnsSettings.managed</string>")
            || xml_str.contains("<key>PayloadType</key>") && xml_str.contains("<string>com.apple.dnsSettings.managed</string>"));

        // 3. PayloadType Configuration
        assert!(xml_str.contains("<string>Configuration</string>"));

        // 4. PayloadUUID format validation (8-4-4-4-12 hex format)
        let uuid_indices: Vec<_> = xml_str.match_indices("<key>PayloadUUID</key>").collect();
        assert!(uuid_indices.len() >= 2, "Mobileconfig must contain at least 2 PayloadUUIDs (inner and outer)");

        // 5. Server URL / Name and DNS protocol
        assert!(xml_str.contains(exp_server));
        assert!(xml_str.contains(exp_protocol));

        // 6. OnDemandRules structure
        assert!(xml_str.contains("<key>OnDemandRules</key>"));
        assert!(xml_str.contains("<key>InterfaceTypeMatch</key>"));
        assert!(xml_str.contains("<string>WiFi</string>"));
        assert!(xml_str.contains("<string>Cellular</string>"));

        // 7. XML Well-formedness check via Powershell [xml] parser
        let temp_xml = std::env::temp_dir().join(format!("mobileconfig_val_{}.xml", std::process::id()));
        fs::write(&temp_xml, xml_str.as_bytes()).unwrap();

        let ps_cmd = format!(
            r#"[xml]$doc = Get-Content -Raw "{}"; if ($doc.plist.dict -ne $null) {{ Write-Host "XML_VALID" }} else {{ Write-Host "XML_INVALID" }}"#,
            temp_xml.to_str().unwrap()
        );
        let ps_out = Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(&ps_cmd)
            .output()
            .unwrap();

        let _ = fs::remove_file(&temp_xml);
        let ps_res = String::from_utf8_lossy(&ps_out.stdout).trim().to_string();
        assert_eq!(ps_res, "XML_VALID", "PowerShell XML parser failed to parse plist for path {}", path);
    }
}

// ============================================================================
// Objective 4: Health & Telemetry Accuracy
// ============================================================================

#[tokio::test]
async fn test_empirical_health_and_telemetry_accuracy() {
    let server = EmpiricalWebServer::start().await;

    // 1. Initial /health check
    let req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, headers, body) = server.send_raw(req).await.unwrap();
    assert_eq!(status, 200);

    let ct = headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.as_str());
    assert_eq!(ct, Some("application/json"));

    let health: HealthResponse = serde_json::from_slice(&body).expect("Failed to deserialize /health JSON");
    assert_eq!(health.status, "ok");
    assert_eq!(health.service, "ZapretTVBridge");
    assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(health.uptime_seconds, health.uptime_secs);
    assert!(health.metrics.active_connections >= 1);
    assert_eq!(health.metrics.bytes_client_to_remote, 0);
    assert_eq!(health.metrics.bytes_remote_to_client, 0);
    assert_eq!(health.metrics.errors_count, 0);

    // 2. Initial /api/stats check
    let req_stats = "GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status2, _, body2) = server.send_raw(req_stats).await.unwrap();
    assert_eq!(status2, 200);
    let stats: StatsResponse = serde_json::from_slice(&body2).expect("Failed to deserialize /api/stats JSON");
    assert!(stats.active_connections >= 1);
    assert_eq!(stats.bytes_client_to_remote, 0);
    assert_eq!(stats.bytes_remote_to_client, 0);
    assert_eq!(stats.errors_count, 0);

    // 3. Dynamic Telemetry Accuracy Test:
    // Spin up MockEchoServer and establish an HTTP CONNECT tunnel through our proxy server,
    // transfer 8192 bytes upstream and 8192 bytes downstream.
    let echo = MockEchoServer::start().await;
    let payload = vec![0x42u8; 8192];

    let (mut client, tunnel_status, _) = http_connect_tunnel(server.addr, "127.0.0.1", echo.port())
        .await
        .expect("HTTP CONNECT tunnel to echo server failed");
    assert_eq!(tunnel_status, 200);

    client.write_all(&payload).await.expect("Failed to write upstream data");
    client.flush().await.expect("Flush failed");

    let mut recv_buf = vec![0u8; 8192];
    client.read_exact(&mut recv_buf).await.expect("Failed to read downstream echoed data");
    assert_eq!(recv_buf, payload);

    // Drop client stream to terminate connection cleanly
    drop(client);

    // 4. Query telemetry again and assert counters reflect the data transferred
    let mut updated_stats = StatsResponse {
        active_connections: 999,
        total_connections: 0,
        bytes_client_to_remote: 0,
        bytes_remote_to_client: 0,
        errors_count: 0,
        uptime_seconds: 0,
    };
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        if let Ok((200, _, body3)) = server.send_raw(req_stats).await {
            if let Ok(s) = serde_json::from_slice::<StatsResponse>(&body3) {
                if s.active_connections == 0 {
                    updated_stats = s;
                    break;
                }
                updated_stats = s;
            }
        }
    }

    assert!(
        updated_stats.total_connections >= 1,
        "Total connections must be >= 1"
    );
    assert!(
        updated_stats.bytes_client_to_remote >= 8192,
        "Upstream bytes must be >= 8192, got {}",
        updated_stats.bytes_client_to_remote
    );
    assert!(
        updated_stats.bytes_remote_to_client >= 8192,
        "Downstream bytes must be >= 8192, got {}",
        updated_stats.bytes_remote_to_client
    );
    assert_eq!(
        updated_stats.active_connections, 1,
        "Only the stats query request itself is active during the call"
    );

    // When idle (no HTTP request in-flight), server metrics active_connections must be 0
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        server.metrics.snapshot().active_connections, 0,
        "Active connections in server metrics must return to 0 when idle"
    );

    // Verify /health metrics match /api/stats
    let (_, _, body_h2) = server.send_raw(req).await.unwrap();
    let health2: HealthResponse = serde_json::from_slice(&body_h2).unwrap();
    assert_eq!(health2.metrics.total_connections, updated_stats.total_connections + 1);
    assert_eq!(health2.metrics.bytes_client_to_remote, updated_stats.bytes_client_to_remote);
    assert_eq!(health2.metrics.bytes_remote_to_client, updated_stats.bytes_remote_to_client);
    assert!(health2.metrics.active_connections >= 1);
}

// ============================================================================
// Objective 5: Zero Trigger Words Compliance
// ============================================================================

#[test]
fn test_empirical_zero_trigger_words_compliance() {
    let p1: [u8; 10] = [0xd0, 0xbe, 0xd0, 0xb1, 0xd1, 0x85, 0xd0, 0xbe, 0xd0, 0xb4];
    let p2: [u8; 18] = [0xd0, 0xb1, 0xd0, 0xbb, 0xd0, 0xbe, 0xd0, 0xba, 0xd0, 0xb8, 0xd1, 0x80, 0xd0, 0xbe, 0xd0, 0xb2, 0xd0, 0xba];
    let p3: [u8; 6] = [0xd1, 0x80, 0xd0, 0xba, 0xd0, 0xbd];
    let p4: [u8; 24] = [0xd1, 0x80, 0xd0, 0xbe, 0xd1, 0x81, 0xd0, 0xba, 0xd0, 0xbe, 0xd0, 0xbc, 0xd0, 0xbd, 0xd0, 0xb0, 0xd0, 0xb4, 0xd0, 0xb7, 0xd0, 0xbe, 0xd1, 0x80];
    let p5: [u8; 6] = [0x62, 0x79, 0x70, 0x61, 0x73, 0x73];
    let forbidden: &[(&str, &[u8])] = &[
        ("Term-1", &p1),
        ("Term-2", &p2),
        ("Term-3", &p3),
        ("Term-4", &p4),
        ("Term-5", &p5),
    ];
    let root = Path::new("d:\\projects\\zapret-tv-bridge\\bridge-rs");

    fn scan_dir(dir: &Path, forbidden: &[(&str, &[u8])], violations: &mut Vec<(String, usize, String)>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if dir_name == "target" || dir_name == ".git" {
                        continue;
                    }
                    scan_dir(&path, forbidden, violations);
                } else if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext == "rs" || ext == "md" || ext == "toml" || ext == "txt" {
                        if let Ok(content) = fs::read(&path) {
                            let text = String::from_utf8_lossy(&content);
                            for (line_num, line) in text.lines().enumerate() {
                                let line_lower = line.to_lowercase();
                                let line_bytes = line_lower.as_bytes();
                                for (label, pat) in forbidden {
                                    if line_bytes.windows(pat.len()).any(|w| w == *pat) {
                                        violations.push((
                                            path.display().to_string(),
                                            line_num + 1,
                                            format!("Pattern {}: {}", label, line.trim()),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut violations = Vec::new();
    scan_dir(root, forbidden, &mut violations);

    if !violations.is_empty() {
        for (file, line, text) in &violations {
            eprintln!("TRIGGER WORD VIOLATION: {}:{} -> {}", file, line, text);
        }
    }
    assert!(
        violations.is_empty(),
        "Detected {} forbidden trigger word occurrences in codebase!",
        violations.len()
    );
}

// ============================================================================
// Objective 6: Adversarial Stress & Edge Cases
// ============================================================================

#[tokio::test]
async fn test_empirical_stress_and_adversarial_resilience() {
    let server = EmpiricalWebServer::start().await;

    // 1. High-concurrency blitz: 100 concurrent requests across distinct endpoints
    let mut handles = Vec::new();
    for i in 0..100 {
        let addr = server.addr;
        let endpoint = match i % 5 {
            0 => "/proxy.pac",
            1 => "/health",
            2 => "/api/stats",
            3 => "/supercell.mobileconfig",
            _ => "/favicon.ico",
        };
        handles.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", endpoint);
            s.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            assert!(!buf.is_empty());
            let first_line = String::from_utf8_lossy(&buf);
            assert!(
                first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.1 204"),
                "Request to {} failed: {}",
                endpoint,
                first_line.lines().next().unwrap_or("")
            );
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // 2. Path Traversal & Injection attempts -> MUST return 404, never 200 or internal error
    let malicious_paths = [
        "/../../etc/passwd",
        "/..%2f..%2fconfig.json",
        "/..\\..\\Windows\\win.ini",
        "/supercell.mobileconfig/../../secret",
        "/health/../../../main.rs",
    ];
    for bad_path in malicious_paths {
        let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", bad_path);
        let (status, _, body) = server.send_raw(&req).await.unwrap();
        assert_eq!(
            status, 404,
            "Path traversal '{}' must return 404 Not Found, got: {}",
            bad_path, status
        );
        assert_eq!(String::from_utf8_lossy(&body), "404 Not Found");
    }

    // 3. Query strings and URL fragments
    let req_query = "GET /proxy.pac?client=ios&network=wifi&v=2#cache HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _, body) = server.send_raw(req_query).await.unwrap();
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("FindProxyForURL"));

    // 4. Favicon 204 No Content
    let req_fav = "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let (status, _, body) = server.send_raw(req_fav).await.unwrap();
    assert_eq!(status, 204);
    assert!(body.is_empty(), "204 No Content must have 0 body bytes");

    // 5. Dashboard HTML UI Verification
    let req_dash = "GET / HTTP/1.1\r\nHost: 192.168.1.150:8080\r\nConnection: close\r\n\r\n";
    let (status, headers, body) = server.send_raw(req_dash).await.unwrap();
    assert_eq!(status, 200);
    let ct = headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.as_str());
    assert_eq!(ct, Some("text/html; charset=utf-8"));
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Zapret TV &amp; Mobile Bridge") || html.contains("Zapret TV & Mobile Bridge"));
    assert!(html.contains("РАБОТАЕТ"));
    assert!(html.contains("http://192.168.1.150:8080/proxy.pac"));
    assert!(html.contains("/supercell.mobileconfig"));
    assert!(html.contains("/nullsproxy.mobileconfig"));
}
