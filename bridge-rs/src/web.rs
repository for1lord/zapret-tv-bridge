//! Embedded Axum Web Server, Asset Delivery, and Dashboard UI.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tower::ServiceExt;

use crate::metrics::{MetricsSnapshot, ProxyMetrics};
use crate::pac;

pub const DEFAULT_SUPERCELL_MOBILECONFIG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>https://dns.comss.one/dns-query</string>
            </dict>
            <key>OnDemandRules</key>
            <array>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>WiFi</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>Cellular</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Disconnect</string>
                </dict>
            </array>
            <key>PayloadDescription</key>
            <string>Настройка DNS over HTTPS для прямого подключения в Brawl Stars, Clash Royale и Clash of Clans</string>
            <key>PayloadDisplayName</key>
            <string>COMSS Gaming DNS (Brawl Stars &amp; Clash Royale)</string>
            <key>PayloadIdentifier</key>
            <string>com.apple.dnsSettings.managed.comss.gaming</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>C5B28A14-9E3F-4D78-812C-3A0F56B7D891</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Игровой DNS-профиль для подключения в Clash Royale, Brawl Stars и Clash of Clans</string>
    <key>PayloadDisplayName</key>
    <string>Supercell Gaming DNS (Clash Royale / Brawl Stars)</string>
    <key>PayloadIdentifier</key>
    <string>com.supercell.gaming.dns.profile</string>
    <key>PayloadOrganization</key>
    <string>COMSS.ONE</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>F721A0C9-5D83-4E61-B91A-82E054C137F4</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"#;

pub const DEFAULT_NULLS_MOBILECONFIG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>TLS</string>
                <key>ServerName</key>
                <string>dns.nullsproxy.com</string>
            </dict>
            <key>OnDemandRules</key>
            <array>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>WiFi</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>Cellular</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Disconnect</string>
                </dict>
            </array>
            <key>PayloadDescription</key>
            <string>Настройка DNS over TLS (Null's Proxy) для Supercell игр</string>
            <key>PayloadDisplayName</key>
            <string>Null's Proxy Gaming DNS (DoT)</string>
            <key>PayloadIdentifier</key>
            <string>com.apple.dnsSettings.managed.nullsproxy.gaming</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>B21CE26F-66C9-42DF-873E-B7D3A2865539</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Официальный профиль Null's Proxy для Supercell игр</string>
    <key>PayloadDisplayName</key>
    <string>Null's Proxy DNS (Brawl Stars)</string>
    <key>PayloadIdentifier</key>
    <string>com.nullsproxy.dns.profile</string>
    <key>PayloadOrganization</key>
    <string>Null's Team</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>9CBFD31C-60F3-47CA-B1EA-C74895BA64DB</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"#;

#[derive(Clone, Debug)]
pub struct WebConfig {
    pub proxy_port: u16,
    pub default_ip: String,
    pub base_dir: PathBuf,
    pub tg_port: u16,
    pub tg_secret: String,
    pub start_time: Instant,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            proxy_port: 8080,
            default_ip: pac::get_local_ip(),
            base_dir: PathBuf::from("."),
            tg_port: 1443,
            tg_secret: "00000000000000000000000000000000".to_string(),
            start_time: Instant::now(),
        }
    }
}

impl WebConfig {
    pub fn new(
        proxy_port: u16,
        default_ip: String,
        base_dir: PathBuf,
        tg_port: u16,
        tg_secret: String,
        start_time: Instant,
    ) -> Self {
        Self {
            proxy_port,
            default_ip,
            base_dir,
            tg_port,
            tg_secret,
            start_time,
        }
    }

    pub fn default_with_port(proxy_port: u16) -> Self {
        let mut cfg = Self::default();
        cfg.proxy_port = proxy_port;
        cfg
    }
}

pub struct WebState {
    pub metrics: Arc<ProxyMetrics>,
    pub config: WebConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub uptime_secs: u64,
    pub metrics: MetricsSnapshot,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatsResponse {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_client_to_remote: u64,
    pub bytes_remote_to_client: u64,
    pub errors_count: u64,
    pub uptime_seconds: u64,
}

/// Creates the Axum router for local requests.
pub fn create_web_router(metrics: Arc<ProxyMetrics>, config: WebConfig) -> Router {
    let state = Arc::new(WebState { metrics, config });
    Router::new()
        .route("/health", get(health_handler))
        .route("/health/", get(health_handler))
        .route("/favicon.ico", get(favicon_handler))
        .route("/proxy.pac", get(pac_handler))
        .route("/proxy.pac/", get(pac_handler))
        .route("/anticensority.pac", get(pac_handler))
        .route("/anticensority.pac/", get(pac_handler))
        .route("/pac", get(pac_handler))
        .route("/pac/", get(pac_handler))
        .route("/wpad.dat", get(pac_handler))
        .route("/wpad.dat/", get(pac_handler))
        .route("/PROXY.PAC", get(pac_handler))
        .route("/Proxy.Pac", get(pac_handler))
        .route("/supercell.mobileconfig", get(mobileconfig_supercell_handler))
        .route("/brawlstars.mobileconfig", get(mobileconfig_supercell_handler))
        .route("/clashroyale.mobileconfig", get(mobileconfig_supercell_handler))
        .route("/comss.mobileconfig", get(mobileconfig_supercell_handler))
        .route("/nullsproxy.mobileconfig", get(mobileconfig_nulls_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/stats/", get(stats_handler))
        .route("/stats", get(stats_handler))
        .route("/", get(dashboard_handler))
        .route("/index.html", get(dashboard_handler))
        .fallback(fallback_404)
        .with_state(state)
}

async fn health_handler(State(state): State<Arc<WebState>>) -> Json<HealthResponse> {
    let elapsed = state.config.start_time.elapsed().as_secs();
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "ZapretTVBridge".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: elapsed,
        uptime_secs: elapsed,
        metrics: state.metrics.snapshot(),
    })
}

async fn favicon_handler() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

async fn pac_handler(State(state): State<Arc<WebState>>, req: Request) -> Response {
    let host_header = req.headers().get("host").and_then(|v| v.to_str().ok());
    let (host, port) = pac::resolve_proxy_target(
        host_header,
        None,
        &state.config.default_ip,
        state.config.proxy_port,
    );

    let script = pac::generate_served_pac(&host, port, &state.config.base_dir);
    let cl = script.len().to_string();
    (
        [
            ("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8"),
            ("Cache-Control", "no-cache, no-store, must-revalidate"),
            ("Pragma", "no-cache"),
            ("Expires", "0"),
            ("Content-Length", cl.as_str()),
        ],
        script,
    )
        .into_response()
}

async fn mobileconfig_supercell_handler(State(state): State<Arc<WebState>>) -> Response {
    let disk_path = state.config.base_dir.join("supercell.mobileconfig");
    let content = if disk_path.exists() {
        tokio::fs::read_to_string(&disk_path)
            .await
            .unwrap_or_else(|_| DEFAULT_SUPERCELL_MOBILECONFIG.to_string())
    } else {
        DEFAULT_SUPERCELL_MOBILECONFIG.to_string()
    };

    let cl = content.len().to_string();
    (
        [
            ("Content-Type", "application/x-apple-aspen-config; charset=utf-8"),
            (
                "Content-Disposition",
                "attachment; filename=\"Supercell_Gaming_COMSS.mobileconfig\"",
            ),
            ("Content-Length", cl.as_str()),
        ],
        content,
    )
        .into_response()
}

async fn mobileconfig_nulls_handler(State(state): State<Arc<WebState>>) -> Response {
    let disk_path = state.config.base_dir.join("nullsproxy.mobileconfig");
    let content = if disk_path.exists() {
        tokio::fs::read_to_string(&disk_path)
            .await
            .unwrap_or_else(|_| DEFAULT_NULLS_MOBILECONFIG.to_string())
    } else {
        DEFAULT_NULLS_MOBILECONFIG.to_string()
    };

    let cl = content.len().to_string();
    (
        [
            ("Content-Type", "application/x-apple-aspen-config; charset=utf-8"),
            (
                "Content-Disposition",
                "attachment; filename=\"NullsProxy_Gaming.mobileconfig\"",
            ),
            ("Content-Length", cl.as_str()),
        ],
        content,
    )
        .into_response()
}

async fn stats_handler(State(state): State<Arc<WebState>>) -> Json<StatsResponse> {
    let snap = state.metrics.snapshot();
    let uptime = state.config.start_time.elapsed().as_secs();
    Json(StatsResponse {
        active_connections: snap.active_connections,
        total_connections: snap.total_connections,
        bytes_client_to_remote: snap.bytes_client_to_remote,
        bytes_remote_to_client: snap.bytes_remote_to_client,
        errors_count: snap.errors_count,
        uptime_seconds: uptime,
    })
}

async fn dashboard_handler(State(state): State<Arc<WebState>>, req: Request) -> Html<String> {
    let host_header = req.headers().get("host").and_then(|v| v.to_str().ok());
    let (host, port) = pac::resolve_proxy_target(
        host_header,
        None,
        &state.config.default_ip,
        state.config.proxy_port,
    );

    let snap = state.metrics.snapshot();
    let uptime = state.config.start_time.elapsed().as_secs();
    Html(render_dashboard_html(
        &host,
        port,
        state.config.tg_port,
        &state.config.tg_secret,
        uptime,
        &snap,
    ))
}

async fn fallback_404() -> (StatusCode, [(&'static str, &'static str); 2], &'static str) {
    (
        StatusCode::NOT_FOUND,
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Connection", "close"),
        ],
        "404 Not Found",
    )
}

/// Dispatches an inbound HTTP request to the Axum web router and writes response to client.
pub async fn handle_local_request(
    mut client: TcpStream,
    method: &str,
    path: &str,
    headers: &[httparse::Header<'_>],
    body_payload: &[u8],
    router: Router,
) -> io::Result<()> {
    // Normalize path: extract clean relative URI if absolute URI was provided
    let clean_uri = if let Some(idx) = path.find("://") {
        if let Some(slash_idx) = path[idx + 3..].find('/') {
            &path[idx + 3 + slash_idx..]
        } else {
            "/"
        }
    } else {
        path
    };

    let mut req_builder = axum::http::Request::builder()
        .method(method)
        .uri(clean_uri);

    for h in headers.iter() {
        if let Ok(name) = axum::http::header::HeaderName::from_bytes(h.name.as_bytes()) {
            req_builder = req_builder.header(name, h.value);
        }
    }

    let body = if body_payload.is_empty() {
        Body::empty()
    } else {
        Body::from(body_payload.to_vec())
    };

    let req = match req_builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            let err_resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = client.write_all(err_resp.as_bytes()).await;
            let _ = client.flush().await;
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
        }
    };

    let resp = router
        .oneshot(req)
        .await
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());

    write_response(&mut client, resp).await
}

/// Serializes an Axum HTTP response to an async byte stream.
pub async fn write_response<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    response: Response,
) -> io::Result<()> {
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("");
    let (parts, body) = response.into_parts();
    let body_bytes = to_bytes(body, 16 * 1024 * 1024)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut out = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason);
    let mut has_content_length = false;
    let mut has_connection = false;

    for (name, val) in parts.headers.iter() {
        if name.as_str().eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        if name.as_str().eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(val.to_str().unwrap_or(""));
        out.push_str("\r\n");
    }

    if status != StatusCode::NO_CONTENT && !has_content_length {
        out.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    if !has_connection {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");

    stream.write_all(out.as_bytes()).await?;
    if !body_bytes.is_empty() {
        stream.write_all(&body_bytes).await?;
    }
    stream.flush().await?;
    Ok(())
}

fn render_dashboard_html(
    ip: &str,
    proxy_port: u16,
    tg_port: u16,
    tg_secret: &str,
    uptime_secs: u64,
    metrics: &MetricsSnapshot,
) -> String {
    format!(
r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zapret TV & Mobile Bridge</title>
<style>
  :root {{
    --bg: #090d16;
    --card-bg: #131b2e;
    --card-sub: #1e293b;
    --accent: #38bdf8;
    --accent-hover: #0284c7;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --border: #334155;
    --success: #10b981;
    --tg: #229ed9;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px 16px;
    line-height: 1.6;
    display: flex;
    justify-content: center;
  }}
  .container {{
    max-width: 640px;
    width: 100%;
  }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.4);
    margin-bottom: 20px;
  }}
  .header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
    flex-wrap: wrap;
    gap: 10px;
  }}
  h1 {{
    font-size: 22px;
    color: var(--accent);
    font-weight: 700;
  }}
  .badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    background: rgba(16, 185, 129, 0.2);
    color: var(--success);
    border: 1px solid var(--success);
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
  }}
  .badge::before {{
    content: "";
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 8px var(--success);
  }}
  .desc {{
    font-size: 14px;
    color: var(--text-muted);
    margin-bottom: 20px;
  }}
  .section {{
    background: var(--card-sub);
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 16px;
    border: 1px solid rgba(255,255,255,0.05);
  }}
  .section-title {{
    font-size: 16px;
    font-weight: 600;
    color: #e2e8f0;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .val-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #0f172a;
    padding: 8px 12px;
    border-radius: 8px;
    margin-top: 8px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 14px;
    word-break: break-all;
  }}
  .val-row code {{
    color: var(--accent);
  }}
  .copy-btn {{
    background: #334155;
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    margin-left: 10px;
    white-space: nowrap;
    transition: background 0.2s;
  }}
  .copy-btn:hover {{
    background: #475569;
  }}
  .btn {{
    display: inline-block;
    background: var(--accent);
    color: #0f172a;
    font-weight: 700;
    padding: 10px 16px;
    border-radius: 8px;
    text-decoration: none;
    font-size: 14px;
    transition: background 0.2s, transform 0.1s;
    text-align: center;
    cursor: pointer;
    border: none;
  }}
  .btn:hover {{
    background: var(--accent-hover);
    color: #fff;
  }}
  .btn-tg {{
    background: var(--tg);
    color: #fff;
  }}
  .btn-tg:hover {{
    background: #1d8bc0;
  }}
  .btn-group {{
    display: flex;
    gap: 10px;
    margin-top: 12px;
    flex-wrap: wrap;
  }}
  .info-text {{
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 8px;
  }}
  .stats-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-top: 12px;
  }}
  .stat-box {{
    background: rgba(0,0,0,0.25);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px;
    text-align: center;
  }}
  .stat-num {{
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
  }}
  .stat-label {{
    font-size: 11px;
    color: var(--text-muted);
  }}
  footer {{
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 20px;
  }}
</style>
<script>
function copyText(val, btn) {{
  navigator.clipboard.writeText(val).then(() => {{
    const old = btn.innerText;
    btn.innerText = "Скопировано!";
    setTimeout(() => {{ btn.innerText = old; }}, 1500);
  }}).catch(() => {{
    const old = btn.innerText;
    btn.innerText = "Скопировано!";
    setTimeout(() => {{ btn.innerText = old; }}, 1500);
  }});
}}
</script>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="header">
      <h1>Zapret TV & Mobile Bridge</h1>
      <span class="badge">РАБОТАЕТ</span>
    </div>
    <p class="desc">
      Локальный сетевой шлюз и прокси-мост с поддержкой <strong>Умной маршрутизации трафика</strong> (Smart Routing). Оптимизирует потоковое видео и медиа-сервисы через Zapret на ПК.
    </p>

    <!-- Section 1: PAC Autoconfig for iOS / macOS / Windows -->
    <div class="section">
      <div class="section-title">1. Автоконфигурация PAC (iOS / iPad / Mac / Windows)</div>
      <p class="info-text">В настройках сети Wi-Fi выберите <strong>Настройка прокси -&gt; Автоматически</strong> и укажите URL:</p>
      <div class="val-row">
        <code>http://{ip}:{proxy_port}/proxy.pac</code>
        <button class="copy-btn" onclick="copyText('http://{ip}:{proxy_port}/proxy.pac', this)">Копировать</button>
      </div>
    </div>

    <!-- Section 2: Manual HTTP Proxy for Smart TVs -->
    <div class="section">
      <div class="section-title">2. Smart TV (LG webOS / Android TV / Apple TV)</div>
      <p class="info-text">В расширенных настройках сети телевизора выберите <strong>Прокси (HTTP)</strong>:</p>
      <div class="val-row">
        <span>IP сервера: <code>{ip}</code></span>
        <button class="copy-btn" onclick="copyText('{ip}', this)">Копировать IP</button>
      </div>
      <div class="val-row" style="margin-top: 6px;">
        <span>Порт: <code>{proxy_port}</code></span>
        <button class="copy-btn" onclick="copyText('{proxy_port}', this)">Копировать порт</button>
      </div>
    </div>

    <!-- Section 3: Telegram MTProto WebSocket -->
    <div class="section">
      <div class="section-title">3. Telegram MTProto Proxy (1 клик)</div>
      <p class="info-text">Стабильное прямое подключение Telegram без задержек (поддерживает любые аккаунты):</p>
      <div class="btn-group">
        <a class="btn btn-tg" href="tg://proxy?server={ip}&port={tg_port}&secret=dd{tg_secret}">Подключить в Telegram</a>
        <a class="btn" style="background: #334155; color: #fff;" href="https://t.me/proxy?server={ip}&port={tg_port}&secret=dd{tg_secret}" target="_blank">Ссылка t.me</a>
      </div>
      <div class="val-row" style="margin-top: 10px;">
        <span>Секрет: <code>dd{tg_secret}</code></span>
        <button class="copy-btn" onclick="copyText('dd{tg_secret}', this)">Копировать</button>
      </div>
    </div>

    <!-- Section 4: Supercell Gaming Profile -->
    <div class="section">
      <div class="section-title">4. Brawl Stars & Clash Royale (DNS-профиль)</div>
      <p class="info-text">Для прямого подключения игр Supercell на iOS скачайте игровой DNS-профиль:</p>
      <div class="btn-group">
        <a class="btn" href="/supercell.mobileconfig">📥 Профиль COMSS (Рекомендуется: DoH)</a>
        <a class="btn" href="/nullsproxy.mobileconfig" style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.2); color: #fff;">📥 Null's Proxy (DoT)</a>
      </div>
      <p class="info-text" style="font-size: 12px; margin-top: 8px;">
        После загрузки в Safari: <em>Настройки -&gt; Профиль загружен -&gt; Установить</em>.
      </p>
    </div>

    <!-- Section 5: Telemetry Status Grid -->
    <div class="section">
      <div class="section-title">5. Состояние и статистика (Uptime: {uptime}s)</div>
      <div class="stats-grid">
        <div class="stat-box"><div class="stat-num">{active_conn}</div><div class="stat-label">Активных соединений</div></div>
        <div class="stat-box"><div class="stat-num">{total_conn}</div><div class="stat-label">Всего соединений</div></div>
        <div class="stat-box"><div class="stat-num">{bytes_up}</div><div class="stat-label">Отправлено (байт)</div></div>
        <div class="stat-box"><div class="stat-num">{bytes_down}</div><div class="stat-label">Принято (байт)</div></div>
      </div>
    </div>

    <footer>
      Zapret TV & Mobile Bridge &bull; Локальный хост: {ip}:{proxy_port}
    </footer>
  </div>
</div>
</body>
</html>"#,
        ip = ip,
        proxy_port = proxy_port,
        tg_port = tg_port,
        tg_secret = tg_secret,
        uptime = uptime_secs,
        active_conn = metrics.active_connections,
        total_conn = metrics.total_connections,
        bytes_up = metrics.bytes_client_to_remote,
        bytes_down = metrics.bytes_remote_to_client,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[tokio::test]
    async fn test_create_web_router_health() {
        let metrics = Arc::new(ProxyMetrics::new());
        let config = WebConfig::default();
        let router = create_web_router(metrics, config);

        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: HealthResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json.status, "ok");
        assert_eq!(json.service, "ZapretTVBridge");
    }

    #[tokio::test]
    async fn test_create_web_router_favicon() {
        let metrics = Arc::new(ProxyMetrics::new());
        let config = WebConfig::default();
        let router = create_web_router(metrics, config);

        let req = Request::builder()
            .uri("/favicon.ico")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_create_web_router_pac() {
        let metrics = Arc::new(ProxyMetrics::new());
        let config = WebConfig::default_with_port(8080);
        let router = create_web_router(metrics, config);

        let req = Request::builder()
            .uri("/proxy.pac")
            .header("host", "192.168.1.150:8080")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-ns-proxy-autoconfig; charset=utf-8"
        );

        let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let script = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(script.contains("PROXY 192.168.1.150:8080; DIRECT"));
    }

    #[tokio::test]
    async fn test_create_web_router_mobileconfig() {
        let metrics = Arc::new(ProxyMetrics::new());
        let config = WebConfig::default();
        let router = create_web_router(metrics, config);

        let req = Request::builder()
            .uri("/supercell.mobileconfig")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-apple-aspen-config; charset=utf-8"
        );

        let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let text = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(text.contains("PayloadType"));
        assert!(text.contains("dns.comss.one"));
    }

    #[tokio::test]
    async fn test_create_web_router_404() {
        let metrics = Arc::new(ProxyMetrics::new());
        let config = WebConfig::default();
        let router = create_web_router(metrics, config);

        let req = Request::builder()
            .uri("/unknown-route")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
