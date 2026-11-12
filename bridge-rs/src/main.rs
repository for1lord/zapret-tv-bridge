use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use zapret_tv_bridge_rs::{menu, metrics, proxy, router, socks5};

/// Multi-threaded Tokio runtime configuration builder enforcing 4 worker threads
/// for minimal memory footprint (7-12 MB) on Windows IOCP.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_dir = get_base_dir();
    let args: Vec<String> = std::env::args().collect();

    // 1. Help & Version
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("Zapret TV & Mobile Bridge (Rust Core) v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // 2. Standalone subcommands
    if args.iter().any(|a| a == "--status") {
        menu::cmd_status(&base_dir);
        return Ok(());
    }
    if args.iter().any(|a| a == "--start") {
        menu::cmd_start(&base_dir);
        return Ok(());
    }
    if args.iter().any(|a| a == "--stop") {
        menu::cmd_stop(&base_dir);
        return Ok(());
    }
    if args.iter().any(|a| a == "--restart") {
        menu::cmd_restart(&base_dir);
        return Ok(());
    }
    if args.iter().any(|a| a == "--test") {
        menu::cmd_test();
        return Ok(());
    }
    if args.iter().any(|a| a == "--firewall") {
        menu::ensure_admin(&args);
        menu::cmd_firewall();
        return Ok(());
    }
    if args.iter().any(|a| a == "--fix-proxy") {
        menu::cmd_fix_proxy();
        return Ok(());
    }
    if args.iter().any(|a| a == "--optimize-browsers" || a == "--fix-browsers") {
        menu::cmd_optimize_browsers();
        return Ok(());
    }
    if args.iter().any(|a| a == "--parse-rules" || a == "--sync-rules") {
        menu::ensure_admin(&args);
        menu::cmd_sync_rules(&base_dir);
        return Ok(());
    }
    if args.iter().any(|a| a == "--startup-enable") {
        menu::ensure_admin(&args);
        menu::cmd_startup(true, &base_dir);
        return Ok(());
    }
    if args.iter().any(|a| a == "--startup-disable") {
        menu::ensure_admin(&args);
        menu::cmd_startup(false, &base_dir);
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|a| a == "--install-all") {
        menu::ensure_admin(&args);
        let strat = args.get(pos + 1).map(|s| s.as_str());
        menu::cmd_install_all(&base_dir, strat);
        return Ok(());
    }
    if args.iter().any(|a| a == "--remove-all") {
        menu::ensure_admin(&args);
        menu::cmd_remove_all(&base_dir);
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|a| a == "--install-strategy") {
        menu::ensure_admin(&args);
        let strat = args.get(pos + 1).map(|s| s.as_str());
        menu::cmd_install_strategy(&base_dir, strat);
        return Ok(());
    }
    if args.iter().any(|a| a == "--remove-service") {
        menu::ensure_admin(&args);
        menu::cmd_remove_strategy();
        return Ok(());
    }

    // 3. Interactive Menu Mode
    // Default when double-clicked in Windows Explorer or run without arguments in console
    let is_daemon = args.iter().any(|a| a == "--daemon");
    let is_foreground = args.iter().any(|a| a == "--server" || a == "--foreground");
    let explicit_menu = args.iter().any(|a| a == "--menu");

    if explicit_menu || (!is_daemon && !is_foreground && args.len() <= 1 && is_stdin_terminal()) {
        menu::ensure_admin(&["--menu".to_string()]);
        menu::run_interactive_menu(&base_dir);
        return Ok(());
    }

    // 4. Daemon or Foreground Server runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("bridge-worker")
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()?;

    let res = runtime.block_on(async_main(base_dir, is_daemon));
    if let Err(e) = res {
        eprintln!("\n[!] Ошибка запуска шлюза: {}", e);
        if !is_daemon && is_stdin_terminal() {
            menu::pause_exit();
        }
        std::process::exit(1);
    }

    Ok(())
}

fn is_stdin_terminal() -> bool {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> isize;
            fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
        }
        const STD_INPUT_HANDLE: u32 = -10i32 as u32;
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle == 0 || handle == -1 {
            return false;
        }
        let mut mode: u32 = 0;
        unsafe { GetConsoleMode(handle, &mut mode) != 0 }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

fn get_base_dir() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    if exe_dir.join("lists").exists() {
        exe_dir
    } else if exe_dir.join("..").join("lists").exists() {
        exe_dir.join("..")
    } else if exe_dir.join("..").join("..").join("lists").exists() {
        exe_dir.join("..").join("..")
    } else if PathBuf::from("d:\\projects\\zapret-tv-bridge\\lists").exists() {
        PathBuf::from("d:\\projects\\zapret-tv-bridge")
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }
}

fn print_help() {
    println!("Zapret TV & Mobile Bridge (Rust Native Core) v{}", env!("CARGO_PKG_VERSION"));
    println!("Usage: ZapretTVBridge [OPTIONS]\n");
    println!("Options:");
    println!("  --menu             Launch interactive console manager (default if double-clicked)");
    println!("  --daemon           Run silently as background daemon");
    println!("  --server           Run in foreground server mode");
    println!("  --status           Display bridge and service status");
    println!("  --start            Start background bridge daemon");
    println!("  --stop             Stop running bridge daemon");
    println!("  --restart          Restart running bridge daemon");
    println!("  --install-all [S]  Install Zapret service with strategy and start Bridge");
    println!("  --remove-all       Stop and remove Zapret service and Bridge");
    println!("  --startup-enable   Enable Windows Startup");
    println!("  --startup-disable  Disable Windows Startup");
    println!("  --firewall         Configure Windows Firewall rules");
    println!("  --fix-proxy        Reset Windows system proxy");
    println!("  --optimize-browsers Enable multi-threaded parallel downloading in Chromium browsers");
    println!("  --test             Run network latency and DNS tests");
    println!("  -h, --help         Print help information");
    println!("  -v, --version      Print version information\n");
    println!("Environment Variables:");
    println!("  BRIDGE_PROXY_ADDR  Universal proxy address (default: 0.0.0.0:8080)");
    println!("  BRIDGE_SOCKS5_ADDR Dedicated SOCKS5 address (default: 0.0.0.0:1080)");
    println!("  BRIDGE_TG_PORT     Telegram Gateway port (default: 1443)");
    println!("  BRIDGE_TG_SECRET   Hex secret (32, 34 with 'dd', or 34+domain with 'ee')");
}

struct PidCleanup {
    pid_file: PathBuf,
    ip_file: PathBuf,
    tg_pid_file: PathBuf,
    tg_port: u16,
    base_dir: PathBuf,
}

impl Drop for PidCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pid_file);
        let _ = std::fs::remove_file(&self.ip_file);
        let _ = std::fs::remove_file(&self.tg_pid_file);
        ensure_tg_port_free(self.tg_port, &self.base_dir);
    }
}

/// Discovers Python executable (pythonw.exe preferred for silent execution, fallback to python.exe).
fn find_python_binary() -> Option<PathBuf> {
    if let Ok(py) = std::env::var("BRIDGE_PYTHON_BIN") {
        let p = PathBuf::from(py);
        if p.exists() {
            return Some(p);
        }
    }

    for cmd_name in &["pythonw", "python"] {
        if let Ok(output) = std::process::Command::new("where.exe").arg(cmd_name).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let path = PathBuf::from(line.trim());
                    if path.exists() && !line.to_lowercase().contains("windowsapps") {
                        return Some(path);
                    }
                }
            }
        }
    }

    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let programs = PathBuf::from(local_appdata).join("Programs").join("Python");
        if programs.exists() {
            if let Ok(entries) = std::fs::read_dir(programs) {
                for entry in entries.flatten() {
                    let pw = entry.path().join("pythonw.exe");
                    if pw.exists() {
                        return Some(pw);
                    }
                    let p = entry.path().join("python.exe");
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }
    }

    None
}

/// Ensures Telegram proxy port (default: 1443) is free from previous/stale instances.
fn ensure_tg_port_free(port: u16, base_dir: &std::path::Path) {
    let tg_pid_file = base_dir.join("tg_proxy.pid");
    if tg_pid_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&tg_pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                #[cfg(windows)]
                {
                    let _ = std::process::Command::new("taskkill")
                        .args(&["/F", "/PID", &pid.to_string()])
                        .output();
                }
            }
        }
        let _ = std::fs::remove_file(&tg_pid_file);
    }

    #[cfg(windows)]
    {
        let ps_cmd = format!(
            "$pids = (Get-NetTCPConnection -LocalPort {} -State Listen -ErrorAction SilentlyContinue).OwningProcess; \
             foreach ($p in $pids) {{ Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }}",
            port
        );
        let _ = std::process::Command::new("powershell")
            .args(&["-NoProfile", "-Command", &ps_cmd])
            .output();
    }
}

async fn async_main(base_dir: PathBuf, is_daemon: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Automatically ensure Zapret service is started if installed
    menu::ensure_zapret_service_running();

    if !is_daemon {
        println!("=====================================================");
        println!("  Zapret TV & Mobile Bridge - Native Rust Core");
        println!("=====================================================");
        println!("[*] Base directory: {:?}", base_dir);
    }

    let router = Arc::new(router::SmartRouter::new(&base_dir));
    let metrics = Arc::new(metrics::ProxyMetrics::new());

    let http_addr: SocketAddr = std::env::var("BRIDGE_PROXY_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    let socks5_addr: SocketAddr = std::env::var("BRIDGE_SOCKS5_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:1080".to_string())
        .parse()?;

    let secret_file = base_dir.join("tg_secret.txt");
    let tg_secret_str = if let Ok(sec) = std::env::var("BRIDGE_TG_SECRET") {
        sec
    } else if secret_file.exists() {
        let content = std::fs::read_to_string(&secret_file).unwrap_or_default();
        let trimmed = content.trim().to_string();
        if trimmed.len() >= 32 {
            trimmed
        } else {
            let mut rnd = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rnd);
            let s = hex::encode(rnd);
            let _ = std::fs::write(&secret_file, &s);
            s
        }
    } else {
        let mut rnd = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rnd);
        let s = hex::encode(rnd);
        let _ = std::fs::write(&secret_file, &s);
        s
    };

    let (tg_secret, tg_masking) = zapret_tv_bridge_rs::faketls::parse_secret(&tg_secret_str)
        .unwrap_or_else(|_| {
            let mut rnd = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rnd);
            (rnd, None)
        });

    let tg_port: u16 = std::env::var("BRIDGE_TG_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1443);

    let tg_addr: SocketAddr = std::env::var("BRIDGE_TG_ADDR")
        .ok()
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], tg_port)));

    let start_time = std::time::Instant::now();
    let default_ip = zapret_tv_bridge_rs::pac::get_local_ip();

    // Register PID and IP files with RAII cleanup
    let pid_file = base_dir.join("tv_proxy.pid");
    let ip_file = base_dir.join("tv_proxy.ip");
    let tg_pid_file = base_dir.join("tg_proxy.pid");
    let _ = std::fs::write(&pid_file, std::process::id().to_string());
    let _ = std::fs::write(&ip_file, format!("{}:{}", default_ip, http_addr.port()));
    let _cleanup = PidCleanup {
        pid_file,
        ip_file,
        tg_pid_file: tg_pid_file.clone(),
        tg_port,
        base_dir: base_dir.clone(),
    };

    let clean_tg_secret_str = tg_secret_str.strip_prefix("dd").unwrap_or(&tg_secret_str);
    let clean_tg_secret_str = if clean_tg_secret_str.len() >= 32 {
        clean_tg_secret_str[..32].to_string()
    } else {
        clean_tg_secret_str.to_string()
    };

    let web_config = zapret_tv_bridge_rs::web::WebConfig::new(
        http_addr.port(),
        default_ip.clone(),
        base_dir.clone(),
        tg_port,
        clean_tg_secret_str.clone(),
        start_time,
    );
    let web_router = zapret_tv_bridge_rs::web::create_web_router(Arc::clone(&metrics), web_config);

    // 1. Universal listener on port 8080 (HTTP CONNECT + SOCKS5 via 1-byte peek + Web Server)
    let r1 = Arc::clone(&router);
    let m1 = Arc::clone(&metrics);
    let w1 = web_router.clone();
    let mut _http_handle = tokio::spawn(async move {
        if let Err(e) = proxy::run_proxy_listener_with_web(http_addr, r1, m1, w1).await {
            eprintln!("[Proxy] Universal autodetect listener notice on {http_addr}: {e}");
            Err(e)
        } else {
            Ok(())
        }
    });

    // 2. Dedicated SOCKS5 listener on port 1080
    let r2 = Arc::clone(&router);
    let m2 = Arc::clone(&metrics);
    let mut _socks5_handle = tokio::spawn(async move {
        if let Err(e) = socks5::run_socks5_listener(socks5_addr, r2, m2).await {
            eprintln!("[Proxy] Dedicated SOCKS5 listener notice on {socks5_addr}: {e}");
            Err(e)
        } else {
            Ok(())
        }
    });

    // 3. Telegram Proxy (Flowseal tg-ws-proxy WebSocket Bridge or internal FakeTLS fallback)
    let standalone_tg_candidates = [
        base_dir.join("bin").join("tgwsproxy.exe"),
        base_dir.join("tgwsproxy.exe"),
        base_dir.join("..").join("bin").join("tgwsproxy.exe"),
    ];
    let standalone_tg_exe = standalone_tg_candidates.into_iter().find(|p| p.is_file());

    let tg_proxy_dir = if base_dir.join("tg_ws_proxy").is_dir() {
        Some(base_dir.join("tg_ws_proxy"))
    } else if base_dir.join("..").join("tg_ws_proxy").is_dir() {
        Some(base_dir.join("..").join("tg_ws_proxy"))
    } else {
        None
    };
    let python_bin = find_python_binary();

    let mut _tg_handle = if let Some(exe_path) = standalone_tg_exe {
        ensure_tg_port_free(tg_port, &base_dir);

        let mut cmd = std::process::Command::new(&exe_path);
        cmd.args(&[
            "--host",
            "0.0.0.0",
            "--port",
            &tg_port.to_string(),
            "--secret",
            &clean_tg_secret_str,
            "--dc-ip",
            "2:149.154.167.220",
            "--dc-ip",
            "4:149.154.167.220",
        ]);
        let tg_log_path = base_dir.join("tg_proxy.log");
        if let Some(s) = tg_log_path.to_str() {
            cmd.args(&["--log-file", s]);
        }
        cmd.current_dir(&base_dir);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let c_pid = child.id();
                let _ = std::fs::write(&tg_pid_file, c_pid.to_string());
                if !is_daemon {
                    println!(
                        "[*] Telegram WS Proxy (tgwsproxy standalone) запущен на 0.0.0.0:{} [PID: {}]",
                        tg_port, c_pid
                    );
                }
                let pid_file_copy = tg_pid_file.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                eprintln!("[TgWsProxy] Telegram proxy process exited with status: {:?}", status);
                                let _ = std::fs::remove_file(&pid_file_copy);
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "tgwsproxy process exited",
                                ));
                            }
                            Ok(None) => {}
                            Err(e) => {
                                let _ = std::fs::remove_file(&pid_file_copy);
                                return Err(e);
                            }
                        }
                    }
                })
            }
            Err(e) => {
                eprintln!("[TgWsProxy] Failed to spawn standalone tgwsproxy via {:?}: {}", exe_path, e);
                let tg_config = zapret_tv_bridge_rs::faketls::TgGatewayConfig::new(
                    tg_addr,
                    tg_secret,
                    tg_masking.or_else(|| std::env::var("BRIDGE_TG_MASKING").ok()),
                );
                let m3 = Arc::clone(&metrics);
                tokio::spawn(async move {
                    if let Err(e) = zapret_tv_bridge_rs::faketls::run_tg_gateway(tg_config, m3).await {
                        eprintln!("[TgGateway] FakeTLS listener notice on {tg_addr}: {e}");
                        Err(e)
                    } else {
                        Ok(())
                    }
                })
            }
        }
    } else if let (Some(tg_dir), Some(py_bin)) = (tg_proxy_dir, python_bin) {
        ensure_tg_port_free(tg_port, &base_dir);

        let mut cmd = std::process::Command::new(&py_bin);
        cmd.args(&[
            "-m",
            "proxy.tg_ws_proxy",
            "--host",
            "0.0.0.0",
            "--port",
            &tg_port.to_string(),
            "--secret",
            &clean_tg_secret_str,
            "--dc-ip",
            "2:149.154.167.220",
            "--dc-ip",
            "4:149.154.167.220",
        ]);
        let tg_log_path = base_dir.join("tg_proxy.log");
        if let Some(s) = tg_log_path.to_str() {
            cmd.args(&["--log-file", s]);
        }
        cmd.current_dir(&tg_dir);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let c_pid = child.id();
                let _ = std::fs::write(&tg_pid_file, c_pid.to_string());
                if !is_daemon {
                    println!(
                        "[*] Telegram WS Proxy (tgwsproxy python) запущен на 0.0.0.0:{} [PID: {}]",
                        tg_port, c_pid
                    );
                }
                let pid_file_copy = tg_pid_file.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                eprintln!("[TgWsProxy] Telegram proxy process exited with status: {:?}", status);
                                let _ = std::fs::remove_file(&pid_file_copy);
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "tgwsproxy process exited",
                                ));
                            }
                            Ok(None) => {}
                            Err(e) => {
                                let _ = std::fs::remove_file(&pid_file_copy);
                                return Err(e);
                            }
                        }
                    }
                })
            }
            Err(e) => {
                eprintln!("[TgWsProxy] Failed to spawn tgwsproxy via {:?}: {}", py_bin, e);
                let tg_config = zapret_tv_bridge_rs::faketls::TgGatewayConfig::new(
                    tg_addr,
                    tg_secret,
                    tg_masking.or_else(|| std::env::var("BRIDGE_TG_MASKING").ok()),
                );
                let m3 = Arc::clone(&metrics);
                tokio::spawn(async move {
                    if let Err(e) = zapret_tv_bridge_rs::faketls::run_tg_gateway(tg_config, m3).await {
                        eprintln!("[TgGateway] FakeTLS listener notice on {tg_addr}: {e}");
                        Err(e)
                    } else {
                        Ok(())
                    }
                })
            }
        }
    } else {
        let tg_config = zapret_tv_bridge_rs::faketls::TgGatewayConfig::new(
            tg_addr,
            tg_secret,
            tg_masking.or_else(|| std::env::var("BRIDGE_TG_MASKING").ok()),
        );
        let m3 = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(e) = zapret_tv_bridge_rs::faketls::run_tg_gateway(tg_config, m3).await {
                eprintln!("[TgGateway] FakeTLS listener notice on {tg_addr}: {e}");
                Err(e)
            } else {
                Ok(())
            }
        })
    };

    if !is_daemon {
        println!("[*] Ready for 4K video streaming, low-latency proxying, and Telegram MTProto Gateway.");
        println!(
            "[*] Autodetect proxy: {}, Dedicated SOCKS5: {}, TG Gateway: 0.0.0.0:{}",
            http_addr, socks5_addr, tg_port
        );
    }

    // Coordinated execution with startup fault detection and clean listener abort
    if is_daemon {
        tokio::select! {
            res = &mut _http_handle => {
                let _ = res;
                std::process::exit(1);
            }
            res = &mut _socks5_handle => {
                let _ = res;
                std::process::exit(1);
            }
            res = &mut _tg_handle => {
                let _ = res;
                std::process::exit(1);
            }
            _ = std::future::pending::<()>() => {}
        }
    } else {
        tokio::select! {
            res = &mut _http_handle => {
                eprintln!("\n[!] Ошибка: Порт {} занят или недоступен: {:?}", http_addr, res);
                eprintln!("    Возможно, служба шлюза уже запущена в фоновом режиме.");
                eprintln!("    Используйте: ZapretTVBridge.exe --status или ZapretTVBridge.exe --restart");
                if is_stdin_terminal() {
                    menu::pause_exit();
                }
                std::process::exit(1);
            }
            res = &mut _socks5_handle => {
                eprintln!("\n[!] Ошибка: Порт SOCKS5 {} недоступен: {:?}", socks5_addr, res);
                if is_stdin_terminal() {
                    menu::pause_exit();
                }
                std::process::exit(1);
            }
            res = &mut _tg_handle => {
                eprintln!("\n[!] Ошибка: Служба Telegram (tgwsproxy) на порту {} завершилась: {:?}", tg_port, res);
                eprintln!("    Возможно, порт занят другой копией службы.");
                eprintln!("    Используйте: ZapretTVBridge.exe --restart");
                if is_stdin_terminal() {
                    menu::pause_exit();
                }
                std::process::exit(1);
            }
            sig = tokio::signal::ctrl_c() => {
                if let Err(e) = sig {
                    eprintln!("[Warning] Error awaiting Ctrl+C signal: {e}");
                }
                println!("\n[*] Сигнал остановки получен. Завершение сессий...");
            }
        }
    }

    // Immediately abort listener tasks so no new connections are accepted during drain
    _http_handle.abort();
    _socks5_handle.abort();
    _tg_handle.abort();

    ensure_tg_port_free(tg_port, &base_dir);

    let drain_start = std::time::Instant::now();
    let drain_timeout = std::time::Duration::from_secs(3);
    while metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed) > 0
        && drain_start.elapsed() < drain_timeout
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    if !is_daemon {
        println!("[*] Служба остановлена.");
    }
    Ok(())
}
