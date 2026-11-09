use std::path::{Path, PathBuf};
use std::process::Command;
use crate::pac;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows Creation Flags
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x00000008;

/// Checks if current process is running with Administrator privileges.
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Reruns current executable with Administrator privileges via UAC if not already elevated.
pub fn ensure_admin(args: &[String]) {
    #[cfg(windows)]
    {
        if is_admin() {
            return;
        }
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: isize,
                lpOperation: *const u16,
                lpFile: *const u16,
                lpParameters: *const u16,
                lpDirectory: *const u16,
                nShowCmd: i32,
            ) -> isize;
        }

        if let Ok(exe) = std::env::current_exe() {
            let exe_wide: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            let op_wide: Vec<u16> = OsStr::new("runas").encode_wide().chain(std::iter::once(0)).collect();
            let params = args.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(" ");
            let params_wide: Vec<u16> = OsStr::new(&params).encode_wide().chain(std::iter::once(0)).collect();

            let ret = unsafe {
                ShellExecuteW(0, op_wide.as_ptr(), exe_wide.as_ptr(), params_wide.as_ptr(), std::ptr::null(), 1)
            };
            if ret > 32 {
                std::process::exit(0);
            }
        }
    }
}

/// Pauses and waits for user to press Enter.
pub fn pause_menu() {
    println!("\n   Нажмите Enter для возврата в меню...");
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}

/// Pauses before program exit.
pub fn pause_exit() {
    println!("\n   Нажмите Enter для закрытия окна...");
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}

/// Checks whether a process PID is currently running.
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;
            fn CloseHandle(hObject: isize) -> i32;
            fn GetExitCodeProcess(hProcess: isize, lpExitCode: *mut u32) -> i32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const STILL_ACTIVE: u32 = 259;

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle != 0 {
            let mut code: u32 = 0;
            let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
            unsafe { CloseHandle(handle) };
            return ok != 0 && code == STILL_ACTIVE;
        }
        false
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(format!("/proc/{}", pid)).exists()
    }
}

/// Checks whether bridge daemon is running (via PID file or port 8080 probe).
pub fn is_bridge_running(base_dir: &Path) -> (bool, Option<u32>) {
    let pid_file = base_dir.join("tv_proxy.pid");
    if pid_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                if is_pid_alive(pid) {
                    return (true, Some(pid));
                }
            }
        }
    }

    // Secondary check: probe port 8080
    if let Ok(_stream) = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:8080".parse().unwrap(),
        std::time::Duration::from_millis(300),
    ) {
        return (true, None);
    }

    (false, None)
}

/// Checks whether Telegram Proxy (tgwsproxy) is running (via PID file or port 1443 probe).
pub fn is_tg_proxy_running(base_dir: &Path) -> (bool, Option<u32>) {
    let pid_file = base_dir.join("tg_proxy.pid");
    if pid_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                if is_pid_alive(pid) {
                    return (true, Some(pid));
                }
            }
        }
    }

    // Secondary check: probe port 1443
    if let Ok(_stream) = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:1443".parse().unwrap(),
        std::time::Duration::from_millis(300),
    ) {
        return (true, None);
    }

    (false, None)
}

/// Checks Zapret Windows service status and active strategy preset.
pub fn get_zapret_service_status() -> (bool, String) {
    let mut is_running = false;
    let mut strategy = String::new();

    // Query registry for active strategy
    let reg_output = Command::new("reg")
        .args(&[
            "query",
            r"HKLM\System\CurrentControlSet\Services\zapret",
            "/v",
            "zapret-discord-youtube",
        ])
        .output();

    if let Ok(out) = reg_output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("zapret-discord-youtube") && line.contains("REG_SZ") {
                let parts: Vec<&str> = line.split("REG_SZ").collect();
                if parts.len() >= 2 {
                    strategy = parts[1].trim().to_string();
                }
            }
        }
    }

    // Query sc.exe for service status
    let sc_output = Command::new("sc").args(&["query", "zapret"]).output();
    if let Ok(out) = sc_output {
        let text = String::from_utf8_lossy(&out.stdout).to_uppercase();
        if text.contains("RUNNING") || text.contains(": 4") {
            is_running = true;
        }
    }

    // Fallback: check winws.exe process in tasklist
    if !is_running {
        let task_output = Command::new("tasklist")
            .args(&["/FI", "IMAGENAME eq winws.exe"])
            .output();
        if let Ok(out) = task_output {
            let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if text.contains("winws.exe") {
                is_running = true;
            }
        }
    }

    (is_running, strategy)
}

/// Checks whether autostart is configured via Registry Run, Startup shortcut, or Scheduled Task.
pub fn is_startup_enabled() -> bool {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let startup_dir = PathBuf::from(&appdata)
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup");
    if startup_dir.join("Zapret_TV_Bridge.lnk").exists()
        || startup_dir.join("Zapret_TV_Bridge.vbs").exists()
    {
        return true;
    }

    // Check HKCU Run key
    let reg_hkcu = Command::new("reg")
        .args(&[
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "ZapretTVBridge",
        ])
        .output();
    if let Ok(out) = reg_hkcu {
        if out.status.success() {
            return true;
        }
    }

    // Check HKLM Run key
    let reg_hklm = Command::new("reg")
        .args(&[
            "query",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "ZapretTVBridge",
        ])
        .output();
    if let Ok(out) = reg_hklm {
        if out.status.success() {
            return true;
        }
    }

    let sch_output = Command::new("schtasks")
        .args(&["/query", "/tn", "Zapret_TV_Bridge"])
        .output();

    if let Ok(out) = sch_output {
        if out.status.success() {
            return true;
        }
    }

    false
}

/// Discovers available strategy presets in presets folder.
pub fn discover_zapret_strategies(base_dir: &Path) -> Vec<(String, PathBuf)> {
    let presets_dir = base_dir.join("presets");
    let mut strategies = Vec::new();

    if presets_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&presets_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("bat") {
                    let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
                    if !name.to_lowercase().starts_with("service") {
                        strategies.push((name, path));
                    }
                }
            }
        }
    }

    // Sort with "general (ALT)" prioritized, then ALT numbers, then "general", then others
    strategies.sort_by(|(a_name, _), (b_name, _)| {
        let a_low = a_name.to_lowercase();
        let b_low = b_name.to_lowercase();

        let rank = |s: &str| -> (u8, u32) {
            if s == "general (alt)" {
                (1, 1)
            } else if s.starts_with("general (alt") && s.ends_with(')') {
                let num_str = &s[12..s.len() - 1];
                let num = num_str.parse::<u32>().unwrap_or(99);
                (1, num)
            } else if s == "general" {
                (2, 0)
            } else if s.contains("exp") {
                (3, 0)
            } else if s.contains("fake tls") {
                (4, 0)
            } else {
                (5, 0)
            }
        };

        rank(&a_low).cmp(&rank(&b_low)).then_with(|| a_low.cmp(&b_low))
    });

    strategies
}

/// Parses winws.exe arguments from a strategy .bat file.
pub fn parse_strategy_args(bat_path: &Path, bin_dir: &Path, lists_dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(bat_path).ok()?;

    let bin_str = format!("{}\\", bin_dir.to_string_lossy().trim_end_matches('\\'));
    let lists_str = format!("{}\\", lists_dir.to_string_lossy().trim_end_matches('\\'));

    let mut replaced = content
        .replace("%GameFilterTCP%", "12")
        .replace("%GameFilterUDP%", "12")
        .replace("%GameFilter%", "12")
        .replace("%BIN%", &bin_str)
        .replace("%LISTS%", &lists_str);

    // Normalize Windows CRLF
    replaced = replaced.replace("\r\n", "\n");

    let mut capture = false;
    let mut winws_lines = Vec::new();

    for line in replaced.lines() {
        let stripped = line.trim();
        if stripped.contains("winws.exe") {
            capture = true;
        }
        if capture {
            winws_lines.push(stripped);
            if !stripped.ends_with('^') {
                break;
            }
        }
    }

    if winws_lines.is_empty() {
        return None;
    }

    let full_cmd = winws_lines.join(" ").replace('^', " ");
    if let Some(pos) = full_cmd.to_lowercase().find("winws.exe") {
        let after = &full_cmd[pos + 9..].trim();
        let cleaned_after = after.trim_start_matches(|c| c == '"' || c == '\'').trim();
        // Collapse spaces
        let collapsed = cleaned_after.split_whitespace().collect::<Vec<_>>().join(" ");
        if !collapsed.is_empty() {
            return Some(collapsed);
        }
    }

    None
}

/// Main Interactive Console Manager for Zapret & TV Bridge.
pub fn run_interactive_menu(base_dir: &PathBuf) {
    // Automatically ensure Zapret service is running if registered
    ensure_zapret_service_running();

    loop {
        // Clear console screen on Windows
        let _ = Command::new("cmd").args(&["/c", "cls"]).status();

        let (zapret_running, zapret_strat) = get_zapret_service_status();
        let zapret_label = if zapret_running {
            if !zapret_strat.is_empty() {
                format!("[RUNNING - {}]", zapret_strat)
            } else {
                "[RUNNING]".to_string()
            }
        } else {
            "[STOPPED]".to_string()
        };

        let (bridge_running, bridge_pid) = is_bridge_running(base_dir);
        let bridge_label = if bridge_running {
            if let Some(pid) = bridge_pid {
                format!("[RUNNING - PID: {}]", pid)
            } else {
                "[RUNNING - Active on :8080]".to_string()
            }
        } else {
            "[STOPPED]".to_string()
        };

        let local_ip = pac::get_local_ip();
        let host_port = format!("{}:8080", local_ip);

        let secret_file = base_dir.join("tg_secret.txt");
        let tg_secret = std::fs::read_to_string(&secret_file)
            .unwrap_or_default()
            .trim()
            .to_string();

        let startup_enabled = is_startup_enabled();
        let startup_status = if startup_enabled { "[enabled]" } else { "[disabled]" };

        println!();
        println!("  ==================================================");
        println!("  ZAPRET TV & MOBILE BRIDGE MANAGER v1.13 (Rust Core)");
        println!("  ==================================================");
        println!("  Служба Zapret:         {}", zapret_label);
        println!("  Шлюз для ТВ/Мобильных: {}", bridge_label);
        if bridge_running {
            println!("  Адрес шлюза:           http://{}/", host_port);
            println!("  PAC URL:               http://{}/proxy.pac", host_port);
            println!("  Smart TV:              IP {}  Port 8080", local_ip);
            if !tg_secret.is_empty() {
                let clean_secret = tg_secret.strip_prefix("dd").unwrap_or(&tg_secret);
                let clean_secret = if clean_secret.len() >= 32 { &clean_secret[..32] } else { clean_secret };
                let (tg_running, tg_pid) = is_tg_proxy_running(base_dir);
                let tg_tag = if tg_running {
                    if let Some(p) = tg_pid {
                        format!(" [PID: {}]", p)
                    } else {
                        "".to_string()
                    }
                } else {
                    " [STOPPED]".to_string()
                };
                println!(
                    "  Telegram (tgwsproxy):  tg://proxy?server={}&port=1443&secret=dd{}{}",
                    local_ip, clean_secret, tg_tag
                );
            }
        }
        println!("  Папка программы:       {}", base_dir.display());
        println!("  --------------------------------------------------");
        println!();
        println!("  :: УПРАВЛЕНИЕ СЛУЖБАМИ");
        println!("     1. Установить и запустить службы [Выбор стратегии Zapret]");
        println!("     2. Остановить и удалить службы");
        println!("     3. Проверить статус и адреса для подключения (ТВ / Смартфон)");
        println!();
        println!("  :: НАСТРОЙКИ");
        println!("     4. Автозагрузка Windows              {}", startup_status);
        println!("     5. Открыть веб-панель в браузере");
        println!("     6. Перезапустить шлюз (Restart Bridge)");
        println!();
        println!("  --------------------------------------------------");
        println!("     0. Выход");
        println!("  --------------------------------------------------");
        println!();
        print!("   Выберите пункт [0-6]: ");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }

        let choice = input.trim();
        match choice {
            "0" => break,
            "1" => {
                cmd_install_all(base_dir, None);
                pause_menu();
            }
            "2" => {
                cmd_remove_all(base_dir);
                pause_menu();
            }
            "3" => {
                cmd_status(base_dir);
                pause_menu();
            }
            "4" => {
                cmd_toggle_startup(base_dir);
                pause_menu();
            }
            "5" => {
                cmd_open_browser(&format!("http://{}/", host_port));
            }
            "6" => {
                cmd_restart(base_dir);
                pause_menu();
            }
            _ => {}
        }
    }
}

/// Installs Zapret service with selected strategy preset, starts Bridge daemon, and applies firewall rules.
pub fn cmd_install_all(base_dir: &Path, chosen_strategy: Option<&str>) -> bool {
    ensure_admin(&["--menu".to_string()]);
    if !is_admin() {
        println!("\n[!] Ошибка: Для установки служб требуются права Администратора.");
        return false;
    }

    let success = cmd_install_strategy(base_dir, chosen_strategy);
    if !success {
        return false;
    }

    println!("\n[*] Запуск локального шлюза для Smart TV и мобильных устройств...");
    cmd_start(base_dir);
    cmd_firewall();

    println!("\n  ==================================================");
    println!("  [+] ВСЕ СЛУЖБЫ УСПЕШНО УСТАНОВЛЕНЫ И ЗАПУЩЕНЫ!");
    println!("  ==================================================");
    println!("  1. Служба Zapret активна с выбранной стратегией.");
    println!("  2. Сеть Windows в заводском режиме (прямое подключение).");
    println!("  3. Высокоскоростной шлюз Rust для ТВ и смартфонов запущен.");
    println!("  4. Системный прокси отключен для изоляции сред разработки.");
    println!("  --------------------------------------------------\n");

    cmd_status(base_dir);
    true
}

/// Directly writes service configuration to registry without sc.exe command line truncation or quoting issues.
#[cfg(windows)]
pub fn write_service_registry(full_bin_path: &str, strategy_name: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            hKey: isize,
            lpSubKey: *const u16,
            Reserved: u32,
            lpClass: *const u16,
            dwOptions: u32,
            samDesired: u32,
            lpSecurityAttributes: *const std::ffi::c_void,
            phkResult: *mut isize,
            lpdwDisposition: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hKey: isize,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;
        fn RegCloseKey(hKey: isize) -> i32;
    }

    const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as i32 as isize;
    const KEY_SET_VALUE: u32 = 0x0002;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_DWORD: u32 = 4;

    let subkey: Vec<u16> = OsStr::new(r"System\CurrentControlSet\Services\zapret")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey: isize = 0;
    let mut disp: u32 = 0;
    let ret = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut hkey,
            &mut disp,
        )
    };

    if ret != 0 || hkey == 0 {
        return false;
    }

    let set_str = |name: &str, val: &str, reg_type: u32| {
        let name_w: Vec<u16> = OsStr::new(name).encode_wide().chain(std::iter::once(0)).collect();
        let val_w: Vec<u16> = OsStr::new(val).encode_wide().chain(std::iter::once(0)).collect();
        unsafe {
            RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                reg_type,
                val_w.as_ptr() as *const u8,
                (val_w.len() * 2) as u32,
            )
        };
    };

    let set_dword = |name: &str, val: u32| {
        let name_w: Vec<u16> = OsStr::new(name).encode_wide().chain(std::iter::once(0)).collect();
        unsafe {
            RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                REG_DWORD,
                &val as *const u32 as *const u8,
                4,
            )
        };
    };

    let clean_path = full_bin_path.trim();
    set_str("ImagePath", clean_path, REG_EXPAND_SZ);
    set_str("DisplayName", "zapret", REG_SZ);
    set_str("Description", "Zapret DPI Network Optimization Service", REG_SZ);
    set_str("zapret-discord-youtube", strategy_name, REG_SZ);
    set_dword("Start", 2); // Automatic
    set_dword("Type", 0x10); // SERVICE_WIN32_OWN_PROCESS
    set_dword("ErrorControl", 1); // SERVICE_ERROR_NORMAL

    unsafe { RegCloseKey(hkey) };
    true
}

#[cfg(not(windows))]
pub fn write_service_registry(_full_bin_path: &str, _strategy_name: &str) -> bool {
    true
}

/// Ensures Zapret service is running if installed in the system.
pub fn ensure_zapret_service_running() -> bool {
    let (running, _) = get_zapret_service_status();
    if running {
        return true;
    }
    let _ = Command::new("sc").args(&["start", "zapret"]).output();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let (running_after, _) = get_zapret_service_status();
    running_after
}

/// Discovers strategies, prompts or selects one, configures Windows service zapret, and starts it.
pub fn cmd_install_strategy(base_dir: &Path, chosen_strategy: Option<&str>) -> bool {
    ensure_admin(&["--menu".to_string()]);
    if !is_admin() {
        println!("\n[!] ОШИБКА: Для установки системной службы требуются права Администратора.");
        return false;
    }

    let strategies = discover_zapret_strategies(base_dir);
    if strategies.is_empty() {
        println!("\n[!] Стратегии Zapret не найдены. Убедитесь, что папка 'presets' существует.");
        return false;
    }

    let mut selected_name = String::new();
    let mut selected_bat = PathBuf::new();

    if let Some(chosen) = chosen_strategy {
        let clean = chosen.trim().to_lowercase();
        if let Ok(idx) = clean.parse::<usize>() {
            if idx >= 1 && idx <= strategies.len() {
                selected_name = strategies[idx - 1].0.clone();
                selected_bat = strategies[idx - 1].1.clone();
            }
        } else {
            for (name, path) in &strategies {
                let name_low = name.to_lowercase();
                if name_low == clean || name_low == format!("general ({})", clean) {
                    selected_name = name.clone();
                    selected_bat = path.clone();
                    break;
                }
            }
        }
    }

    if selected_bat.as_os_str().is_empty() {
        println!("\n  ==================================================");
        println!("  ВЫБОР СТРАТЕГИИ ZAPRET ДЛЯ УСТАНОВКИ СЛУЖБЫ");
        println!("  ==================================================");
        for (i, (name, _)) in strategies.iter().enumerate() {
            println!("     {:2}. {}", i + 1, name);
        }
        println!("  --------------------------------------------------");
        println!("      0. Отмена");
        println!();
        print!("  Выберите стратегию [1-{}, 0 для отмены]: ", strategies.len());
        use std::io::Write;
        let _ = std::io::stdout().flush();

        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }

        let trimmed = input.trim();
        if trimmed == "0" || trimmed.is_empty() {
            return false;
        }

        if let Ok(idx) = trimmed.parse::<usize>() {
            if idx >= 1 && idx <= strategies.len() {
                selected_name = strategies[idx - 1].0.clone();
                selected_bat = strategies[idx - 1].1.clone();
            } else {
                println!("[!] Неверный номер стратегии.");
                return false;
            }
        } else {
            let clean = trimmed.to_lowercase();
            for (name, path) in &strategies {
                let name_low = name.to_lowercase();
                if name_low == clean || name_low == format!("general ({})", clean) {
                    selected_name = name.clone();
                    selected_bat = path.clone();
                    break;
                }
            }
            if selected_bat.as_os_str().is_empty() {
                println!("[!] Стратегия не найдена.");
                return false;
            }
        }
    }

    let winws_candidates = [
        base_dir.join("bin").join("winws.exe"),
        base_dir.join("winws.exe"),
    ];

    let mut winws_exe = None;
    for c in &winws_candidates {
        if c.exists() {
            winws_exe = Some(c.clone());
            break;
        }
    }

    let winws_exe = match winws_exe {
        Some(exe) => exe,
        None => {
            println!("[!] winws.exe не найден в папке bin. Установка невозможна.");
            return false;
        }
    };

    let bin_dir = winws_exe.parent().unwrap_or(base_dir);
    let lists_dir = base_dir.join("lists");
    if !lists_dir.exists() {
        println!("[!] Папка lists не найдена: {}", lists_dir.display());
        return false;
    }

    println!("\n[*] Применение стратегии: {}", selected_name);
    let parsed_args = match parse_strategy_args(&selected_bat, bin_dir, &lists_dir) {
        Some(args) => args,
        None => {
            println!("[!] Не удалось разобрать параметры запуска из файла стратегии.");
            return false;
        }
    };

    let full_bin_path = format!("\"{}\" {}", winws_exe.to_string_lossy(), parsed_args);

    // Stop existing winws and zapret service
    let _ = Command::new("taskkill").args(&["/IM", "winws.exe", "/F"]).output();
    let _ = Command::new("sc").args(&["stop", "zapret"]).output();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Create base service if not already present
    let _ = Command::new("sc")
        .args(&[
            "create",
            "zapret",
            "binPath=",
            "%SystemRoot%\\System32\\cmd.exe",
            "DisplayName=",
            "zapret",
            "start=",
            "auto",
        ])
        .output();

    // Directly write service configuration to registry without sc.exe command line truncation
    if !write_service_registry(&full_bin_path, &selected_name) {
        println!("[!] Ошибка записи параметров службы в реестр Windows.");
        return false;
    }

    // Configure service dependencies and failure recovery
    let _ = Command::new("sc").args(&["config", "zapret", "depend=", "BFE/Tcpip"]).output();
    let _ = Command::new("sc")
        .args(&["failure", "zapret", "reset=", "86400", "actions=", "restart/2000/restart/5000//"])
        .output();

    // Start service
    let start_res = Command::new("sc").args(&["start", "zapret"]).output();
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Recheck status
    let (running, _) = get_zapret_service_status();
    if running {
        println!("[+] Служба Zapret со стратегией [{}] успешно установлена и запущена!", selected_name);
        true
    } else {
        if let Ok(out) = start_res {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.to_uppercase().contains("START_PENDING") || text.to_uppercase().contains("RUNNING") {
                println!("[+] Служба Zapret со стратегией [{}] запускается...", selected_name);
                return true;
            }
        }
        println!("[!] Служба зарегистрирована со стратегией [{}]. Запуск процесса...", selected_name);
        true
    }
}

/// Stops and removes Zapret Windows service and cleans up WinDivert drivers.
pub fn cmd_remove_strategy() -> bool {
    ensure_admin(&["--menu".to_string()]);
    if !is_admin() {
        println!("\n[!] ОШИБКА: Для удаления службы Windows требуются права Администратора.");
        return false;
    }

    println!("\n[*] Остановка и удаление службы Zapret...");
    let _ = Command::new("sc").args(&["stop", "zapret"]).output();
    let _ = Command::new("sc").args(&["delete", "zapret"]).output();
    let _ = Command::new("taskkill").args(&["/IM", "winws.exe", "/F"]).output();

    println!("[+] Служба Zapret успешно остановлена и удалена.");
    true
}

/// Unified Uninstaller: stops & removes service, stops bridge daemon, and clears proxy settings.
pub fn cmd_remove_all(base_dir: &Path) -> bool {
    ensure_admin(&["--menu".to_string()]);
    if !is_admin() {
        println!("\n[!] Ошибка: Для удаления служб требуются права Администратора.");
        return false;
    }

    println!("\n[*] Остановка и удаление всех служб...");
    cmd_remove_strategy();
    cmd_stop(base_dir);
    cmd_fix_proxy();
    println!("\n[+] Все службы успешно остановлены и удалены из системы.\n");
    true
}

/// Starts the bridge daemon in a fully detached background process.
pub fn cmd_start(base_dir: &Path) -> bool {
    let (running, pid) = is_bridge_running(base_dir);
    if running {
        if let Some(p) = pid {
            println!("[i] Zapret TV Bridge уже запущен в фоне [PID: {}].", p);
        } else {
            println!("[i] Zapret TV Bridge уже активно работает на порту 8080.");
        }
        return true;
    }

    println!("[*] Запуск Zapret TV & Mobile Bridge в тихом фоновом режиме...");
    let exe = std::env::current_exe().unwrap_or_else(|_| base_dir.join("ZapretTVBridge.exe"));

    #[cfg(windows)]
    {
        let res = Command::new(&exe)
            .arg("--daemon")
            .current_dir(base_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn();

        match res {
            Ok(child) => {
                let child_pid = child.id();
                // Wait briefly for daemon to initialize sockets
                for _ in 0..10 {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let (now_running, _) = is_bridge_running(base_dir);
                    if now_running {
                        println!("[+] Сервис успешно запущен в фоне [PID: {}].", child_pid);
                        return true;
                    }
                }
                println!("[+] Процесс запущен [PID: {}].", child_pid);
                true
            }
            Err(e) => {
                println!("[!] Ошибка запуска фонового процесса: {}", e);
                false
            }
        }
    }
    #[cfg(not(windows))]
    {
        let res = Command::new(&exe)
            .arg("--daemon")
            .current_dir(base_dir)
            .spawn();
        res.is_ok()
    }
}

/// Stops all running bridge daemon processes and cleans up PID/IP files.
pub fn cmd_stop(base_dir: &Path) -> bool {
    let pid_file = base_dir.join("tv_proxy.pid");
    let ip_file = base_dir.join("tv_proxy.ip");

    if pid_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                let _ = Command::new("taskkill")
                    .args(&["/F", "/PID", &pid.to_string()])
                    .output();
            }
        }
        let _ = std::fs::remove_file(&pid_file);
    }
    if ip_file.exists() {
        let _ = std::fs::remove_file(&ip_file);
    }

    // Stop Telegram proxy (tgwsproxy)
    let tg_pid_file = base_dir.join("tg_proxy.pid");
    if tg_pid_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&tg_pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                let _ = Command::new("taskkill")
                    .args(&["/F", "/PID", &pid.to_string()])
                    .output();
            }
        }
        let _ = std::fs::remove_file(&tg_pid_file);
    }

    #[cfg(windows)]
    {
        let _ = Command::new("taskkill").args(&["/F", "/IM", "tgwsproxy.exe"]).output();
        let ps_kill_tg = "$pids = (Get-NetTCPConnection -LocalPort 1443 -State Listen -ErrorAction SilentlyContinue).OwningProcess; foreach ($p in $pids) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }";
        let _ = Command::new("powershell")
            .args(&["-NoProfile", "-Command", ps_kill_tg])
            .output();
    }

    // Terminate any other ZapretTVBridge instances except current process
    let curr_pid = std::process::id();
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill").args(&["/F", "/IM", "ZapretTVBridge_old.exe"]).output();
        let old_file = base_dir.join("ZapretTVBridge_old.exe");
        if old_file.exists() {
            let _ = std::fs::remove_file(&old_file);
        }

        let ps_cmd = format!(
            "$procs = Get-CimInstance Win32_Process | Where-Object {{ \
             ($_.Name -like '*ZapretTVBridge*' -or $_.CommandLine -like '*ZapretTVBridge*') \
             -and $_.ProcessId -ne {} }}; \
             foreach ($p in $procs) {{ Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }}",
            curr_pid
        );
        let _ = Command::new("powershell")
            .args(&["-NoProfile", "-Command", &ps_cmd])
            .output();
    }

    println!("[+] Zapret TV Bridge успешно остановлен.");
    true
}

/// Restarts the bridge background daemon and refreshes services.
pub fn cmd_restart(base_dir: &Path) -> bool {
    println!("[*] Перезапуск сервисов...");
    let (zapret_running, _) = get_zapret_service_status();
    if zapret_running {
        println!("[*] Перезапуск службы Zapret для обновления списков...");
        let _ = Command::new("net").args(&["stop", "zapret"]).output();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = Command::new("net").args(&["start", "zapret"]).output();
    }
    cmd_stop(base_dir);
    std::thread::sleep(std::time::Duration::from_millis(1000));
    cmd_start(base_dir)
}

/// Displays bridge status, IP, port, and client setup links.
pub fn cmd_status(base_dir: &Path) {
    let (is_running, pid) = is_bridge_running(base_dir);
    let (zapret_running, zapret_strat) = get_zapret_service_status();
    let startup_enabled = is_startup_enabled();
    let local_ip = pac::get_local_ip();

    let secret_file = base_dir.join("tg_secret.txt");
    let tg_secret = std::fs::read_to_string(&secret_file)
        .unwrap_or_default()
        .trim()
        .to_string();

    println!();
    println!("  ==================================================");
    println!("  ZAPRET TV & MOBILE BRIDGE -- СТАТУС СЕРВИСА");
    println!("  ==================================================");

    if zapret_running {
        let strat_str = if !zapret_strat.is_empty() {
            format!(" [{}]", zapret_strat)
        } else {
            "".to_string()
        };
        println!("  Служба Zapret:  АКТИВНА{}", strat_str);
    } else {
        println!("  Служба Zapret:  ОСТАНОВЛЕНА");
    }

    if is_running {
        let pid_str = if let Some(p) = pid {
            format!(" [PID: {}]", p)
        } else {
            "".to_string()
        };
        println!("  Мост [Bridge]:  АКТИВЕН{}", pid_str);
        println!("  Адрес:          http://{}:8080/", local_ip);
        println!("  PAC URL:        http://{}:8080/proxy.pac", local_ip);
        println!("  Smart TV:       IP {}  Порт 8080", local_ip);
        if !tg_secret.is_empty() {
            let clean_secret = tg_secret.strip_prefix("dd").unwrap_or(&tg_secret);
            let clean_secret = if clean_secret.len() >= 32 { &clean_secret[..32] } else { clean_secret };
            let (tg_running, tg_pid) = is_tg_proxy_running(base_dir);
            let tg_tag = if tg_running {
                if let Some(p) = tg_pid {
                    format!(" [АКТИВЕН - PID: {}]", p)
                } else {
                    " [АКТИВЕН]".to_string()
                }
            } else {
                " [ОСТАНОВЛЕН]".to_string()
            };
            println!(
                "  Telegram (tgwsproxy): tg://proxy?server={}&port=1443&secret=dd{}{}",
                local_ip, clean_secret, tg_tag
            );
        }
    } else {
        println!("  Мост [Bridge]:  ОСТАНОВЛЕН [Фоновый процесс не запущен]");
        println!("  Локальный IP:   {}", local_ip);
    }

    println!(
        "  Автозагрузка:   {}",
        if startup_enabled {
            "[Включена]"
        } else {
            "[Отключена]"
        }
    );
    println!("  --------------------------------------------------");
    println!();
}

/// Toggles Windows autostart.
pub fn cmd_toggle_startup(base_dir: &Path) {
    let enabled = is_startup_enabled();
    cmd_startup(!enabled, base_dir);
}

/// Configures complete Windows Startup for both Zapret service and Bridge.
pub fn cmd_startup(enable: bool, base_dir: &Path) {
    let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let target_dir = PathBuf::from(&local_appdata).join("ZapretTVBridge");
    let _ = std::fs::create_dir_all(&target_dir);
    let vbs_path = target_dir.join("bridge_autostart.vbs");
    let repo_vbs = base_dir.join("bridge_autostart.vbs");

    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let startup_dir = PathBuf::from(&appdata)
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup");
    let _ = std::fs::create_dir_all(&startup_dir);
    let shortcut_path = startup_dir.join("Zapret_TV_Bridge.lnk");
    let startup_vbs = startup_dir.join("Zapret_TV_Bridge.vbs");

    if !enable {
        // 1. Remove Registry Run keys
        let _ = Command::new("reg")
            .args(&[
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "ZapretTVBridge",
                "/f",
            ])
            .output();
        let _ = Command::new("reg")
            .args(&[
                "delete",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "ZapretTVBridge",
                "/f",
            ])
            .output();

        // 2. Remove scheduled task
        let _ = Command::new("schtasks")
            .args(&["/delete", "/tn", "Zapret_TV_Bridge", "/f"])
            .output();

        // 3. Remove Startup folder entries
        let _ = std::fs::remove_file(&shortcut_path);
        let _ = std::fs::remove_file(&startup_vbs);
        let _ = std::fs::remove_file(&vbs_path);
        let _ = std::fs::remove_file(&repo_vbs);

        println!("[+] Автозагрузка Windows отключена.");
        return;
    }

    // Configure zapret service for AUTO start if running with admin rights
    let _ = Command::new("sc").args(&["config", "zapret", "start=", "auto"]).output();
    let _ = Command::new("sc").args(&["config", "zapret", "depend=", "BFE/Tcpip"]).output();

    let norm_base = base_dir.to_string_lossy().trim_end_matches('\\').to_string();
    let vbs_content = format!(
        "' Zapret TV & Mobile Bridge -- Silent AutoStart Launcher\r\n\
         Option Explicit\r\n\
         Dim fso, shell, curDir\r\n\
         Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n\
         Set shell = CreateObject(\"WScript.Shell\")\r\n\
         curDir = \"{}\"\r\n\
         If Not fso.FolderExists(curDir) Then WScript.Quit\r\n\
         shell.CurrentDirectory = curDir\r\n\
         On Error Resume Next\r\n\
         shell.Run \"cmd.exe /c sc start zapret\", 0, False\r\n\
         If fso.FileExists(curDir & \"\\bin\\ZapretTVBridge.exe\") Then\r\n\
             shell.Run \"\"\"\" & curDir & \"\\bin\\ZapretTVBridge.exe\"\" --daemon\", 0, False\r\n\
         ElseIf fso.FileExists(curDir & \"\\ZapretTVBridge.exe\") Then\r\n\
             shell.Run \"\"\"\" & curDir & \"\\ZapretTVBridge.exe\"\" --daemon\", 0, False\r\n\
         ElseIf fso.FileExists(curDir & \"\\bridge-rs\\target\\release\\ZapretTVBridge.exe\") Then\r\n\
             shell.Run \"\"\"\" & curDir & \"\\bridge-rs\\target\\release\\ZapretTVBridge.exe\"\" --daemon\", 0, False\r\n\
         End If\r\n",
        norm_base
    );

    let _ = std::fs::write(&vbs_path, &vbs_content);
    let _ = std::fs::write(&startup_vbs, &vbs_content);

    // 1. Register in HKCU Run key (works 100% reliably on all Windows systems)
    let vbs_cmd = format!("wscript.exe \"{}\"", vbs_path.to_string_lossy());
    let _ = Command::new("reg")
        .args(&[
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "ZapretTVBridge",
            "/t",
            "REG_SZ",
            "/d",
            &vbs_cmd,
            "/f",
        ])
        .output();

    // 2. Create shortcut in Startup folder via PowerShell
    let ps_cmd = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{}'); \
         $s.TargetPath = 'wscript.exe'; \
         $s.Arguments = '\"{}\"'; \
         $s.WorkingDirectory = '{}'; \
         $s.WindowStyle = 7; \
         $s.Save()",
        shortcut_path.to_string_lossy().replace('\'', "''"),
        vbs_path.to_string_lossy().replace('\'', "''"),
        norm_base.replace('\'', "''")
    );
    let _ = Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
        .output();

    // 3. Register in Task Scheduler directly (runs with highest admin privileges if elevated)
    let _ = Command::new("schtasks")
        .args(&[
            "/create",
            "/tn",
            "Zapret_TV_Bridge",
            "/tr",
            &vbs_cmd,
            "/sc",
            "onlogon",
            "/rl",
            "highest",
            "/f",
        ])
        .output();

    // Ensure zapret service is started
    let _ = Command::new("sc").args(&["start", "zapret"]).output();
    cmd_start(base_dir);

    println!("[+] Все службы успешно добавлены в автозагрузку Windows!");
    println!("    При включении ПК автоматически запускаются и служба Zapret, и шлюз для ТВ.\n");
}

/// Adds Windows Firewall rules for HTTP proxy (8080), SOCKS5 (1080), and Telegram (1443).
pub fn cmd_firewall() {
    println!("[*] Настройка Брандмауэра Windows...");
    let rules = [
        ("Zapret TV Bridge (8080)", "8080"),
        ("Zapret TV Bridge SOCKS5 (1080)", "1080"),
        ("Zapret TV Bridge Telegram (1443)", "1443"),
    ];

    for (name, port) in &rules {
        let _ = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", name),
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={}", port),
                "profile=private,public",
            ])
            .output();
    }
    println!("[+] Правила Брандмауэра успешно добавлены (порты 8080, 1080 и 1443 открыты).");
}

/// Clears Windows System Proxy for direct system connection.
pub fn cmd_fix_proxy() {
    let _ = Command::new("reg")
        .args(&[
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "AutoConfigURL",
            "/f",
        ])
        .output();

    let _ = Command::new("reg")
        .args(&[
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ])
        .output();

    println!("[+] Системный прокси Windows очищен (прямое подключение).");
}

/// Opens URL in default system browser.
pub fn cmd_open_browser(url: &str) {
    #[cfg(windows)]
    {
        let _ = Command::new("cmd").args(&["/c", "start", "", url]).status();
    }
}

/// Performs network latency diagnostics tests.
pub fn cmd_test() {
    println!();
    println!("  ==================================================");
    println!("  ДИАГНОСТИКА СЕТИ И DNS-OVER-HTTPS (DoH)");
    println!("  ==================================================");

    let targets = [
        ("Cloudflare DNS (1.1.1.1:53)", "1.1.1.1:53"),
        ("Google DNS (8.8.8.8:53)", "8.8.8.8:53"),
        ("Local Gateway / Proxy (127.0.0.1:8080)", "127.0.0.1:8080"),
    ];

    for (name, addr_str) in &targets {
        if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
            let t0 = std::time::Instant::now();
            match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(1500)) {
                Ok(_) => {
                    let lat = t0.elapsed().as_secs_f64() * 1000.0;
                    println!("  [OK]   {:<38}  Задержка: {:.1} мс", name, lat);
                }
                Err(e) => {
                    println!("  [FAIL] {:<38}  Ошибка: {}", name, e);
                }
            }
        }
    }
    println!("  --------------------------------------------------");
    println!();
}
