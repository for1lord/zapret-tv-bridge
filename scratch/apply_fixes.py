import os
import re

bridge_path = r'D:\projects\zapret-tv-bridge\zapret_tv_bridge.py'
service_bat_path = r'D:\projects\zapret-tv-bridge\service.bat'

# 1. Update zapret_tv_bridge.py
with open(bridge_path, 'r', encoding='utf-8') as f:
    text = f.read()

# Add pause_menu helper
if "def pause_menu(" not in text:
    target_pos = text.find("def is_admin():")
    pause_func = '''def pause_menu(prompt="   Нажмите любую клавишу для возврата в меню..."):
    """Waits for any key press on Windows without requiring Enter."""
    print(f"\\n{prompt}", end="", flush=True)
    try:
        import msvcrt
        msvcrt.getch()
        print()
    except Exception:
        try:
            input()
        except Exception:
            pass


'''
    text = text[:target_pos] + pause_func + text[target_pos:]

# Replace get_zapret_service_status
old_status_func = '''def get_zapret_service_status():
    """Checks whether the zapret Windows service is currently running."""
    is_running = False
    strategy = ""
    try:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\\CurrentControlSet\\Services\\zapret", 0, winreg.KEY_READ)
            strategy, _ = winreg.QueryValueEx(key, "zapret-discord-youtube")
            winreg.CloseKey(key)
        except Exception:
            pass

        res = subprocess.run(["sc", "query", "zapret"], capture_output=True, text=True)
        if "STATE" in res.stdout and "RUNNING" in res.stdout:
            is_running = True
    except Exception:
        pass
    return is_running, strategy'''

new_status_func = '''def get_zapret_service_status():
    """Checks whether the zapret Windows service is currently running across all localizations."""
    is_running = False
    strategy = ""
    try:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\\CurrentControlSet\\Services\\zapret", 0, winreg.KEY_READ)
            strategy, _ = winreg.QueryValueEx(key, "zapret-discord-youtube")
            winreg.CloseKey(key)
        except Exception:
            pass

        res = subprocess.run("sc query zapret", shell=True, capture_output=True, text=True, errors="ignore")
        if "RUNNING" in res.stdout.upper() or ": 4" in res.stdout:
            is_running = True
        else:
            t_res = subprocess.run('tasklist /FI "IMAGENAME eq winws.exe"', shell=True, capture_output=True, text=True, errors="ignore")
            if "winws.exe" in t_res.stdout.lower():
                is_running = True
    except Exception:
        pass
    return is_running, strategy'''

assert old_status_func in text, "old_status_func not found!"
text = text.replace(old_status_func, new_status_func, 1)

# Update cmd_status service label
old_cmd_status_zapret = '''    if zapret_running:
        strat_str = f" [{zapret_strat}]" if zapret_strat else ""
        print(f"  Служба Zapret:  АКТИВНА{strat_str}")
    else:
        print("  Служба Zapret:  ОСТАНОВЛЕНА / НЕ УСТАНОВЛЕНА")'''

new_cmd_status_zapret = '''    if zapret_running:
        strat_str = f" [{zapret_strat}]" if zapret_strat else ""
        print(f"  Служба Zapret:  АКТИВНА{strat_str}")
    else:
        res = subprocess.run("sc query zapret", shell=True, capture_output=True, text=True, errors="ignore")
        if "1060" in res.stdout or "не установлена" in res.stdout.lower():
            print("  Служба Zapret:  НЕ УСТАНОВЛЕНА")
        else:
            print("  Служба Zapret:  ОСТАНОВЛЕНА")'''

assert old_cmd_status_zapret in text, "old_cmd_status_zapret not found!"
text = text.replace(old_cmd_status_zapret, new_cmd_status_zapret, 1)

# Update cmd_install_strategy service creation
old_sc_create = '''    subprocess.run(["sc", "stop", "zapret"], capture_output=True)
    subprocess.run(["sc", "delete", "zapret"], capture_output=True)
    subprocess.run(["taskkill", "/IM", "winws.exe", "/F"], capture_output=True)

    res = subprocess.run([
        "sc", "create", "zapret",
        f"binPath= \\"{winws_exe}\\"",
        "DisplayName=", "zapret",
        "start=", "auto"
    ], capture_output=True, text=True)

    if res.returncode != 0:
        print(f"[!] Ошибка создания службы: {res.stdout.strip() or res.stderr.strip()}")
        return False

    subprocess.run(["sc", "description", "zapret", "Zapret DPI Network Optimization Service"], capture_output=True)

    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\\CurrentControlSet\\Services\\zapret", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, f'"{winws_exe}" {parsed_args}')
        winreg.SetValueEx(key, "zapret-discord-youtube", 0, winreg.REG_SZ, strategy_name)
        winreg.CloseKey(key)
    except Exception as e:
        print(f"[!] Ошибка записи реестра: {e}")
        return False

    start_res = subprocess.run(["sc", "start", "zapret"], capture_output=True, text=True)
    if "START_PENDING" in start_res.stdout or "RUNNING" in start_res.stdout:
        print(f"[+] Служба Zapret со стратегией '{strategy_name}' успешно установлена и запущена!")
    else:
        q_res = subprocess.run(["sc", "query", "zapret"], capture_output=True, text=True)
        if "RUNNING" in q_res.stdout:
            print(f"[+] Служба Zapret со стратегией '{strategy_name}' успешно запущена!")
        else:
            print(f"[!] Служба создана, но статус запуска: {start_res.stdout.strip() or start_res.stderr.strip()}")'''

new_sc_create = '''    subprocess.run("sc stop zapret", shell=True, capture_output=True)
    subprocess.run("sc delete zapret", shell=True, capture_output=True)
    subprocess.run("taskkill /IM winws.exe /F", shell=True, capture_output=True)
    import time
    time.sleep(1)

    cmd_sc = f'sc create zapret binPath= "\\"{winws_exe}\\" {parsed_args}" DisplayName= zapret start= auto'
    res = subprocess.run(cmd_sc, shell=True, capture_output=True, text=True, errors="ignore")

    if res.returncode != 0:
        # Fallback via registry ImagePath
        res_fb = subprocess.run(f'sc create zapret binPath= "\\"{winws_exe}\\"" DisplayName= zapret start= auto',
                                shell=True, capture_output=True, text=True, errors="ignore")
        if res_fb.returncode == 0:
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\\CurrentControlSet\\Services\\zapret", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, f'"{winws_exe}" {parsed_args}')
                winreg.SetValueEx(key, "zapret-discord-youtube", 0, winreg.REG_SZ, strategy_name)
                winreg.CloseKey(key)
                res = res_fb
            except Exception as e:
                print(f"[!] Ошибка записи реестра: {e}")
                return False
        else:
            print(f"[!] Ошибка создания службы через sc: {res.stdout.strip() or res.stderr.strip()}")
            return False

    subprocess.run('sc description zapret "Zapret DPI Network Optimization Service"', shell=True, capture_output=True)

    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\\CurrentControlSet\\Services\\zapret", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "zapret-discord-youtube", 0, winreg.REG_SZ, strategy_name)
        winreg.CloseKey(key)
    except Exception:
        pass

    start_res = subprocess.run("sc start zapret", shell=True, capture_output=True, text=True, errors="ignore")
    time.sleep(1)
    q_res = subprocess.run("sc query zapret", shell=True, capture_output=True, text=True, errors="ignore")
    if "RUNNING" in q_res.stdout.upper() or ": 4" in q_res.stdout:
        print(f"[+] Служба Zapret со стратегией '{strategy_name}' успешно установлена и запущена!")
    elif "START_PENDING" in q_res.stdout.upper() or ": 2" in q_res.stdout:
        print(f"[+] Служба Zapret со стратегией '{strategy_name}' запускается...")
    else:
        t_res = subprocess.run('tasklist /FI "IMAGENAME eq winws.exe"', shell=True, capture_output=True, text=True, errors="ignore")
        if "winws.exe" in t_res.stdout.lower():
            print(f"[+] Служба Zapret со стратегией '{strategy_name}' успешно запущена (процесс активен)!")
        else:
            print(f"[!] Служба создана, но статус запуска: {q_res.stdout.strip() or start_res.stdout.strip()}")'''

assert old_sc_create in text, "old_sc_create not found!"
text = text.replace(old_sc_create, new_sc_create, 1)

# Update DoH in cmd_optimize_network
old_opt_browser = '''    # 3. Disable Chromium QUIC and Kyber via System Registry Policies (Chrome, Edge, Yandex)
    browser_policies = [
        (r"SOFTWARE\\Policies\\Google\\Chrome", "Google Chrome"),
        (r"SOFTWARE\\Policies\\Microsoft\\Edge", "Microsoft Edge"),
        (r"SOFTWARE\\Policies\\Yandex\\YandexBrowser", "Yandex Browser")
    ]
    try:
        import winreg
        for key_path, b_name in browser_policies:
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "QuicAllowed", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "PostQuantumKeyAgreementEnabled", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                print(f"    [+] {b_name}: системные политики QUIC=0 и Kyber=0 успешно применены.")
            except Exception:
                pass
    except Exception as e:
        print(f"    [-] Предупреждение при настройке политик браузеров: {e}")'''

new_opt_browser = '''    # 3. Disable Chromium QUIC and Kyber + Enable Secure DNS (DoH) via System Registry Policies
    browser_policies = [
        (r"SOFTWARE\\Policies\\Google\\Chrome", "Google Chrome"),
        (r"SOFTWARE\\Policies\\Microsoft\\Edge", "Microsoft Edge"),
        (r"SOFTWARE\\Policies\\Yandex\\YandexBrowser", "Yandex Browser")
    ]
    try:
        import winreg
        for key_path, b_name in browser_policies:
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "QuicAllowed", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "PostQuantumKeyAgreementEnabled", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "DnsOverHttpsMode", 0, winreg.REG_SZ, "automatic")
                winreg.SetValueEx(key, "DnsOverHttpsTemplates", 0, winreg.REG_SZ, "https://dns.google/dns-query{?dns}")
                winreg.CloseKey(key)
                print(f"    [+] {b_name}: политики QUIC=0, Kyber=0 и Безопасный DNS (DoH) успешно применены.")
            except Exception:
                pass
    except Exception as e:
        print(f"    [-] Предупреждение при настройке политик браузеров: {e}")

    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
    except Exception:
        pass'''

assert old_opt_browser in text, "old_opt_browser not found!"
text = text.replace(old_opt_browser, new_opt_browser, 1)

# Replace all input("...Нажмите Enter для возврата в меню...") with pause_menu()
text = re.sub(r'input\s*\(\s*["\'].*?Нажмите Enter для возврата в меню.*?["\']\s*\)', 'pause_menu()', text)

with open(bridge_path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)
print("zapret_tv_bridge.py successfully updated!")

# 2. Update service.bat
with open(service_bat_path, 'r', encoding='utf-8') as f:
    bat_text = f.read()

old_bat_status = '''sc query zapret 2>nul | findstr /i "STATE" | findstr /i "RUNNING" >nul
if not errorlevel 1 (
    set "ZAPRET_RUNNING=1"
    for /f "tokens=2*" %%A in ('reg query "HKLM\\System\\CurrentControlSet\\Services\\zapret" /v zapret-discord-youtube 2^>nul') do set "ZAPRET_STRATEGY=%%B"
)

if "!ZAPRET_RUNNING!"=="1" (
    if defined ZAPRET_STRATEGY (
        set "ZAPRET_STATUS_STR=[RUNNING - !ZAPRET_STRATEGY!]"
    ) else (
        set "ZAPRET_STATUS_STR=[RUNNING]"
    )
) else (
    sc query zapret 2>nul | findstr /i "zapret" >nul
    if not errorlevel 1 (
        set "ZAPRET_STATUS_STR=[STOPPED]"
    ) else (
        set "ZAPRET_STATUS_STR=[NOT INSTALLED]"
    )
)'''

new_bat_status = '''sc query zapret 2>nul | findstr /i "RUNNING" >nul
if not errorlevel 1 (
    set "ZAPRET_RUNNING=1"
) else (
    tasklist /FI "IMAGENAME eq winws.exe" 2>nul | findstr /i "winws.exe" >nul
    if not errorlevel 1 set "ZAPRET_RUNNING=1"
)

if "!ZAPRET_RUNNING!"=="1" (
    for /f "tokens=2*" %%A in ('reg query "HKLM\\System\\CurrentControlSet\\Services\\zapret" /v zapret-discord-youtube 2^>nul') do set "ZAPRET_STRATEGY=%%B"
    if defined ZAPRET_STRATEGY (
        set "ZAPRET_STATUS_STR=[RUNNING - !ZAPRET_STRATEGY!]"
    ) else (
        set "ZAPRET_STATUS_STR=[RUNNING]"
    )
) else (
    reg query "HKLM\\System\\CurrentControlSet\\Services\\zapret" >nul 2>&1
    if not errorlevel 1 (
        set "ZAPRET_STATUS_STR=[STOPPED]"
    ) else (
        set "ZAPRET_STATUS_STR=[NOT INSTALLED]"
    )
)'''

assert old_bat_status in bat_text, "old_bat_status not found!"
bat_text = bat_text.replace(old_bat_status, new_bat_status, 1)

with open(service_bat_path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(bat_text)
print("service.bat successfully updated!")
