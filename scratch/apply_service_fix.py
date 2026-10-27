import os

path = r'D:\projects\zapret-tv-bridge\zapret_tv_bridge.py'

with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

old_block = '''    subprocess.run("sc stop zapret", shell=True, capture_output=True)
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
    q_res = subprocess.run("sc query zapret", shell=True, capture_output=True, text=True, errors="ignore")'''

new_block = '''    full_bin_path = f'"{winws_exe}" {parsed_args}'

    # 1. Stop existing service and processes
    subprocess.run(["taskkill", "/IM", "winws.exe", "/F"], capture_output=True)
    subprocess.run(["sc.exe", "stop", "zapret"], capture_output=True)
    import time
    time.sleep(1)

    service_created = False

    # 2. Try native WinAPI CreateServiceW (zero cmd quoting issues)
    try:
        import ctypes
        from ctypes import wintypes
        advapi32 = ctypes.windll.advapi32
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_ALL_ACCESS = 0xF01FF
        SERVICE_WIN32_OWN_PROCESS = 0x00000010
        SERVICE_AUTO_START = 0x00000002
        SERVICE_ERROR_NORMAL = 0x00000001

        h_scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
        if h_scm:
            h_srv = advapi32.OpenServiceW(h_scm, "zapret", SERVICE_ALL_ACCESS)
            if h_srv:
                advapi32.DeleteService(h_srv)
                advapi32.CloseServiceHandle(h_srv)
                time.sleep(1)

            h_new = advapi32.CreateServiceW(
                h_scm, "zapret", "zapret",
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL, full_bin_path,
                None, None, None, None, None
            )
            if h_new:
                advapi32.CloseServiceHandle(h_new)
                service_created = True
            advapi32.CloseServiceHandle(h_scm)
    except Exception:
        pass

    # 3. Fallback: sc.exe create without complex quotes, then update ImagePath
    if not service_created:
        sc_res = subprocess.run(["sc.exe", "create", "zapret", "binPath= %SystemRoot%\\\\System32\\\\cmd.exe", "DisplayName= zapret", "start= auto"],
                                capture_output=True, text=True, errors="ignore")
        if sc_res.returncode == 0 or "already exists" in sc_res.stdout.lower() or "уже существует" in sc_res.stdout.lower():
            service_created = True

    # 4. Set/Ensure exact ImagePath, strategy, and description in Registry
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\\CurrentControlSet\\Services\\zapret", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, full_bin_path)
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "zapret")
        winreg.SetValueEx(key, "Description", 0, winreg.REG_SZ, "Zapret DPI Network Optimization Service")
        winreg.SetValueEx(key, "zapret-discord-youtube", 0, winreg.REG_SZ, strategy_name)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 2)
        winreg.CloseKey(key)
        service_created = True
    except Exception as e:
        print(f"[!] Ошибка настройки реестра службы: {e}")
        return False

    if not service_created:
        print("[!] Ошибка: Не удалось зарегистрировать службу zapret в системе.")
        return False

    start_res = subprocess.run(["sc.exe", "start", "zapret"], capture_output=True, text=True, errors="ignore")
    time.sleep(1)
    q_res = subprocess.run(["sc.exe", "query", "zapret"], capture_output=True, text=True, errors="ignore")'''

assert old_block in text, "old_block not found in zapret_tv_bridge.py!"
text = text.replace(old_block, new_block, 1)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print("zapret_tv_bridge.py successfully updated with robust service creation!")
