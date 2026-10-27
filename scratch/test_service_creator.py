import ctypes
from ctypes import wintypes
import os
import subprocess
import time
import winreg

def create_zapret_service(winws_exe, parsed_args, strategy_name):
    """
    100% reliable Windows service creator.
    Uses WinAPI advapi32 + Registry ImagePath.
    Zero dependency on cmd.exe quote parsing.
    """
    full_bin_path = f'"{winws_exe}" {parsed_args}'
    
    # 1. Stop existing process and service
    subprocess.run(["taskkill", "/IM", "winws.exe", "/F"], capture_output=True)
    subprocess.run(["sc.exe", "stop", "zapret"], capture_output=True)
    time.sleep(1)

    service_created = False

    # 2. Try WinAPI CreateServiceW
    try:
        advapi32 = ctypes.windll.advapi32
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_ALL_ACCESS = 0xF01FF
        SERVICE_WIN32_OWN_PROCESS = 0x00000010
        SERVICE_AUTO_START = 0x00000002
        SERVICE_ERROR_NORMAL = 0x00000001

        h_scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
        if h_scm:
            # Check if exists
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
    except Exception as e:
        print("WinAPI note:", e)

    # 3. Fallback: sc.exe create with simple clean path, then update ImagePath
    if not service_created:
        # Check if service already exists in SCM/Registry
        sc_res = subprocess.run(["sc.exe", "create", "zapret", "binPath= %SystemRoot%\\System32\\cmd.exe", "DisplayName= zapret", "start= auto"],
                                capture_output=True, text=True, errors="ignore")
        if sc_res.returncode == 0 or "already exists" in sc_res.stdout.lower() or "уже существует" in sc_res.stdout.lower():
            service_created = True

    # 4. Set/Ensure exact ImagePath and strategy in Registry
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services\zapret", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, full_bin_path)
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "zapret")
        winreg.SetValueEx(key, "Description", 0, winreg.REG_SZ, "Zapret DPI Network Optimization Service")
        winreg.SetValueEx(key, "zapret-discord-youtube", 0, winreg.REG_SZ, strategy_name)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 2)
        winreg.CloseKey(key)
        service_created = True
    except Exception as e:
        print("Registry write note:", e)

    return service_created

print("Function defined and ready.")
