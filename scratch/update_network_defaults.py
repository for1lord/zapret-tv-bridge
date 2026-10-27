import os
import re

path = r'D:\projects\zapret-tv-bridge\zapret_tv_bridge.py'

with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# Replace cmd_optimize_network definition
old_optimize = '''def cmd_optimize_network():
    """Optimizes Windows 10/11 network stack: disables RSC, disables IPv6, sets browser policies for QUIC & Kyber."""
    if not is_admin():
        ensure_admin()
        if not is_admin():
            print("\\n[!] Ошибка: Для оптимизации сетевого стека требуются права Администратора.")
            return False

    print("\\n[*] Оптимизация сети Windows 10/11 (RSC, QUIC, Kyber, IPv6)...")

    # 1. Disable Receive Segment Coalescing (RSC) to prevent packet loss & speed drops with WinDivert
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", "Disable-NetAdapterRsc -Name * -Confirm:$false"], capture_output=True)
        subprocess.run(["netsh", "int", "tcp", "set", "global", "rsc=disabled"], capture_output=True)
        print("    [+] Режим RSC отключен (устраняет потерю пакетов и просадку скорости).")
    except Exception as e:
        print(f"    [-] Предупреждение при отключении RSC: {e}")

    # 2. Disable IPv6 on active adapters (prevents hanging Google/DNS IPv6 requests)
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", "Disable-NetAdapterBinding -Name * -ComponentId ms_tcpip6 -Confirm:$false"], capture_output=True)
        print("    [+] Протокол IPv6 отключен на адаптерах (исправлено зависание поиска Google).")
    except Exception as e:
        print(f"    [-] Предупреждение при отключении IPv6: {e}")

    # 3. Disable Chromium QUIC and Kyber + Enable Secure DNS (DoH) via System Registry Policies
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
        pass

    # 4. Ensure TCP Auto-Tuning is normal
    try:
        subprocess.run(["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"], capture_output=True)
    except Exception:
        pass

    print("[+] Оптимизация сети Windows успешно применена!\\n")
    return True'''

new_optimize = '''def cmd_restore_network_defaults():
    """Restores factory default Windows network settings, re-enables IPv6 & RSC, and removes forced browser policies."""
    print("\\n[*] Восстановление заводских параметров сети Windows...")
    # 1. Re-enable IPv6
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", "Enable-NetAdapterBinding -Name * -ComponentId ms_tcpip6 -Confirm:$false"], capture_output=True)
        print("    [+] Протокол IPv6 включен (заводское состояние).")
    except Exception:
        pass

    # 2. Re-enable RSC
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", "Enable-NetAdapterRsc -Name * -Confirm:$false"], capture_output=True)
        subprocess.run(["netsh", "int", "tcp", "set", "global", "rsc=enabled"], capture_output=True)
        print("    [+] Режим RSC включен (заводское состояние).")
    except Exception:
        pass

    # 3. Clean up all forced browser policies
    browser_policies = [
        (r"SOFTWARE\\Policies\\Google\\Chrome", "Google Chrome"),
        (r"SOFTWARE\\Policies\\Microsoft\\Edge", "Microsoft Edge"),
        (r"SOFTWARE\\Policies\\Yandex\\YandexBrowser", "Yandex Browser")
    ]
    vals_to_delete = ["DnsOverHttpsMode", "DnsOverHttpsTemplates", "ProxyMode", "QuicAllowed", "PostQuantumKeyAgreementEnabled"]
    try:
        import winreg
        for key_path, b_name in browser_policies:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                for val in vals_to_delete:
                    try:
                        winreg.DeleteValue(key, val)
                    except Exception:
                        pass
                winreg.CloseKey(key)
                print(f"    [+] {b_name}: политики очищены, стандартный DNS и прокси восстановлены.")
            except Exception:
                pass
    except Exception:
        pass

    # 4. Flush DNS
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
    except Exception:
        pass

    print("[+] Заводские параметры сети Windows успешно восстановлены!\\n")
    return True

def cmd_optimize_network():
    """Alias for backwards compatibility: restores clean default network state."""
    return cmd_restore_network_defaults()'''

assert old_optimize in text, "old_optimize not found!"
text = text.replace(old_optimize, new_optimize, 1)

# In cmd_install_strategy, replace cmd_optimize_network() with cmd_restore_network_defaults()
text = text.replace("    cmd_optimize_network()", "    cmd_restore_network_defaults()")

# In cmd_install_all, replace line:
old_install_str = '    print("  2. Сеть Windows оптимизирована (RSC отключен, QUIC/Kyber настроены).")'
new_install_str = '    print("  2. Сеть Windows в заводском режиме (политики браузеров и DNS не блокируются).")'
if old_install_str in text:
    text = text.replace(old_install_str, new_install_str, 1)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print("zapret_tv_bridge.py updated: network optimization replaced with clean defaults restore!")
