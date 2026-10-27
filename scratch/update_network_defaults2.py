import os

path = r'D:\projects\zapret-tv-bridge\zapret_tv_bridge.py'

with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find start and end of def cmd_optimize_network
start_idx = None
end_idx = None

for i, line in enumerate(lines):
    if line.startswith("def cmd_optimize_network():"):
        start_idx = i
    if start_idx is not None and i > start_idx and line.startswith("def cmd_remove_strategy():"):
        end_idx = i
        break

assert start_idx is not None and end_idx is not None, f"indices not found: {start_idx}, {end_idx}"

new_func = """def cmd_restore_network_defaults():
    \"\"\"Restores factory default Windows network settings, re-enables IPv6 & RSC, and removes forced browser policies.\"\"\"
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
    \"\"\"Alias for backwards compatibility: restores clean default network state.\"\"\"
    return cmd_restore_network_defaults()


"""

lines[start_idx:end_idx] = [new_func]

text = "".join(lines)
text = text.replace("    cmd_optimize_network()", "    cmd_restore_network_defaults()")
text = text.replace('    print("  2. Сеть Windows оптимизирована (RSC отключен, QUIC/Kyber настроены).")',
                    '    print("  2. Сеть Windows в заводском режиме (политики браузеров и DNS не блокируются).")')

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print("SUCCESS: zapret_tv_bridge.py updated with cmd_restore_network_defaults!")
