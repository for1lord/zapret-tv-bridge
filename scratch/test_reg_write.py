import winreg

test_key_path = r"Software\TestZapretService"
key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key_path, 0, winreg.KEY_SET_VALUE)
full_bin_path = r'"C:\Users\lanze\Desktop\zapret-tv-bridge-v1.01 (2) (2)\bin\winws.exe" --wf-tcp=80,443'
winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, full_bin_path)
winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "zapret")
winreg.SetValueEx(key, "Description", 0, winreg.REG_SZ, "Zapret DPI Network Optimization Service")
winreg.SetValueEx(key, "zapret-discord-youtube", 0, winreg.REG_SZ, "general (ALT12)")
winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 2)
winreg.SetValueEx(key, "Type", 0, winreg.REG_DWORD, 0x10)
winreg.SetValueEx(key, "ErrorControl", 0, winreg.REG_DWORD, 1)
winreg.CloseKey(key)

# Clean up
winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key_path)
print("winreg test SUCCESSful!")
