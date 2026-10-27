import subprocess

winws_exe = r"C:\Users\lanze\Desktop\zapret-tv-bridge-v1.01 (2) (2)\bin\winws.exe"

# If we use subprocess.run with a list (NO shell=True):
cmd_list = [
    "sc.exe", "create", "zapret",
    f"binPath= \"{winws_exe}\"",
    "DisplayName= zapret",
    "start= auto"
]
print("list2cmdline:")
print(subprocess.list2cmdline(cmd_list))

# If we use string with shell=True:
cmd_str = f'sc create zapret binPath= "\"{winws_exe}\"" DisplayName= zapret start= auto'
print("cmd_str:")
print(cmd_str)
