import subprocess

cmd_test = 'sc create zapret binPath= "C:\\Windows\\System32\\cmd.exe" DisplayName= zapret start= auto'
print("CMD TO RUN:")
print(cmd_test)

res = subprocess.run(cmd_test, shell=True, capture_output=True, text=True)
print("STDOUT:")
print(res.stdout)
print("RETURNCODE:", res.returncode)
