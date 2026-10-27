import subprocess

p = r"C:\Users\lanze\Desktop\zapret-tv-bridge-v1.01 (2) (2)\bin\winws.exe"
parsed_args = '--wf-tcp=80,443 --hostlist="C:\\lists\\list.txt"'

# What we had:
cmd_sc_old = f'sc create zapret binPath= "\"{p}\" {parsed_args}" DisplayName= zapret start= auto'
print("OLD CMD_SC:")
print(cmd_sc_old)

# How Windows cmd parses cmd_sc_old:
# Notice: binPath= "\"C:\...""
# In cmd.exe, \" is NOT an escape for a quote! \" in cmd.exe is a literal backslash followed by a quote!
# So cmd.exe sees:
# binPath= "\"
# C:\Users\...
