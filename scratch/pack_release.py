import os
import zipfile

repo_dir = r"D:\projects\zapret-tv-bridge"
out_zip = os.path.join(repo_dir, "zapret-tv-bridge-v1.01.zip")

files_to_pack = [
    ("ZapretTVBridge.exe", "ZapretTVBridge.exe"),
    ("service.bat", "service.bat"),
    ("restore_network_defaults.bat", "restore_network_defaults.bat"),
    ("stop_old_services.bat", "stop_old_services.bat"),
    ("fix_browsers.reg", "fix_browsers.reg"),
    ("wintun_gateway.py", "wintun_gateway.py"),
    ("README.md", "README.md"),
    ("LICENSE", "LICENSE"),
    ("supercell.mobileconfig", "supercell.mobileconfig"),
]

dirs_to_pack = ["bin", "lists", "presets"]

with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
    for src, arc in files_to_pack:
        p = os.path.join(repo_dir, src)
        if os.path.exists(p):
            z.write(p, arc)
            print(f"Added file: {arc}")
        else:
            print(f"WARNING: {src} not found!")

    for d in dirs_to_pack:
        dp = os.path.join(repo_dir, d)
        if os.path.exists(dp):
            for root, _, files in os.walk(dp):
                for f in files:
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, repo_dir).replace("\\", "/")
                    z.write(full_p, rel_p)
                    print(f"Added {d}: {rel_p}")

print(f"Successfully created: {out_zip} ({os.path.getsize(out_zip)} bytes)")
