# -*- coding: utf-8 -*-
"""
Helper script to generate a new random 32-character hex secret for Telegram MTProto WS Proxy.
Restarts the background bridge automatically to apply the new secret.
Zero hardcoded paths or IPs.
"""

import secrets
import os
import subprocess
import socket
import sys


def get_local_ip():
    for target in [('8.8.8.8', 53), ('1.1.1.1', 53), ('77.88.8.8', 53)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(target)
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith("192.168.") or ip.startswith("10."):
                return ip
            if ip.startswith("172."):
                parts = ip.split(".")
                if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
                    return ip
    except Exception:
        pass
    return "127.0.0.1"


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    secret_path = os.path.join(base_dir, "tg_secret.txt")

    new_secret = secrets.token_hex(16)
    with open(secret_path, "w", encoding="utf-8") as f:
        f.write(new_secret)

    local_ip = get_local_ip()
    dd_secret = f"dd{new_secret}"
    tg_url = f"tg://proxy?server={local_ip}&port=1443&secret={dd_secret}"
    web_url = f"https://t.me/proxy?server={local_ip}&port=1443&secret={dd_secret}"

    print("=" * 60)
    print("  СГЕНЕРИРОВАН НОВЫЙ РАНДОМНЫЙ КЛЮЧ ДЛЯ TELEGRAM MTPROTO")
    print("=" * 60)
    print(f"Секрет (hex): {new_secret}")
    print(f"Секрет (dd):  {dd_secret}")
    print(f"Ссылка (app): {tg_url}")
    print(f"Ссылка (web): {web_url}")
    print("=" * 60)

    # Update local TELEGRAM_CONNECT_INFO.txt
    info_file = os.path.join(base_dir, "TELEGRAM_CONNECT_INFO.txt")
    info_content = f"""========================================================================
 Telegram MTProto WS Proxy (Flowseal/tg-ws-proxy)
========================================================================

Прямая ссылка для подключения в 1 клик (iOS / Android / Desktop):
{tg_url}

Веб-ссылка (t.me):
{web_url}

Параметры для ручного ввода в Telegram:
  • Тип прокси: MTProto
  • Сервер:     {local_ip}
  • Порт:       1443
  • Секрет:     {dd_secret} (или {new_secret})

Статус-страница в браузере:
http://{local_ip}:8080/
========================================================================
"""
    try:
        with open(info_file, "w", encoding="utf-8") as f:
            f.write(info_content)
    except Exception:
        pass

    # Restart background bridge if running
    pid_file = os.path.join(base_dir, "tv_proxy.pid")
    stop_bat = os.path.join(base_dir, "4_STOP.bat")
    start_vbs = os.path.join(base_dir, "2_START.vbs")

    if os.path.exists(pid_file):
        print("[*] Перезапуск фонового моста для применения нового ключа...")
        if os.path.exists(stop_bat):
            subprocess.run(["cmd.exe", "/c", stop_bat], cwd=base_dir, capture_output=True)
        if os.path.exists(start_vbs):
            subprocess.run(["wscript.exe", start_vbs], cwd=base_dir)
        print("[*] Фоновый мост перезапущен!")


if __name__ == "__main__":
    main()
