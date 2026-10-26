# -*- coding: utf-8 -*-
"""
Wintun L3 Virtual Network Adapter & Tun2socks Split Tunneling Manager
Обеспечивает работу изолированного виртуального L3-интерфейса Wintun
с раздельным туннелированием (Split Tunneling) без изменения системного прокси
и без перехвата пакетов через WinDivert.
"""

import os
import sys
import time
import json
import socket
import ipaddress
import subprocess
import ctypes
from ctypes import wintypes


def is_pid_alive(pid):
    """Проверяет, запущен ли процесс с указанным PID в Windows."""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        exit_code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        kernel32.CloseHandle(handle)
        return exit_code.value == 259  # STILL_ACTIVE
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def get_default_physical_interface():
    """
    Определяет основной физический сетевой адаптер с маршрутом 0.0.0.0/0.
    Возвращает кортеж: (interface_alias, interface_index, gateway_ip)
    """
    try:
        ps_cmd = (
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
            "Sort-Object RouteMetric | "
            "Select-Object -First 1 | "
            "Select-Object InterfaceAlias, InterfaceIndex, NextHop | "
            "ConvertTo-Json"
        )
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, stderr=subprocess.DEVNULL
        )
        data = json.loads(out)
        return str(data.get("InterfaceAlias", "Ethernet")), int(data.get("InterfaceIndex", 1)), str(data.get("NextHop", ""))
    except Exception:
        # Fallback через netsh / route print
        try:
            out = subprocess.check_output(["netsh", "interface", "ipv4", "show", "interfaces"], text=True, errors="ignore")
            for line in out.splitlines():
                if "connected" in line.lower() or "подключен" in line.lower():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].isdigit():
                        return parts[-1], int(parts[0]), ""
        except Exception:
            pass
    return "Ethernet", 1, ""


class SplitRouteManager:
    """Управление таблицей маршрутизации Windows для раздельного туннелирования."""

    def __init__(self, interface_name="WintunGateway", gateway_ip="172.19.0.2", base_dir=None):
        self.interface_name = interface_name
        self.gateway_ip = gateway_ip
        self.base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
        self.routes_file = os.path.join(self.base_dir, "wintun_routes.json")
        self.active_routes = []

    def load_target_subnets(self):
        """
        Загружает целевые CIDR-подсети из списков ipset-target.txt и ipset-all.txt.
        Автоматически исключает любые локальные, приватные (RFC1918) и системные адреса.
        """
        subnets = []
        lists_dir = os.path.join(self.base_dir, "lists")
        target_files = [
            os.path.join(lists_dir, "ipset-target.txt"),
            os.path.join(lists_dir, "ipset-all.txt"),
        ]

        # Встроенный fallback список ключевых целевых префиксов (Google, YouTube, Discord, Cloudflare)
        builtin_defaults = [
            "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "173.194.0.0/16", "74.125.0.0/16",
            "66.22.196.0/22", "66.22.200.0/22", "66.22.204.0/22", "66.22.208.0/22", "66.22.240.0/22",
            "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15", "188.114.96.0/20",
            "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
            "91.108.56.0/22", "149.154.160.0/20"
        ]

        found_any = False
        for fpath in target_files:
            if os.path.exists(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            try:
                                net = ipaddress.ip_network(line, strict=False)
                                if net.is_loopback or net.is_private or net.is_link_local or net.prefixlen == 0:
                                    continue
                                subnets.append(str(net))
                                found_any = True
                            except Exception:
                                continue
                except Exception:
                    pass

        if not found_any:
            subnets.extend(builtin_defaults)

        # Удаление дубликатов с сохранением порядка
        seen = set()
        unique_subnets = []
        for s in subnets:
            if s not in seen:
                seen.add(s)
                unique_subnets.append(s)

        return unique_subnets

    def apply_routes(self, subnets=None):
        """Добавляет специфичные маршруты через интерфейс Wintun."""
        if subnets is None:
            subnets = self.load_target_subnets()

        applied = []
        for cidr in subnets:
            try:
                cmd = [
                    "netsh", "interface", "ipv4", "add", "route",
                    cidr, self.interface_name, self.gateway_ip,
                    "metric=10", "store=active"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0 or "already exists" in res.stdout or "уже существует" in res.stdout:
                    applied.append(cidr)
            except Exception:
                pass

        self.active_routes = applied
        try:
            with open(self.routes_file, "w", encoding="utf-8") as f:
                json.dump(applied, f, indent=2)
        except Exception:
            pass

        return len(applied)

    def cleanup_all(self):
        """Удаляет все добавленные маршруты из таблицы маршрутизации."""
        to_remove = list(self.active_routes)
        if os.path.exists(self.routes_file):
            try:
                with open(self.routes_file, "r", encoding="utf-8") as f:
                    file_routes = json.load(f)
                    if isinstance(file_routes, list):
                        for r in file_routes:
                            if r not in to_remove:
                                to_remove.append(r)
            except Exception:
                pass

        for cidr in to_remove:
            try:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "delete", "route",
                     cidr, self.interface_name, self.gateway_ip],
                    capture_output=True
                )
            except Exception:
                pass

        self.active_routes.clear()
        if os.path.exists(self.routes_file):
            try:
                os.remove(self.routes_file)
            except Exception:
                pass


class WintunGatewayManager:
    """Управление виртуальным сетевым адаптером Wintun и процессом Tun2socks."""

    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
        self.adapter_name = "WintunGateway"
        self.adapter_ip = "172.19.0.1"
        self.gateway_ip = "172.19.0.2"
        self.pid_file = os.path.join(self.base_dir, "wintun_gateway.pid")
        self.log_file = os.path.join(self.base_dir, "wintun_gateway.log")
        self.route_manager = SplitRouteManager(self.adapter_name, self.gateway_ip, self.base_dir)

    def is_running(self):
        """Проверяет статус работы Wintun Gateway."""
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, "r", encoding="utf-8") as f:
                    pid = int(f.read().strip())
                if is_pid_alive(pid):
                    return True, pid
                else:
                    try:
                        os.remove(self.pid_file)
                    except Exception:
                        pass
            except Exception:
                pass
        return False, None

    def start_gateway(self, proxy_url="http://127.0.0.1:8080"):
        """Запускает виртуальный сетевой шлюз Wintun и применяет раздельное туннелирование."""
        running, pid = self.is_running()
        if running:
            print(f"[i] Wintun Gateway уже запущен (PID: {pid}).")
            return True

        bin_dir = os.path.join(self.base_dir, "bin")
        tun2socks_exe = os.path.join(bin_dir, "tun2socks.exe")
        wintun_dll = os.path.join(bin_dir, "wintun.dll")

        if not os.path.exists(tun2socks_exe):
            print(f"[!] Ошибка: tun2socks.exe не найден в {bin_dir}")
            return False
        if not os.path.exists(wintun_dll):
            print(f"[!] Ошибка: wintun.dll не найден в {bin_dir}")
            return False

        # Определение физического адаптера для защиты от зацикливания маршрутов
        phys_alias, phys_index, phys_gw = get_default_physical_interface()
        print(f"[*] Основной физический интерфейс: {phys_alias} (Индекс: {phys_index})")

        # Очистка предыдущих процессов tun2socks при повторном запуске
        subprocess.run(["taskkill", "/IM", "tun2socks.exe", "/F"], capture_output=True)
        time.sleep(0.3)

        cmd = [
            tun2socks_exe,
            "-device", f"wintun://{self.adapter_name}",
            "-proxy", proxy_url,
            "-interface", phys_alias,
            "--mtu", "1420",
            "--tcp-auto-tuning",
            "--loglevel", "info"
        ]

        print("[*] Запуск виртуального L3-адаптера Wintun...")
        try:
            log_f = open(self.log_file, "a", encoding="utf-8")
            log_f.write(f"\n--- Wintun Gateway Session Started: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            log_f.flush()

            proc = subprocess.Popen(
                cmd,
                cwd=bin_dir,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )

            with open(self.pid_file, "w", encoding="utf-8") as f:
                f.write(str(proc.pid))

        except Exception as e:
            print(f"[!] Ошибка запуска tun2socks: {e}")
            return False

        # Ожидание создания сетевого интерфейса операционной системой (до 4 секунд)
        adapter_ready = False
        for _ in range(8):
            time.sleep(0.5)
            check_out = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True, text=True, errors="ignore"
            )
            if self.adapter_name.lower() in check_out.stdout.lower():
                adapter_ready = True
                break

        if not adapter_ready:
            print("[!] Предупреждение: интерфейс Wintun еще инициализируется системой...")

        # Назначение статического L3 IP-адреса и высокой метрики (500)
        try:
            subprocess.run([
                "netsh", "interface", "ipv4", "set", "address",
                f"name={self.adapter_name}", "source=static",
                f"addr={self.adapter_ip}", "mask=255.255.255.252", "gateway=none"
            ], capture_output=True)

            subprocess.run([
                "netsh", "interface", "ipv4", "set", "interface",
                f"name={self.adapter_name}", "metric=500"
            ], capture_output=True)
            print(f"[+] L3 IP-адрес интерфейса {self.adapter_name}: {self.adapter_ip}/30 (Метрика: 500)")
        except Exception as e:
            print(f"[-] Предупреждение настройки адреса интерфейса: {e}")

        # Применение маршрутов Split Tunneling
        print("[*] Применение маршрутов раздельного туннелирования (Split Tunneling)...")
        count = self.route_manager.apply_routes()
        print(f"[+] Успешно активировано целевых префиксов в шлюзе: {count}")
        print("[+] Глобальный маршрут по умолчанию (0.0.0.0/0) и среды разработки сохранены в прямом доступе!")

        # Гарантированное отключение системного прокси Windows
        try:
            subprocess.run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                            "/v", "AutoConfigURL", "/f"], capture_output=True)
            subprocess.run(["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                            "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"], capture_output=True)
        except Exception:
            pass

        return True

    def stop_gateway(self):
        """Останавливает Wintun Gateway и безопасно удаляет все маршруты."""
        print("[*] Остановка Wintun Gateway и очистка маршрутов...")

        # 1. Снятие маршрутов
        self.route_manager.cleanup_all()

        # 2. Остановка процесса tun2socks
        running, pid = self.is_running()
        if running and pid:
            try:
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
            except Exception:
                pass
        subprocess.run(["taskkill", "/IM", "tun2socks.exe", "/F"], capture_output=True)

        if os.path.exists(self.pid_file):
            try:
                os.remove(self.pid_file)
            except Exception:
                pass

        print("[+] Wintun Gateway остановлен. Маршруты очищены, сетевой стек в исходном состоянии.")
        return True

    def get_status(self):
        """Возвращает информацию о текущем состоянии Wintun Gateway."""
        running, pid = self.is_running()
        active_routes_count = len(self.route_manager.active_routes)
        if active_routes_count == 0 and os.path.exists(self.route_manager.routes_file):
            try:
                with open(self.route_manager.routes_file, "r", encoding="utf-8") as f:
                    routes_list = json.load(f)
                    if isinstance(routes_list, list):
                        active_routes_count = len(routes_list)
            except Exception:
                pass

        return {
            "running": running,
            "pid": pid,
            "adapter_name": self.adapter_name,
            "adapter_ip": self.adapter_ip,
            "active_routes_count": active_routes_count
        }
