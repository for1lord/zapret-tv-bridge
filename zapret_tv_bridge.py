# -*- coding: utf-8 -*-
"""
Zapret TV & Mobile Bridge — Local Network Proxy & PAC Gateway
Routes secondary devices (LG webOS TV, Apple iOS, Android, etc.) through the host PC's Zapret proxy.

Key Features:
1. Smart Domain Filter & DoH Resolver:
   - Dynamic domain categorization and optimized DNS-over-HTTPS (DoH Cloudflare/Google) resolution.
   - Domestic traffic (Yandex, VK, Gosuslugi, banking) routes DIRECT with zero latency.
   - Streaming and media services (YouTube 4K, Discord, Twitter/X, Instagram) route through Zapret proxy.
2. Built-in PAC Autoconfiguration:
   - Serves http://<IP>:<PORT>/proxy.pac for iOS / iPadOS / macOS / Windows automated proxy routing.
3. Manual HTTP/HTTPS Proxy:
   - Direct connection for Smart TVs (LG webOS, Android TV, Google TV, Apple TV).
4. Telegram MTProto WebSocket Bridge (Flowseal/tg-ws-proxy):
   - Fast, resilient Telegram connectivity across all accounts.
5. Mobile Gaming Network Settings:
   - Configuration profile (.mobileconfig) and DoT resolution for Supercell games (Brawl Stars & Clash Royale).
"""

import socket
import select
import threading
import sys
import os
import time
import urllib.request
import json
import re
import subprocess
import argparse

# Known unreachable or invalid IPs to ignore
INVALID_ROUTE_IPS = {"94.190.64.51", "127.0.0.1", "0.0.0.0", "151.101.195.6", "129.134.30.12"}

# In-memory DNS cache: {hostname: (ip_list, expire_time)}
DNS_CACHE = {}
DNS_CACHE_LOCK = threading.RLock()


def get_local_ip():
    """
    Dynamically discovers the host's LAN IP address.
    Never uses hardcoded IPs.
    """
    # 1. Connect a dummy UDP socket to public DNS resolvers (no actual packets sent)
    for test_target in [('8.8.8.8', 53), ('1.1.1.1', 53), ('77.88.8.8', 53)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(test_target)
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass

    # 2. Iterate network adapters for private RFC1918 IPv4 addresses
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

    return '127.0.0.1'


def is_port_available(port, host="0.0.0.0"):
    """Checks whether a TCP port is free for binding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start_port, host="0.0.0.0", max_attempts=15):
    """Finds the next available port starting from start_port."""
    for p in range(start_port, start_port + max_attempts):
        if is_port_available(p, host):
            return p
    return None


def get_or_create_tg_secret(base_dir):
    """Reads or generates a 32-character random hex secret for Telegram MTProto."""
    secret_file = os.path.join(base_dir, "tg_secret.txt")
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                s = f.read().strip()
                if len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s):
                    return s.lower()
        except Exception:
            pass
    import secrets
    new_secret = secrets.token_hex(16)
    try:
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(new_secret)
    except Exception:
        pass
    return new_secret


class SmartRoutingFilter:
    """
    High-performance in-memory domain routing filter using binary search.
    Checks >660,000 domains in ~3.8 microseconds per query.
    """
    def __init__(self, base_dir, lists_dir=None, log_func=None):
        self.base_dir = base_dir
        self.lists_dir = lists_dir or self._discover_lists_dir(base_dir)
        self.log = log_func or print
        self.data_file = os.path.join(base_dir, "routing_rules.json")
        self.hostnames = {}
        self.zapret_domains = set()
        self.user_domains = set()
        self.exclude_domains = set()
        self.auto_added_domains = set()
        self.lock = threading.RLock()

        self.reload_lists()
        self.load_database()

    def _discover_lists_dir(self, base_dir):
        local_lists = os.path.join(base_dir, "lists")
        if os.path.exists(local_lists):
            return local_lists
        parent_lists = os.path.join(os.path.dirname(base_dir), "lists")
        if os.path.exists(parent_lists):
            return parent_lists
        return local_lists

    def reload_lists(self):
        gen_path = os.path.join(self.lists_dir, "list-general.txt")
        user_path = os.path.join(self.lists_dir, "list-general-user.txt")
        exc_path = os.path.join(self.lists_dir, "list-exclude.txt")
        exc_user_path = os.path.join(self.lists_dir, "list-exclude-user.txt")

        new_zapret = set()
        new_user = set()
        new_exclude = set()

        for path, target_set in [
            (gen_path, new_zapret),
            (user_path, new_user),
            (exc_path, new_exclude),
            (exc_user_path, new_exclude)
        ]:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip().lower()
                            if line and not line.startswith("#"):
                                target_set.add(line)
                except Exception:
                    pass

        with self.lock:
            self.zapret_domains = new_zapret
            self.user_domains = new_user
            self.exclude_domains = new_exclude

    def load_database(self):
        # Check routing_rules.json or legacy anticensority_data.json
        load_path = self.data_file
        if not os.path.exists(load_path):
            alt_path = os.path.join(self.base_dir, "anticensority_data.json")
            if os.path.exists(alt_path):
                load_path = alt_path

        if os.path.exists(load_path):
            try:
                t0 = time.time()
                with open(load_path, "r", encoding="utf-8") as f:
                    self.hostnames = json.load(f)
                total_buckets = len(self.hostnames)
                self.log(f"[SmartRouter] База правил маршрутизации загружена: {total_buckets} категорий за {time.time()-t0:.2f}с")
                return
            except Exception as e:
                self.log(f"[SmartRouter] Ошибка чтения базы правил: {e}")

        # If database file doesn't exist, schedule background update
        t = threading.Thread(target=self.download_database, daemon=True)
        t.start()

    def download_database(self):
        urls = [
            "https://raw.githubusercontent.com/anticensority/generated-pac-scripts/master/anticensority.pac",
            "https://anticensority.github.io/generated-pac-scripts/anticensority.pac"
        ]
        self.log("[SmartRouter] Загрузка актуальной базы доменных правил...")
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    content = resp.read().decode("utf-8", errors="ignore")
                m = re.search(r'const inputs = (\{.*?\});', content)
                if m:
                    data = json.loads(m.group(1))
                    hostnames = data.get("HOSTNAMES", {})
                    with self.lock:
                        self.hostnames = hostnames
                    with open(self.data_file, "w", encoding="utf-8") as f:
                        json.dump(hostnames, f)
                    self.log(f"[SmartRouter] База правил успешно сохранена ({len(hostnames)} категорий)!")
                    return
            except Exception as e:
                self.log(f"[SmartRouter] Ошибка загрузки базы: {e}")

    def _binary_search(self, bucket_str, target):
        L = len(target)
        if not bucket_str or len(bucket_str) < L:
            return False
        istart = 0
        iend = (len(bucket_str) // L) - 1
        while istart < iend:
            imid = (istart + iend) >> 1
            offset = imid * L
            word = bucket_str[offset:offset+L]
            if target > word:
                istart = imid + 1
            else:
                iend = imid
        offset = iend * L
        return bucket_str[offset:offset+L] == target

    def should_route(self, hostname):
        """
        Returns (route_via_zapret: bool, reason: str)
        """
        host = hostname.lower().strip(".")
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return False, "ip_direct"

        parts = host.split(".")

        # 0. Check Zapret Exclude Lists (list-exclude.txt: Yandex, VK, Gosuslugi, Sberbank, etc.)
        with self.lock:
            for i in range(len(parts) - 1):
                sub = ".".join(parts[i:])
                if sub in self.exclude_domains:
                    return False, "excluded_direct"

        # Apple core services -> DIRECT
        if any(h in host for h in ["apple.com", "mzstatic.com", "icloud.com", "itunes.com", "aaplimg.com", "akadns.net"]):
            return False, "apple_direct"

        # Supercell Web & ID services -> DIRECT
        if any(h in host for h in ["supercell.com", "supercellid.com", "clashroyaleapp.com", "brawlstarsgame.com", "clashroyale.com"]):
            if not any(host.startswith(p) for p in ["game.clashroyaleapp.com", "game.brawlstarsgame.com", "game.clashofclans.com", "game.squadbustersgame.com"]):
                return False, "supercell_web_direct"

        # 1. Media & Streaming services -> Route through Zapret
        if "googlevideo" in host or "youtube" in host or "ytimg" in host or "ggpht" in host or "youtu.be" in host:
            return True, "youtube"
        if any(host.startswith(p) for p in ["game.clashroyaleapp.com", "game.brawlstarsgame.com", "game.clashofclans.com", "game.squadbustersgame.com"]):
            return True, "supercell_game"
        if "discord" in host or "discordapp" in host or "discord.gg" in host:
            return True, "discord"
        if any(m in host for m in ["instagram", "cdninstagram", "fbcdn", "facebook", "threads", "ig.me", "meta.com", "fbsbx"]):
            return True, "meta_media"
        if "twitter" in host or "twimg" in host or host == "x.com" or host.endswith(".x.com"):
            return True, "twitter_x"

        # 2. Check Zapret hostlists (list-general.txt / list-general-user.txt)
        with self.lock:
            for i in range(len(parts) - 1):
                sub = ".".join(parts[i:])
                if sub in self.zapret_domains or sub in self.user_domains:
                    return True, "zapret_hostlist"

        # 3. Check Domain Routing Rules dataset
        with self.lock:
            for i in range(len(parts) - 1):
                sub = ".".join(parts[i:])
                L = str(len(sub))
                if L in self.hostnames and self._binary_search(self.hostnames[L], sub):
                    self.auto_add_domain(sub)
                    return True, "rule_match"

        # 4. Known media / forum patterns
        if "rutracker" in host or "rutor" in host or "nnmclub" in host or "flibusta" in host:
            return True, "media_portal"

        return False, "direct"

    def auto_add_domain(self, domain):
        with self.lock:
            if domain in self.zapret_domains or domain in self.user_domains or domain in self.auto_added_domains:
                return
            self.auto_added_domains.add(domain)

        user_path = os.path.join(self.lists_dir, "list-general-user.txt")
        try:
            os.makedirs(self.lists_dir, exist_ok=True)
            with open(user_path, "a", encoding="utf-8") as f:
                f.write(f"{domain}\n")
            self.log(f"[SmartRouter] Домен {domain} добавлен в пользовательский список маршрутизации")
        except Exception:
            pass


def resolve_supercell_dot(domain):
    """
    Resolves Supercell game hostnames via NullsProxy DoT (port 853).
    Only applies to game servers (game.clashroyaleapp.com, game.brawlstarsgame.com, etc.).
    """
    domain_lower = domain.lower()
    if not any(domain_lower.startswith(p) for p in [
        "game.clashroyaleapp.com",
        "game.brawlstarsgame.com",
        "game.clashofclans.com",
        "game.squadbustersgame.com"
    ]):
        return None

    now = time.time()
    with DNS_CACHE_LOCK:
        if domain in DNS_CACHE:
            cached_ip, expire_time = DNS_CACHE[domain]
            if now < expire_time:
                return cached_ip

    import ssl, struct
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        ss = ctx.wrap_socket(s)
        ss.connect(('45.139.239.54', 853))

        ID = 0x55aa
        flags = 0x0100
        header = struct.pack('!HHHHHH', ID, flags, 1, 0, 0, 0)
        qname = b''
        for part in domain.split('.'):
            qname += bytes([len(part)]) + part.encode('ascii')
        qname += b'\x00'
        q = header + qname + struct.pack('!HH', 1, 1)

        ss.sendall(struct.pack('!H', len(q)) + q)
        resp_len = struct.unpack('!H', ss.recv(2))[0]
        data = b''
        while len(data) < resp_len:
            chunk = ss.recv(resp_len - len(data))
            if not chunk: break
            data += chunk
        ss.close()

        offset = 12
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 5
        while offset < len(data):
            if offset + 12 > len(data): break
            if data[offset] & 0xc0 == 0xc0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset+10])
            offset += 10
            if rtype == 1 and rdlen == 4:
                ip = socket.inet_ntoa(data[offset:offset+4])
                with DNS_CACHE_LOCK:
                    DNS_CACHE[domain] = (ip, now + 1200)
                return ip
            offset += rdlen
    except Exception:
        pass

    fallback_ip = None
    if 'brawlstars' in domain:
        fallback_ip = '62.233.36.84'
    elif 'clashroyale' in domain:
        fallback_ip = '81.17.20.82'

    if fallback_ip:
        with DNS_CACHE_LOCK:
            DNS_CACHE[domain] = (fallback_ip, now + 1200)
        return fallback_ip

    return None


def resolve_candidate_ips(hostname, route_via_zapret):
    """
    Returns an ordered list of candidate IPv4 strings for hostname.
    Uses DoH (Cloudflare / Google) for optimized routing endpoints.
    """
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return [hostname]

    now = time.time()
    with DNS_CACHE_LOCK:
        if hostname in DNS_CACHE:
            cached_ip, expire_time = DNS_CACHE[hostname]
            if now < expire_time and cached_ip not in INVALID_ROUTE_IPS:
                return [cached_ip]

    # Mobile gaming server optimization
    if any(hostname.lower().startswith(p) for p in ["game.clashroyaleapp.com", "game.brawlstarsgame.com", "game.clashofclans.com", "game.squadbustersgame.com"]):
        sc_ip = resolve_supercell_dot(hostname)
        if sc_ip:
            return [sc_ip]

    candidates = []

    # 1. Query DoH (Cloudflare / Google) for prioritized services
    if route_via_zapret:
        for url in [
            f"https://1.1.1.1/dns-query?name={hostname}&type=A",
            f"https://dns.google/resolve?name={hostname}&type=A"
        ]:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/dns-json", "User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    data = json.loads(resp.read().decode())
                    for a in data.get("Answer", []):
                        if a.get("type") == 1:
                            ip = a.get("data", "").strip()
                            if ip and ip not in INVALID_ROUTE_IPS and ip not in candidates:
                                candidates.append(ip)
                if candidates:
                    break
            except Exception:
                pass

    # 2. Standard system DNS via getaddrinfo
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        for ai in addr_info:
            ip = ai[4][0]
            if ip and ip not in INVALID_ROUTE_IPS and ip not in candidates:
                candidates.append(ip)
    except Exception:
        pass

    # 3. Fallback to DoH if candidates is empty
    if not candidates:
        for url in [
            f"https://1.1.1.1/dns-query?name={hostname}&type=A",
            f"https://dns.google/resolve?name={hostname}&type=A"
        ]:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/dns-json", "User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    data = json.loads(resp.read().decode())
                    for a in data.get("Answer", []):
                        if a.get("type") == 1:
                            ip = a.get("data", "").strip()
                            if ip and ip not in INVALID_ROUTE_IPS and ip not in candidates:
                                candidates.append(ip)
                if candidates:
                    break
            except Exception:
                pass

    return candidates or [hostname]


def connect_to_remote(hostname, port, route_via_zapret):
    """
    Attempts to connect to hostname:port using candidate IPs.
    Fast failover across candidates (2.5s per IP) to ensure smooth streaming.
    """
    candidates = resolve_candidate_ips(hostname, route_via_zapret)
    for tip in candidates:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(2.5)
            s.connect((tip, port))
            with DNS_CACHE_LOCK:
                DNS_CACHE[hostname] = (tip, time.time() + 600)
            return s, tip
        except Exception:
            try: s.close()
            except Exception: pass
            continue
    return None, None


class ZapretTVBridge:
    def __init__(self, host="0.0.0.0", port=8080, tg_port=1443, log_file=None, enable_tg=True):
        self.host = host
        self.port = port
        self.tg_port = tg_port
        self.local_ip = get_local_ip()
        self.log_file = log_file
        self.enable_tg = enable_tg
        self.running = True

        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.tg_secret = get_or_create_tg_secret(self.base_dir)
        self.filter = SmartRoutingFilter(self.base_dir, log_func=self.log)

    def log(self, message):
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        formatted = f"{timestamp} {message}"
        try:
            print(formatted, flush=True)
        except Exception:
            pass
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(formatted + "\n")
            except Exception:
                pass

    def generate_pac_script(self):
        """
        Generates standard PAC autoconfig for iPhone, iPad, Mac, Windows.
        Directs optimized streaming traffic through the bridge proxy, and domestic services to DIRECT.
        """
        pac_body = f"""function FindProxyForURL(url, host) {{
    var proxy = "PROXY {self.local_ip}:{self.port}; DIRECT";
    var hostLower = host.toLowerCase();

    // YouTube & Streaming Video
    if (shExpMatch(hostLower, "*googlevideo.com*") ||
        shExpMatch(hostLower, "*youtube.com*") ||
        shExpMatch(hostLower, "*ytimg.com*") ||
        shExpMatch(hostLower, "*ggpht.com*") ||
        shExpMatch(hostLower, "*youtu.be*")) {{
        return proxy;
    }}

    // Supercell Services -> DIRECT
    if (shExpMatch(hostLower, "*supercell*") ||
        shExpMatch(hostLower, "*clashroyale*") ||
        shExpMatch(hostLower, "*brawlstars*") ||
        shExpMatch(hostLower, "*clashofclans*")) {{
        return "DIRECT";
    }}

    // Media & Social Platforms
    if (shExpMatch(hostLower, "*instagram*") ||
        shExpMatch(hostLower, "*cdninstagram*") ||
        shExpMatch(hostLower, "*fbcdn*") ||
        shExpMatch(hostLower, "*facebook*") ||
        shExpMatch(hostLower, "*threads*") ||
        shExpMatch(hostLower, "*meta.com*") ||
        shExpMatch(hostLower, "*ig.me*") ||
        shExpMatch(hostLower, "*fbsbx*") ||
        shExpMatch(hostLower, "*discord*") ||
        shExpMatch(hostLower, "*twitter*") ||
        shExpMatch(hostLower, "*x.com*")) {{
        return proxy;
    }}

    // Apple core services -> DIRECT
    if (shExpMatch(hostLower, "*apple.com*") ||
        shExpMatch(hostLower, "*itunes.com*") ||
        shExpMatch(hostLower, "*mzstatic.com*") ||
        shExpMatch(hostLower, "*icloud.com*") ||
        shExpMatch(hostLower, "*aaplimg.com*") ||
        shExpMatch(hostLower, "*akadns.net*")) {{
        return "DIRECT";
    }}

    // Local / Intranet / LAN
    if (isPlainHostName(host) ||
        shExpMatch(hostLower, "*.local") ||
        shExpMatch(hostLower, "*.lan") ||
        shExpMatch(hostLower, "10.*") ||
        shExpMatch(hostLower, "172.16.*") ||
        shExpMatch(hostLower, "172.17.*") ||
        shExpMatch(hostLower, "172.18.*") ||
        shExpMatch(hostLower, "172.19.*") ||
        shExpMatch(hostLower, "172.2*") ||
        shExpMatch(hostLower, "172.3*") ||
        shExpMatch(hostLower, "192.168.*") ||
        shExpMatch(hostLower, "127.*")) {{
        return "DIRECT";
    }}

    // Domestic services -> DIRECT
    if (shExpMatch(hostLower, "*.ru") &&
        (shExpMatch(hostLower, "*yandex*") ||
         shExpMatch(hostLower, "*vk.com*") ||
         shExpMatch(hostLower, "*gosuslugi*") ||
         shExpMatch(hostLower, "*sber*") ||
         shExpMatch(hostLower, "*ozon*") ||
         shExpMatch(hostLower, "*wildberries*") ||
         shExpMatch(hostLower, "*tinkoff*") ||
         shExpMatch(hostLower, "*mail.ru*"))) {{
        return "DIRECT";
    }}

    return proxy;
}}
"""
        return pac_body

    def handle_client(self, client_sock, client_addr):
        server_sock = None
        try:
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_sock.settimeout(15.0)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                request += chunk
                if len(request) > 65536:
                    break

            if not request:
                return

            first_line = request.split(b"\r\n")[0].decode('latin1', errors='ignore')
            parts = first_line.split()
            if len(parts) < 2:
                return

            method, target = parts[0].upper(), parts[1]

            # Parse headers for Host
            headers = request.split(b"\r\n\r\n")[0]
            host_header = None
            for line in headers.split(b"\r\n")[1:]:
                if line.lower().startswith(b"host:"):
                    host_header = line.split(b":", 1)[1].strip().decode('latin1', errors='ignore')
                    break

            # Normalize request path
            path = target
            if "://" in path:
                try:
                    import urllib.parse
                    parsed_u = urllib.parse.urlparse(path)
                    path = parsed_u.path or "/"
                except Exception:
                    path = "/"

            clean_path = path.split("?")[0].rstrip("/")
            if not clean_path:
                clean_path = "/"

            # Check if this request is addressed directly to this proxy server itself
            self_names = {"127.0.0.1", "localhost", "0.0.0.0", self.local_ip.lower()}
            is_addressed_to_self = False
            if host_header:
                h_name = host_header.split(":")[0].strip().lower()
                h_port = int(host_header.split(":")[1]) if ":" in host_header else 80
                if h_name in self_names and (h_port == self.port or h_port == 80):
                    is_addressed_to_self = True
            elif target.startswith("/") or not (target.startswith("http://") or target.startswith("https://")):
                is_addressed_to_self = True

            # 1. PAC Autoconfig HTTP requests
            if method == "GET" and clean_path in ["/proxy.pac", "/anticensority.pac", "/pac", "/wpad.dat"]:
                pac_content = self.generate_pac_script().encode('utf-8')
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n"
                    b"Connection: close\r\n"
                    + f"Content-Length: {len(pac_content)}\r\n\r\n".encode('ascii')
                    + pac_content
                )
                client_sock.sendall(resp)
                try: client_sock.shutdown(socket.SHUT_WR)
                except Exception: pass
                self.log(f"[PAC] Выдан PAC-скрипт клиенту {client_addr[0]}")
                return

            # 2. Supercell MobileConfig Profile for iOS
            if method == "GET" and clean_path in ["/supercell.mobileconfig", "/brawlstars.mobileconfig", "/clashroyale.mobileconfig", "/nullsproxy.mobileconfig"]:
                profile_path = os.path.join(self.base_dir, "supercell.mobileconfig")
                if os.path.exists(profile_path):
                    try:
                        with open(profile_path, "rb") as f:
                            prof_data = f.read()
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: application/x-apple-aspen-config; charset=utf-8\r\n"
                            b"Content-Disposition: attachment; filename=\"Supercell_Gaming.mobileconfig\"\r\n"
                            b"Connection: close\r\n"
                            + f"Content-Length: {len(prof_data)}\r\n\r\n".encode('ascii')
                            + prof_data
                        )
                        client_sock.sendall(resp)
                        try: client_sock.shutdown(socket.SHUT_WR)
                        except Exception: pass
                        self.log(f"[PROFILE] Выдан игровой профиль Supercell клиенту {client_addr[0]}")
                        return
                    except Exception as e:
                        self.log(f"[ERROR] Не удалось отправить профиль: {e}")

            # 3. Favicon request
            if method == "GET" and clean_path == "/favicon.ico":
                client_sock.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                try: client_sock.shutdown(socket.SHUT_WR)
                except Exception: pass
                return

            # 4. Proxy Status & Setup Dashboard HTTP Page
            if method == "GET" and is_addressed_to_self:
                html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zapret TV & Mobile Bridge</title>
<style>
  :root {{
    --bg: #090d16;
    --card-bg: #131b2e;
    --card-sub: #1e293b;
    --accent: #38bdf8;
    --accent-hover: #0284c7;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --border: #334155;
    --success: #10b981;
    --tg: #229ed9;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px 16px;
    line-height: 1.6;
    display: flex;
    justify-content: center;
  }}
  .container {{
    max-width: 640px;
    width: 100%;
  }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.4);
    margin-bottom: 20px;
  }}
  .header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
    flex-wrap: wrap;
    gap: 10px;
  }}
  h1 {{
    font-size: 22px;
    color: var(--accent);
    font-weight: 700;
  }}
  .badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    background: rgba(16, 185, 129, 0.2);
    color: var(--success);
    border: 1px solid var(--success);
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
  }}
  .badge::before {{
    content: "";
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 8px var(--success);
  }}
  .desc {{
    font-size: 14px;
    color: var(--text-muted);
    margin-bottom: 20px;
  }}
  .section {{
    background: var(--card-sub);
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 16px;
    border: 1px solid rgba(255,255,255,0.05);
  }}
  .section-title {{
    font-size: 16px;
    font-weight: 600;
    color: #e2e8f0;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .val-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #0f172a;
    padding: 8px 12px;
    border-radius: 8px;
    margin-top: 8px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 14px;
    word-break: break-all;
  }}
  .val-row code {{
    color: var(--accent);
  }}
  .copy-btn {{
    background: #334155;
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    margin-left: 10px;
    white-space: nowrap;
    transition: background 0.2s;
  }}
  .copy-btn:hover {{
    background: #475569;
  }}
  .btn {{
    display: inline-block;
    background: var(--accent);
    color: #0f172a;
    font-weight: 700;
    padding: 10px 16px;
    border-radius: 8px;
    text-decoration: none;
    font-size: 14px;
    transition: background 0.2s, transform 0.1s;
    text-align: center;
    cursor: pointer;
    border: none;
  }}
  .btn:hover {{
    background: var(--accent-hover);
    color: #fff;
  }}
  .btn-tg {{
    background: var(--tg);
    color: #fff;
  }}
  .btn-tg:hover {{
    background: #1d8bc0;
  }}
  .btn-group {{
    display: flex;
    gap: 10px;
    margin-top: 12px;
    flex-wrap: wrap;
  }}
  .info-text {{
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 8px;
  }}
  footer {{
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 20px;
  }}
</style>
<script>
function copyText(val, btn) {{
  navigator.clipboard.writeText(val).then(() => {{
    const old = btn.innerText;
    btn.innerText = "Скопировано!";
    setTimeout(() => {{ btn.innerText = old; }}, 1500);
  }});
}}
</script>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="header">
      <h1>Zapret TV & Mobile Bridge</h1>
      <span class="badge">РАБОТАЕТ</span>
    </div>
    <p class="desc">
      Локальный сетевой шлюз и прокси-мост с поддержкой <strong>Умной маршрутизации трафика</strong> (Smart Routing). Оптимизирует потоковое видео и медиа-сервисы через Zapret на ПК.
    </p>

    <!-- Section 1: PAC Autoconfig for iOS / macOS / Windows -->
    <div class="section">
      <div class="section-title">1. Автоконфигурация PAC (iOS / iPad / Mac / Windows)</div>
      <p class="info-text">В настройках сети Wi-Fi выберите <strong>Настройка прокси -> Автоматически</strong> и укажите URL:</p>
      <div class="val-row">
        <code>http://{self.local_ip}:{self.port}/proxy.pac</code>
        <button class="copy-btn" onclick="copyText('http://{self.local_ip}:{self.port}/proxy.pac', this)">Копировать</button>
      </div>
    </div>

    <!-- Section 2: Manual HTTP Proxy for Smart TVs -->
    <div class="section">
      <div class="section-title">2. Smart TV (LG webOS / Android TV / Apple TV)</div>
      <p class="info-text">В расширенных настройках сети телевизора выберите <strong>Прокси (HTTP)</strong>:</p>
      <div class="val-row">
        <span>IP сервера: <code>{self.local_ip}</code></span>
        <button class="copy-btn" onclick="copyText('{self.local_ip}', this)">Копировать IP</button>
      </div>
      <div class="val-row" style="margin-top: 6px;">
        <span>Порт: <code>{self.port}</code></span>
        <button class="copy-btn" onclick="copyText('{self.port}', this)">Копировать порт</button>
      </div>
    </div>

    <!-- Section 3: Telegram MTProto WebSocket -->
    <div class="section">
      <div class="section-title">3. Telegram MTProto Proxy (1 клик)</div>
      <p class="info-text">Стабильное прямое подключение Telegram без задержек (поддерживает любые аккаунты):</p>
      <div class="btn-group">
        <a class="btn btn-tg" href="tg://proxy?server={self.local_ip}&port={self.tg_port}&secret=dd{self.tg_secret}">Подключить в Telegram</a>
        <a class="btn" style="background: #334155; color: #fff;" href="https://t.me/proxy?server={self.local_ip}&port={self.tg_port}&secret=dd{self.tg_secret}" target="_blank">Ссылка t.me</a>
      </div>
      <div class="val-row" style="margin-top: 10px;">
        <span>Секрет: <code>dd{self.tg_secret}</code></span>
        <button class="copy-btn" onclick="copyText('dd{self.tg_secret}', this)">Копировать</button>
      </div>
    </div>

    <!-- Section 4: Supercell Gaming Profile -->
    <div class="section">
      <div class="section-title">4. Brawl Stars & Clash Royale (DNS-профиль)</div>
      <p class="info-text">Для оптимального прямого подключения на iOS скачайте игровой сетевой профиль:</p>
      <div class="btn-group">
        <a class="btn" href="/supercell.mobileconfig">Скачать профиль для iOS</a>
      </div>
      <p class="info-text" style="font-size: 12px; margin-top: 8px;">
        После загрузки: <em>Настройки -> Профиль загружен -> Установить</em>.
      </p>
    </div>

    <footer>
      Zapret TV & Mobile Bridge &bull; Локальный хост: {self.local_ip}:{self.port}
    </footer>
  </div>
</div>
</body>
</html>""".encode('utf-8')
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Connection: close\r\n"
                    + f"Content-Length: {len(html)}\r\n\r\n".encode('ascii')
                    + html
                )
                client_sock.sendall(resp)
                try: client_sock.shutdown(socket.SHUT_WR)
                except Exception: pass
                return

            # 5. CONNECT Tunnel (HTTPS / YouTube / Media services)
            if method == "CONNECT":
                if ":" in target:
                    remote_host, remote_port_s = target.split(":")
                    remote_port = int(remote_port_s)
                else:
                    remote_host = target
                    remote_port = 443

                route_via_zapret, reason = self.filter.should_route(remote_host)

                server_sock, target_ip = connect_to_remote(remote_host, remote_port, route_via_zapret)
                if not server_sock:
                    self.log(f"[ERROR] Не удалось подключиться к {remote_host}:{remote_port}")
                    try:
                        client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    except Exception:
                        pass
                    return

                tag = f" [МАРШРУТ: {'ZAPRET' if route_via_zapret else 'DIRECT'} ({reason}) -> {target_ip}]"
                self.log(f"[CONNECT] {client_addr[0]} -> {remote_host}:{remote_port}{tag}")

                server_sock.settimeout(None)
                client_sock.settimeout(None)

                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.pipe_sockets(client_sock, server_sock)

            # 6. Plain HTTP Proxy
            else:
                headers = request.split(b"\r\n\r\n")[0]
                host = None
                port = 80
                for line in headers.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"host:"):
                        h_val = line.split(b":", 1)[1].strip().decode('latin1')
                        if ":" in h_val:
                            host, port_s = h_val.split(":")
                            port = int(port_s)
                        else:
                            host = h_val
                        break

                if not host:
                    return

                if host.lower() in self_names and (port == self.port or port == 80):
                    return

                route_via_zapret, reason = self.filter.should_route(host)

                server_sock, target_ip = connect_to_remote(host, port, route_via_zapret)
                if not server_sock:
                    self.log(f"[ERROR] Не удалось подключиться к {host}:{port}")
                    try:
                        client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    except Exception:
                        pass
                    return

                tag = f" [МАРШРУТ: {'ZAPRET' if route_via_zapret else 'DIRECT'} ({reason}) -> {target_ip}]"
                self.log(f"[HTTP] {client_addr[0]} -> {host}:{port}{tag}")

                server_sock.settimeout(None)
                client_sock.settimeout(None)

                rel_request = request
                if b"://" in first_line.encode('latin1'):
                    try:
                        import urllib.parse
                        u = urllib.parse.urlparse(target)
                        rel_path = u.path or "/"
                        if u.query:
                            rel_path += "?" + u.query
                        new_first_line = f"{method} {rel_path} HTTP/1.1\r\n".encode('latin1')
                        rel_request = new_first_line + request.split(b"\r\n", 1)[1]
                    except Exception:
                        rel_request = request

                server_sock.sendall(rel_request)
                self.pipe_sockets(client_sock, server_sock)

        except Exception:
            pass
        finally:
            if client_sock:
                try: client_sock.close()
                except Exception: pass
            if server_sock:
                try: server_sock.close()
                except Exception: pass

    def pipe_sockets(self, s1, s2):
        socks = [s1, s2]
        while self.running:
            try:
                r, _, x = select.select(socks, [], socks, 60.0)
                if not r or x:
                    break
                for s in r:
                    other = s2 if s is s1 else s1
                    try:
                        data = s.recv(131072)
                        if not data:
                            return
                        other.sendall(data)
                    except Exception:
                        return
            except Exception:
                break

    def run(self, pid_file=None, ip_file=None):
        if os.name == 'nt':
            try:
                os.system('chcp 65001 >nul 2>&1')
            except Exception:
                pass

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Port conflict handling: verify port availability
        try:
            server.bind((self.host, self.port))
        except OSError as e:
            self.log(f"[WARN] Порт {self.port} занят. Поиск свободного порта...")
            alt_port = find_available_port(self.port + 1, self.host)
            if alt_port:
                self.port = alt_port
                server.bind((self.host, self.port))
                self.log(f"[*] Выбран альтернативный порт: {self.port}")
            else:
                self.log(f"[FATAL] Не удалось занять порт {self.port} и альтернативные порты: {e}")
                raise

        server.listen(512)

        if pid_file:
            try:
                with open(pid_file, "w", encoding="utf-8") as f:
                    f.write(str(os.getpid()))
            except Exception:
                pass

        if ip_file:
            try:
                with open(ip_file, "w", encoding="utf-8") as f:
                    f.write(f"{self.local_ip}:{self.port}")
            except Exception:
                pass

        self.log(f"[*] Zapret TV Bridge запущен на {self.host}:{self.port}")
        self.log(f"[*] Локальный адрес для ТВ и телефонов: {self.local_ip}:{self.port}")
        self.log(f"[*] PAC автоконфигурация: http://{self.local_ip}:{self.port}/proxy.pac")
        self.log(f"[*] Режим: Умная маршрутизация потокового медиа активна")

        # Launch Telegram WS Proxy (Flowseal/tg-ws-proxy)
        tg_proc = None
        if self.enable_tg:
            tg_dir = os.path.join(self.base_dir, "tg_ws_proxy")
            if os.path.exists(tg_dir):
                if not is_port_available(self.tg_port, "0.0.0.0"):
                    alt_tg = find_available_port(self.tg_port + 1, "0.0.0.0")
                    if alt_tg:
                        self.tg_port = alt_tg
                try:
                    tg_log = os.path.join(self.base_dir, "tg_proxy.log")
                    py_bin = sys.executable
                    if "python.exe" in py_bin.lower():
                        pyw_candidate = py_bin.lower().replace("python.exe", "pythonw.exe")
                        if os.path.exists(pyw_candidate):
                            py_bin = pyw_candidate
                    tg_cmd = [
                        py_bin, "-m", "proxy.tg_ws_proxy",
                        "--host", "0.0.0.0",
                        "--port", str(self.tg_port),
                        "--secret", self.tg_secret,
                        "--dc-ip", "2:149.154.167.220",
                        "--dc-ip", "4:149.154.167.220",
                        "--log-file", tg_log
                    ]
                    cflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                    tg_proc = subprocess.Popen(tg_cmd, cwd=tg_dir, creationflags=cflags)
                    self.log(f"[*] Telegram WS Proxy запущен на 0.0.0.0:{self.tg_port} [PID: {tg_proc.pid}]")
                    self.log(f"[*] Ссылка для Telegram на iPhone: tg://proxy?server={self.local_ip}&port={self.tg_port}&secret=dd{self.tg_secret}")
                except Exception as e:
                    self.log(f"[WARN] Не удалось запустить Telegram WS Proxy: {e}")

        try:
            while self.running:
                client_sock, client_addr = server.accept()
                t = threading.Thread(target=self.handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            self.log("[*] Остановка моста по сигналу...")
        except Exception as e:
            self.log(f"[ERROR] Ошибка в цикле приема соединений: {e}")
        finally:
            self.running = False
            if tg_proc:
                try:
                    tg_proc.terminate()
                    tg_proc.wait(timeout=2)
                except Exception:
                    pass
            try:
                server.close()
            except Exception:
                pass
            if pid_file and os.path.exists(pid_file):
                try: os.remove(pid_file)
                except Exception: pass
            if ip_file and os.path.exists(ip_file):
                try: os.remove(ip_file)
                except Exception: pass


def main():
    parser = argparse.ArgumentParser(description="Zapret TV & Mobile Bridge - Local Network Proxy")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP/PAC Proxy port (default: 8080)")
    parser.add_argument("--tg-port", type=int, default=1443, help="Telegram MTProto port (default: 1443)")
    parser.add_argument("--daemon", action="store_true", help="Run silently as background daemon")
    parser.add_argument("--no-tg", action="store_true", help="Disable Telegram MTProto bridge")
    args = parser.parse_args()

    cur_dir = os.path.dirname(os.path.abspath(__file__))
    pid_file = os.path.join(cur_dir, "tv_proxy.pid")
    log_file = os.path.join(cur_dir, "tv_proxy.log")
    ip_file = os.path.join(cur_dir, "tv_proxy.ip")

    if pid_file and os.path.exists(pid_file):
        try:
            with open(pid_file, "r", encoding="utf-8") as f:
                old_pid = int(f.read().strip())
            if old_pid != os.getpid():
                import ctypes
                h_proc = ctypes.windll.kernel32.OpenProcess(0x1000, False, old_pid)
                if h_proc:
                    ctypes.windll.kernel32.CloseHandle(h_proc)
                    print(f"[*] Zapret TV Bridge уже запущен в фоне (PID: {old_pid})")
                    sys.exit(0)
        except Exception:
            pass

    bridge = None
    try:
        bridge = ZapretTVBridge(
            host=args.host,
            port=args.port,
            tg_port=args.tg_port,
            log_file=log_file,
            enable_tg=not args.no_tg
        )
        bridge.run(pid_file=pid_file, ip_file=ip_file)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        if log_file:
            try:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [FATAL] {tb}\n")
            except Exception:
                pass
        if pid_file and os.path.exists(pid_file):
            try: os.remove(pid_file)
            except Exception: pass
        if ip_file and os.path.exists(ip_file):
            try: os.remove(ip_file)
            except Exception: pass
        sys.exit(1)


if __name__ == "__main__":
    main()
