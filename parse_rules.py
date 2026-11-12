#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_rules.py - Comprehensive Domain Parser & Synchronizer for Zapret TV Bridge
Parses AntiCensority / AntiZapret domain registry (660,000+ domains) and updates Zapret hostlists.
"""

import os
import sys
import json
import re
import urllib.request
import time

def get_base_dir():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(script_dir, "lists")):
        return script_dir
    parent = os.path.dirname(script_dir)
    if os.path.exists(os.path.join(parent, "lists")):
        return parent
    return script_dir

def normalize_domain(raw):
    if not raw:
        return None
    d = raw.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = re.sub(r'[:/].*$', '', d)
    d = d.strip().strip('.')
    if not d or '.' not in d:
        return None
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', d):
        return None
    for ign in [".local", ".lan", ".home", ".internal", ".in-addr.arpa", ".ip6.arpa"]:
        if d.endswith(ign):
            return None
    return d

def load_exclude_set(lists_dir):
    exc = set()
    for fname in ["list-exclude.txt", "list-exclude-user.txt"]:
        p = os.path.join(lists_dir, fname)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        norm = normalize_domain(line)
                        if norm:
                            exc.add(norm)
    return exc

def extract_from_json(json_path):
    if not os.path.exists(json_path):
        return set()
    print(f"[*] Чтение локальной базы правил: {json_path}")
    t0 = time.time()
    with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    domains = set()
    for k, v in data.items():
        if k.isdigit():
            L = int(k)
            for i in range(0, len(v), L):
                d = v[i:i+L].strip().lower()
                norm = normalize_domain(d)
                if norm:
                    domains.add(norm)
    print(f"[+] Извлечено {len(domains)} уникальных доменов за {time.time()-t0:.2f}с")
    return domains

def fetch_online_pac():
    urls = [
        "https://raw.githubusercontent.com/anticensority/generated-pac-scripts/master/anticensority.pac",
        "https://anticensority.github.io/generated-pac-scripts/anticensority.pac"
    ]
    print("[*] Загрузка актуального PAC-скрипта из сети...")
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r'const inputs = (\{.*?\});', content)
            if m:
                data = json.loads(m.group(1))
                hostnames = data.get("HOSTNAMES", {})
                domains = set()
                for k, v in hostnames.items():
                    if k.isdigit():
                        L = int(k)
                        for i in range(0, len(v), L):
                            d = v[i:i+L].strip().lower()
                            norm = normalize_domain(d)
                            if norm:
                                domains.add(norm)
                print(f"[+] Успешно скачано и распарсено {len(domains)} доменов из сети!")
                return domains, hostnames
        except Exception as e:
            print(f"[!] Ошибка загрузки из {url}: {e}")
    return set(), {}

def sync_hostlists(base_dir=None, online=False, category_filter=None):
    base = base_dir or get_base_dir()
    lists_dir = os.path.join(base, "lists")
    json_path = os.path.join(base, "routing_rules.json")
    gen_path = os.path.join(lists_dir, "list-general.txt")
    user_path = os.path.join(lists_dir, "list-general-user.txt")

    os.makedirs(lists_dir, exist_ok=True)
    exclude_set = load_exclude_set(lists_dir)

    all_domains = set()

    # 1. Load existing core domains from list-general.txt
    if os.path.exists(gen_path):
        with open(gen_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    norm = normalize_domain(line)
                    if norm:
                        all_domains.add(norm)
        print(f"[*] Сохранено {len(all_domains)} существующих доменов из list-general.txt")

    # 2. Extract from online PAC if requested
    if online:
        net_domains, net_dict = fetch_online_pac()
        if net_domains:
            all_domains.update(net_domains)
            # Update local json
            try:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(net_dict, f)
                print(f"[+] Обновлен файл {json_path}")
            except Exception as e:
                print(f"[!] Не удалось сохранить json: {e}")

    # 3. Extract from local routing_rules.json
    local_domains = extract_from_json(json_path)
    all_domains.update(local_domains)

    # 4. Filter against exclude list
    cleaned = [d for d in all_domains if d not in exclude_set]
    cleaned.sort()

    # 5. Write back to list-general.txt
    print(f"[*] Запись {len(cleaned)} доменов в {gen_path}...")
    t0 = time.time()
    with open(gen_path, "w", encoding="utf-8") as f:
        f.write("# Auto-generated comprehensive domain list by Zapret TV Bridge Parser\n")
        f.write(f"# Total domains: {len(cleaned)}\n\n")
        for d in cleaned:
            f.write(f"{d}\n")
    print(f"[+] Запись завершена за {time.time()-t0:.2f}с (размер файла: {os.path.getsize(gen_path)/(1024*1024):.1f} МБ)")

    # 6. Report popular categories included
    anime_count = sum(1 for d in cleaned if "anime" in d or "manga" in d or "booru" in d)
    media_count = sum(1 for d in cleaned if "video" in d or "tube" in d or "stream" in d)
    print(f"[i] Категории в базе: Аниме/Манга/Booru: {anime_count}, Медиа/Видео: {media_count}")
    return len(cleaned)

if __name__ == "__main__":
    online = "--online" in sys.argv or "--fetch" in sys.argv
    base = get_base_dir()
    count = sync_hostlists(base, online=online)
    print(f"\n[OK] Списки успешно синхронизированы: {count} доменов готовы к работе.")
