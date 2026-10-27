import os
import re

path = r'D:\projects\zapret-tv-bridge\zapret_tv_bridge.py'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# Replace sort
old_sort = """                def strategy_sort_key(p):
                    name = os.path.splitext(os.path.basename(p))[0].strip()
                    if name.lower() == "general":
                        return (0, 0, "")
                    if name.lower() == "general (alt)":
                        return (1, 1, "")
                    m_alt = re.match(r"general \(alt(\d+)\)", name, re.IGNORECASE)
                    if m_alt:
                        return (1, int(m_alt.group(1)), "")
                    if "exp" in name.lower():
                        return (2, 0, name.lower())
                    if "fake tls auto" in name.lower():
                        sub = 0
                        if "alt" in name.lower():
                            m_sub = re.search(r"alt(\d*)", name.lower())
                            sub = int(m_sub.group(1)) if m_sub and m_sub.group(1) else 1
                        return (3, sub, name.lower())
                    if "simple fake" in name.lower():
                        sub = 0
                        if "alt" in name.lower():
                            m_sub = re.search(r"alt(\d*)", name.lower())
                            sub = int(m_sub.group(1)) if m_sub and m_sub.group(1) else 1
                        return (4, sub, name.lower())
                    return (5, 0, name.lower())"""

new_sort = """                def strategy_sort_key(p):
                    name = os.path.splitext(os.path.basename(p))[0].strip()
                    name_l = name.lower()
                    if name_l == "general (alt)":
                        return (1, 1, "")
                    m_alt = re.match(r"^general \(alt(\d+)\)$", name_l)
                    if m_alt:
                        return (1, int(m_alt.group(1)), "")
                    if name_l == "general":
                        return (2, 0, "")
                    if "exp" in name_l:
                        return (3, 0, name_l)
                    if "fake tls auto" in name_l:
                        sub = 0
                        m_sub = re.search(r"alt(\d*)", name_l)
                        if m_sub:
                            sub = int(m_sub.group(1)) if m_sub.group(1) else 1
                        return (4, sub, name_l)
                    if "simple fake" in name_l:
                        sub = 0
                        m_sub = re.search(r"alt(\d*)", name_l)
                        if m_sub:
                            sub = int(m_sub.group(1)) if m_sub.group(1) else 1
                        return (5, sub, name_l)
                    return (6, 0, name_l)"""

assert old_sort in text, "old_sort not found!"
text = text.replace(old_sort, new_sort, 1)

old_install = """    if chosen_strategy is not None:
        if str(chosen_strategy).isdigit():
            idx = int(chosen_strategy) - 1
            if 0 <= idx < len(strategies):
                strategy_name, selected_bat = strategies[idx]
        else:
            for s_name, s_path in strategies:
                if s_name.lower() == str(chosen_strategy).lower() or os.path.basename(s_path).lower() == str(chosen_strategy).lower():
                    strategy_name, selected_bat = s_name, s_path
                    break

    if not selected_bat:
        print("\\n  ==================================================")
        print("  ВЫБОР СТРАТЕГИИ ZAPRET ДЛЯ УСТАНОВКИ СЛУЖБЫ")
        print("  ==================================================")
        for i, (name, path) in enumerate(strategies, 1):
            tag = ""
            if name == "general (ALT)":
                tag = " [Рекомендуется: Высокая скорость / Без потерь]"
            elif name == "general (ALT2)":
                tag = " [Альтернатива: Стабильная]"
            elif name == "general (FAKE TLS AUTO)":
                tag = " [Универсальная: Любые провайдеры]"
            print(f"     {i:2d}. {name}{tag}")
        print("  --------------------------------------------------")
        print("      0. Отмена")
        print()
        try:
            choice = input(f"  Выберите стратегию [1-{len(strategies)}, 0 для отмены]: ").strip()
        except (KeyboardInterrupt, EOFError):
            return False

        if choice == "0" or not choice:
            return False
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(strategies):
                strategy_name, selected_bat = strategies[idx]
            else:
                print("[!] Неверный номер стратегии.")
                return False
        else:
            print("[!] Неверный ввод.")
            return False"""

new_install = """    if chosen_strategy is not None:
        if str(chosen_strategy).isdigit():
            idx = int(chosen_strategy) - 1
            if 0 <= idx < len(strategies):
                strategy_name, selected_bat = strategies[idx]
        else:
            clean_strategy = str(chosen_strategy).strip().lower()
            for s_name, s_path in strategies:
                s_lower = s_name.lower()
                if (clean_strategy == s_lower or 
                    clean_strategy == os.path.splitext(os.path.basename(s_path))[0].lower() or
                    s_lower == f"general ({clean_strategy})" or
                    s_lower.replace(" ", "") == f"general({clean_strategy})"):
                    strategy_name, selected_bat = s_name, s_path
                    break

    if not selected_bat:
        print("\\n  ==================================================")
        print("  ВЫБОР СТРАТЕГИИ ZAPRET ДЛЯ УСТАНОВКИ СЛУЖБЫ")
        print("  ==================================================")
        for i, (name, path) in enumerate(strategies, 1):
            print(f"     {i:2d}. {name}")
        print("  --------------------------------------------------")
        print("      0. Отмена")
        print()
        try:
            choice = input(f"  Выберите стратегию [1-{len(strategies)}, 0 для отмены]: ").strip()
        except (KeyboardInterrupt, EOFError):
            return False

        if choice == "0" or not choice:
            return False
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(strategies):
                strategy_name, selected_bat = strategies[idx]
            else:
                print("[!] Неверный номер стратегии.")
                return False
        else:
            clean_choice = choice.strip().lower()
            for s_name, s_path in strategies:
                s_lower = s_name.lower()
                if (clean_choice == s_lower or 
                    clean_choice == os.path.splitext(os.path.basename(s_path))[0].lower() or
                    s_lower == f"general ({clean_choice})" or
                    s_lower.replace(" ", "") == f"general({clean_choice})"):
                    strategy_name, selected_bat = s_name, s_path
                    break
            if not selected_bat:
                print("[!] Неверный ввод.")
                return False"""

assert old_install in text, "old_install not found!"
text = text.replace(old_install, new_install, 1)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print("SUCCESS: zapret_tv_bridge.py updated")
