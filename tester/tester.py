#!/usr/bin/env python3
"""
tester.py - Script de testare pentru IDS-RS

Trimite pachete UDP catre IDS-RS simuland log-uri de firewall.

Preset-uri rapide (replay automat din fisierele sample pre-generate):
  python tester.py fast                     # Fast Scan GAIA
  python tester.py fast --cef               # Fast Scan CEF
  python tester.py slow                     # Slow Scan GAIA
  python tester.py slow --cef               # Slow Scan CEF
  python tester.py normal                   # Trafic normal GAIA
  python tester.py normal --cef             # Trafic normal CEF

Replay / sample (fisier la alegere):
  python tester.py replay tester/sample2_gaia.log
  python tester.py sample tester/sample2_gaia.log raw-gaia

Generare dinamica (avansat):
  python tester.py fast-scan --format gaia --ports 20 --delay 0.1
  python tester.py slow-scan --format gaia --ports 40
"""

import argparse
import ipaddress
import os
import re
import socket
import sys
import time
import random
from collections import Counter
from typing import Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# =============================================================================
# Generatoare de log-uri
# =============================================================================

def generate_gaia_log(source_ip: str, dst_port: int, action: str = "drop") -> str:
    """Genereaza un log Checkpoint Gaia in formatul REAL (cu header complet)."""
    src_port = random.randint(1024, 65535)
    second = random.randint(0, 59)
    return (
        f"Sep  3 15:12:{second:02d} 192.168.99.1 "
        f"Checkpoint: 3Sep2007 15:12:{second:02d} {action} "
        f"{source_ip} >eth8 rule: 134; "
        f"rule_uid: {{11111111-2222-3333-BD17-711F536C7C33}}; "
        f"service_id: port-scan; src: {source_ip}; dst: 10.0.0.1; "
        f"proto: tcp; product: VPN-1 & FireWall-1; "
        f"service: {dst_port}; s_port: {src_port};"
    )


def generate_cef_log(source_ip: str, dst_port: int, action: str = "drop") -> str:
    """Genereaza un log CEF (Common Event Format) realist cu syslog header."""
    severity = 5 if action == "drop" else 3
    name = "Drop" if action == "drop" else "Accept"
    ts = time.strftime("%b %d %H:%M:%S")
    return (
        f"<134>{ts} gw-checkpoint CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|{name}|{severity}|"
        f"src={source_ip} dst=192.168.1.1 dpt={dst_port} proto=TCP act={action}"
    )


def generate_log(fmt: str, source_ip: str, dst_port: int, action: str = "drop") -> str:
    """Genereaza un log in formatul specificat (gaia sau cef)."""
    if fmt == "cef":
        return generate_cef_log(source_ip, dst_port, action)
    return generate_gaia_log(source_ip, dst_port, action)


# =============================================================================
# Parsare GAIA (pentru sample mode)
# =============================================================================

# Regex pentru header-ul GAIA: extrage actiunea dupa checkpoint date+time.
_GAIA_HEADER_RE = re.compile(
    r"(?i)Checkpoint:\s+\S+\s+\S+\s+(accept|drop|reject)\s+"
)


def parse_gaia_line(line: str) -> Optional[dict]:
    """
    Parseaza o linie de log GAIA si extrage campurile relevante.

    Returneaza un dict cu: action, src, dst, proto, service, rule
    sau None daca linia nu este un log GAIA valid.
    """
    m = _GAIA_HEADER_RE.search(line)
    if not m:
        return None

    action = m.group(1).lower()

    # Zona de extensii: tot ce urmeaza dupa match-ul header-ului.
    extensions = line[m.end():]

    # Extragem campurile key-value separate prin ";"
    fields = {}
    for part in extensions.split(";"):
        part = part.strip()
        if ": " in part:
            key, _, value = part.partition(": ")
            fields[key.strip()] = value.strip()

    result = {"action": action}
    result["src"] = fields.get("src")
    result["dst"] = fields.get("dst")
    result["proto"] = fields.get("proto")
    result["service"] = fields.get("service")
    result["rule"] = fields.get("rule") or fields.get("rule_uid")

    return result


def gaia_to_cef(parsed: dict) -> Optional[str]:
    """
    Converteste campurile parsate din GAIA in format CEF.

    Returneaza un string CEF sau None daca campuri esentiale lipsesc.
    """
    src = parsed.get("src")
    dst = parsed.get("dst")
    action = parsed.get("action", "drop")
    proto = (parsed.get("proto") or "tcp").upper()
    service = parsed.get("service")
    rule = parsed.get("rule") or "100"

    if not src or not dst:
        return None

    severity = 5 if action == "drop" else 3
    name = action.capitalize()

    ts = time.strftime("%b %d %H:%M:%S")
    parts = [
        f"<134>{ts} gw-checkpoint CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|{rule}|{name}|{severity}|",
        f"src={src} dst={dst}",
    ]
    if service:
        parts.append(f"dpt={service}")
    parts.append(f"proto={proto} act={action}")

    return " ".join(parts)


# =============================================================================
# Utilitar UDP
# =============================================================================

def send_udp(sock: socket.socket, host: str, port: int, message: str) -> None:
    """Trimite un mesaj UDP catre IDS-RS."""
    sock.sendto(message.encode("utf-8"), (host, port))


# =============================================================================
# Simulari
# =============================================================================

def simulate_fast_scan(
    sock: socket.socket,
    host: str,
    port: int,
    source_ip: str,
    num_ports: int,
    delay: float,
    batch_size: int,
    fmt: str,
) -> None:
    """
    Simuleaza un Fast Scan: trimite log-uri de tip 'drop' cu porturi unice
    diferite de la acelasi IP sursa, intr-un interval scurt.

    Pragul default din config.toml: >15 porturi in 10 secunde.
    """
    print(f"[*] Simulare FAST SCAN de la {source_ip} (format: {fmt.upper()})")
    print(f"    Porturi: {num_ports} | Delay: {delay}s | Batch: {batch_size}")
    print(f"    Destinatie: {host}:{port}")
    print()

    ports = random.sample(range(1, 65536), min(num_ports, 65535))

    batch_buffer = []
    sent_count = 0

    for i, dst_port in enumerate(ports):
        log_line = generate_log(fmt, source_ip, dst_port, "drop")
        batch_buffer.append(log_line)

        if len(batch_buffer) >= batch_size or i == len(ports) - 1:
            message = "\n".join(batch_buffer)
            send_udp(sock, host, port, message)
            sent_count += len(batch_buffer)

            print(
                f"  [{sent_count:>4}/{num_ports}] "
                f"Trimis {len(batch_buffer)} log(uri) | "
                f"Ultimul port: {dst_port}"
            )

            batch_buffer.clear()

            if delay > 0 and i < len(ports) - 1:
                time.sleep(delay)

    print()
    print(f"[+] Fast Scan complet: {sent_count} log-uri trimise ({fmt.upper()})")
    print(f"    IDS-RS ar trebui sa detecteze scanarea daca pragul este < {num_ports}")


def simulate_slow_scan(
    sock: socket.socket,
    host: str,
    port: int,
    source_ip: str,
    num_ports: int,
    delay: float,
    batch_size: int,
    fmt: str,
) -> None:
    """
    Simuleaza un Slow Scan: trimite log-uri de tip 'drop' distribuite
    pe un interval mai lung, cu delay mare intre pachete.

    Pragul default din config.toml: >30 porturi in 5 minute.
    """
    total_time_est = num_ports * delay / max(batch_size, 1)
    print(f"[*] Simulare SLOW SCAN de la {source_ip} (format: {fmt.upper()})")
    print(f"    Porturi: {num_ports} | Delay: {delay}s | Batch: {batch_size}")
    print(f"    Timp estimat: ~{total_time_est:.0f}s ({total_time_est / 60:.1f} min)")
    print(f"    Destinatie: {host}:{port}")
    print()

    ports = random.sample(range(1, 65536), min(num_ports, 65535))

    batch_buffer = []
    sent_count = 0
    start_time = time.time()

    for i, dst_port in enumerate(ports):
        log_line = generate_log(fmt, source_ip, dst_port, "drop")
        batch_buffer.append(log_line)

        if len(batch_buffer) >= batch_size or i == len(ports) - 1:
            message = "\n".join(batch_buffer)
            send_udp(sock, host, port, message)
            sent_count += len(batch_buffer)

            elapsed = time.time() - start_time
            print(
                f"  [{sent_count:>4}/{num_ports}] "
                f"Port: {dst_port:<5} | "
                f"Elapsed: {elapsed:.1f}s"
            )

            batch_buffer.clear()

            if delay > 0 and i < len(ports) - 1:
                time.sleep(delay)

    elapsed = time.time() - start_time
    print()
    print(f"[+] Slow Scan complet: {sent_count} log-uri in {elapsed:.1f}s ({fmt.upper()})")
    print(f"    IDS-RS ar trebui sa detecteze scanarea daca pragul este < {num_ports}")


def simulate_normal(
    sock: socket.socket,
    host: str,
    port: int,
    source_ip: str,
    count: int,
    fmt: str,
) -> None:
    """
    Trimite trafic normal (drop-uri pe porturi comune) sub pragul de detectie.
    Util pentru a verifica ca IDS-ul NU genereaza alerte false.
    """
    print(f"[*] Trimitere trafic NORMAL de la {source_ip} (format: {fmt.upper()})")
    print(f"    Log-uri: {count} | Destinatie: {host}:{port}")
    print()

    # Porturi comune care ar putea fi blocate in mod normal de firewall.
    common_ports = [22, 80, 443, 8080, 3389, 25, 53, 110, 143, 993]
    # Selectam porturi din lista comuna (cu repetitii posibile).
    ports = [random.choice(common_ports) for _ in range(count)]

    for i, dst_port in enumerate(ports):
        log_line = generate_log(fmt, source_ip, dst_port, "drop")
        send_udp(sock, host, port, log_line)
        print(f"  [{i + 1:>4}/{count}] Port: {dst_port} | {log_line[:70]}...")
        time.sleep(random.uniform(0.5, 2.0))

    unique_ports = len(set(ports))
    print()
    print(f"[+] Trafic normal complet: {count} log-uri, {unique_ports} porturi unice ({fmt.upper()})")
    print(f"    IDS-RS NU ar trebui sa genereze alerte (sub prag)")


def replay_file(
    sock: socket.socket,
    host: str,
    port: int,
    file_path: str,
    delay: float,
    batch_size: int,
) -> None:
    """
    Citeste un fisier cu log-uri si trimite fiecare linie catre IDS-RS.
    Formatul log-urilor trebuie sa corespunda parser-ului activ in config.toml.
    """
    print(f"[*] Replay log-uri din: {file_path}")
    print(f"    Delay: {delay}s | Batch: {batch_size}")
    print(f"    Destinatie: {host}:{port}")
    print()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n\r") for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Eroare: fisierul '{file_path}' nu exista.")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Eroare: nu am permisiuni pentru '{file_path}'.")
        sys.exit(1)

    total = len(lines)
    if total == 0:
        print("[!] Fisierul este gol. Nimic de trimis.")
        return

    print(f"    Linii incarcate: {total}")
    print()

    batch_buffer = []
    sent_count = 0

    for i, line in enumerate(lines):
        batch_buffer.append(line)

        if len(batch_buffer) >= batch_size or i == len(lines) - 1:
            message = "\n".join(batch_buffer)
            send_udp(sock, host, port, message)
            sent_count += len(batch_buffer)

            # Afisam prima linie din batch (trunchiat).
            preview = batch_buffer[0][:70]
            print(
                f"  [{sent_count:>4}/{total}] "
                f"Trimis {len(batch_buffer)} linie(i) | "
                f"{preview}..."
            )

            batch_buffer.clear()

            if delay > 0 and i < len(lines) - 1:
                time.sleep(delay)

    print()
    print(f"[+] Replay complet: {sent_count} log-uri trimise din '{file_path}'")


# =============================================================================
# Sample Mode
# =============================================================================

def _load_sample_file(file_path: str) -> list[str]:
    """Incarca liniile non-goale dintr-un fisier sample."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.rstrip("\n\r") for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Eroare: fisierul '{file_path}' nu exista.")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Eroare: nu am permisiuni pentru '{file_path}'.")
        sys.exit(1)


def _extract_drops(lines: list[str]) -> list[dict]:
    """Parseaza liniile si returneaza doar drop-urile cu src si service."""
    drops = []
    for line in lines:
        parsed = parse_gaia_line(line)
        if parsed and parsed["action"] == "drop" and parsed["src"] and parsed["service"]:
            parsed["_raw"] = line
            drops.append(parsed)
    return drops


def sample_raw_gaia(
    sock: socket.socket,
    host: str,
    port: int,
    lines: list[str],
    delay: float,
    batch_size: int,
) -> None:
    """Trimite liniile GAIA as-is (replay cu filtrare pe linii valide)."""
    valid_lines = [l for l in lines if _GAIA_HEADER_RE.search(l)]
    total = len(valid_lines)
    print(f"[*] Sample RAW-GAIA: {total} linii valide din {len(lines)} total")
    print()

    batch_buffer = []
    sent_count = 0

    for i, line in enumerate(valid_lines):
        batch_buffer.append(line)
        if len(batch_buffer) >= batch_size or i == total - 1:
            message = "\n".join(batch_buffer)
            send_udp(sock, host, port, message)
            sent_count += len(batch_buffer)
            print(f"  [{sent_count:>4}/{total}] Trimis {len(batch_buffer)} linie(i)")
            batch_buffer.clear()
            if delay > 0 and i < total - 1:
                time.sleep(delay)

    print()
    print(f"[+] Raw-GAIA complet: {sent_count} log-uri trimise")


def sample_raw_cef(
    sock: socket.socket,
    host: str,
    port: int,
    lines: list[str],
    delay: float,
    batch_size: int,
) -> None:
    """Parseaza fiecare linie GAIA, converteste la CEF si trimite."""
    cef_lines = []
    for line in lines:
        parsed = parse_gaia_line(line)
        if parsed:
            cef = gaia_to_cef(parsed)
            if cef:
                cef_lines.append(cef)

    total = len(cef_lines)
    print(f"[*] Sample RAW-CEF: {total} linii convertite din {len(lines)} total")
    print()

    batch_buffer = []
    sent_count = 0

    for i, line in enumerate(cef_lines):
        batch_buffer.append(line)
        if len(batch_buffer) >= batch_size or i == total - 1:
            message = "\n".join(batch_buffer)
            send_udp(sock, host, port, message)
            sent_count += len(batch_buffer)
            print(f"  [{sent_count:>4}/{total}] Trimis {len(batch_buffer)} linie(i)")
            batch_buffer.clear()
            if delay > 0 and i < total - 1:
                time.sleep(delay)

    print()
    print(f"[+] Raw-CEF complet: {sent_count} log-uri trimise")


def _find_most_frequent_src(drops: list[dict]) -> str:
    """Gaseste IP-ul sursa cel mai frecvent din drop-uri."""
    src_counter = Counter(d["src"] for d in drops if d["src"])
    if not src_counter:
        return "192.168.11.34"
    return src_counter.most_common(1)[0][0]


def sample_scan(
    sock: socket.socket,
    host: str,
    port: int,
    lines: list[str],
    delay: float,
    batch_size: int,
    fmt: str,
    fast: bool,
) -> None:
    """
    Extrage drop-urile din sample, identifica IP-ul sursa cel mai frecvent
    si porturile reale, apoi genereaza log-uri noi (scan lent sau rapid).
    """
    drops = _extract_drops(lines)
    if not drops:
        print("[!] Nu s-au gasit drop-uri valide in fisier.")
        return

    source_ip = _find_most_frequent_src(drops)
    ports = list({int(d["service"]) for d in drops if d["service"] and d["service"].isdigit()})
    if not ports:
        print("[!] Nu s-au gasit porturi valide in drop-uri.")
        return

    scan_type = "FAST" if fast else "SLOW"
    actual_delay = delay if not fast else min(delay, 0.05)

    print(f"[*] Sample {scan_type}-SCAN ({fmt.upper()}) de la {source_ip}")
    print(f"    Porturi unice din sample: {len(ports)} | Delay: {actual_delay}s")
    print()

    batch_buffer = []
    sent_count = 0
    total = len(ports)

    for i, dst_port in enumerate(ports):
        log_line = generate_log(fmt, source_ip, dst_port, "drop")
        batch_buffer.append(log_line)

        if len(batch_buffer) >= batch_size or i == total - 1:
            message = "\n".join(batch_buffer)
            send_udp(sock, host, port, message)
            sent_count += len(batch_buffer)
            print(f"  [{sent_count:>4}/{total}] Port: {dst_port}")
            batch_buffer.clear()
            if actual_delay > 0 and i < total - 1:
                time.sleep(actual_delay)

    print()
    print(f"[+] {scan_type}-Scan complet: {sent_count} log-uri trimise ({fmt.upper()})")


def run_sample(
    sock: socket.socket,
    host: str,
    port: int,
    file_path: str,
    mode: str,
    delay: float,
    batch_size: int,
) -> None:
    """Dispatch-er pentru sample mode."""
    lines = _load_sample_file(file_path)
    if not lines:
        print("[!] Fisierul este gol.")
        return

    print(f"[*] Fisier incarcat: {file_path} ({len(lines)} linii)")
    print(f"    Mod: {mode} | Delay: {delay}s | Batch: {batch_size}")
    print(f"    Destinatie: {host}:{port}")
    print()

    if mode == "raw-gaia":
        sample_raw_gaia(sock, host, port, lines, delay, batch_size)
    elif mode == "raw-cef":
        sample_raw_cef(sock, host, port, lines, delay, batch_size)
    elif mode == "scan-gaia":
        sample_scan(sock, host, port, lines, delay, batch_size, "gaia", fast=False)
    elif mode == "scan-cef":
        sample_scan(sock, host, port, lines, delay, batch_size, "cef", fast=False)
    elif mode == "fast-gaia":
        sample_scan(sock, host, port, lines, delay, batch_size, "gaia", fast=True)
    elif mode == "fast-cef":
        sample_scan(sock, host, port, lines, delay, batch_size, "cef", fast=True)
    else:
        print(f"[!] Mod necunoscut: {mode}")
        sys.exit(1)


# =============================================================================
# Preset-uri
# =============================================================================

def run_preset(
    sock: socket.socket,
    host: str,
    port: int,
    preset: str,
    cef: bool,
    delay: float,
    batch_size: int,
) -> None:
    """Replay automat din sample-ul corespunzator preset-ului."""
    fmt = "cef" if cef else "gaia"
    filename = f"sample_{preset}_{fmt}.log"
    file_path = os.path.join(SCRIPT_DIR, filename)
    replay_file(sock, host, port, file_path, delay, batch_size)


# =============================================================================
# Meniu Interactiv
# =============================================================================

def _prompt(question: str, default: str = None) -> str:
    """Intreaba utilizatorul o intrebare cu optional default. Repeta la input gol obligatoriu."""
    if default is not None:
        prompt_str = f"  {question} [{default}]: "
    else:
        prompt_str = f"  {question}: "
    while True:
        answer = input(prompt_str).strip()
        if answer == "" and default is not None:
            return default
        if answer == "" and default is None:
            print("  [!] Camp obligatoriu. Incearca din nou.")
            continue
        return answer


def _prompt_int(question: str, default: int) -> int:
    """Intreaba utilizatorul un numar intreg cu retry la input invalid."""
    while True:
        raw = _prompt(question, str(default))
        try:
            return int(raw)
        except ValueError:
            print("  [!] Valoare invalida. Introdu un numar intreg.")


def _prompt_float(question: str, default: float) -> float:
    """Intreaba utilizatorul un numar real cu retry la input invalid."""
    while True:
        raw = _prompt(question, str(default))
        try:
            return float(raw)
        except ValueError:
            print("  [!] Valoare invalida. Introdu un numar real (ex: 0.1).")


def _prompt_choice(valid: list, default: str = None) -> str:
    """Intreaba utilizatorul sa aleaga dintr-o lista de optiuni valide."""
    while True:
        if default is not None:
            raw = input(f"  Alegere [{default}]: ").strip()
            if raw == "":
                return default
        else:
            raw = input("  Alegere: ").strip()
        if raw in valid:
            return raw
        print(f"  [!] Alegere invalida. Optiuni: {', '.join(valid)}")


def _prompt_host_port(default: str = "127.0.0.1:5555") -> tuple:
    """Intreaba host:port si returneaza (host, port). Repeta la format invalid."""
    while True:
        raw = _prompt("Destinatie (host:port)", default)
        if ":" not in raw:
            print("  [!] Format invalid. Foloseste host:port (ex: 127.0.0.1:5555)")
            continue
        host_part, _, port_part = raw.rpartition(":")
        try:
            port = int(port_part)
            if not (1 <= port <= 65535):
                raise ValueError
            return host_part, port
        except ValueError:
            print("  [!] Port invalid. Trebuie sa fie intre 1 si 65535.")


def _random_ip_from_cidr(cidr: str) -> str:
    """Genereaza un IP random dintr-un subnet CIDR folosind aritmetica directa."""
    network = ipaddress.IPv4Network(cidr, strict=False)
    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    if first > last:
        raise ValueError(f"Subnet-ul {cidr} este prea mic (mai putin de 2 adrese utilizabile).")
    return str(ipaddress.IPv4Address(random.randint(first, last)))


def _get_ip_from_choice(choice: str) -> str:
    """
    Rezolva selectia IP pentru optiunile 1-5.
    Returneaza un singur IP ca string.
    """
    CLASS_A = "10.0.0.0/8"
    CLASS_B = "172.16.0.0/12"
    CLASS_C = "192.168.0.0/16"

    if choice == "1":
        ip = _random_ip_from_cidr(CLASS_A)
        print(f"  [*] IP generat (Clasa A): {ip}")
        return ip
    elif choice == "2":
        ip = _random_ip_from_cidr(CLASS_B)
        print(f"  [*] IP generat (Clasa B): {ip}")
        return ip
    elif choice == "3":
        ip = _random_ip_from_cidr(CLASS_C)
        print(f"  [*] IP generat (Clasa C): {ip}")
        return ip
    elif choice == "4":
        while True:
            cidr = _prompt("Prefix CIDR", "192.168.0.0/24")
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                first = int(network.network_address) + 1
                last = int(network.broadcast_address) - 1
                if first > last:
                    print("  [!] Subnet prea mic (minim /30). Incearca din nou.")
                    continue
                ip = _random_ip_from_cidr(cidr)
                print(f"  [*] IP generat din {cidr}: {ip}")
                return ip
            except ValueError:
                print("  [!] CIDR invalid. Exemplu valid: 10.20.0.0/16")
    else:  # choice == "5"
        while True:
            ip_str = _prompt("IP sursa")
            try:
                ipaddress.IPv4Address(ip_str)
                return ip_str
            except ValueError:
                print("  [!] IP invalid. Exemplu: 192.168.1.100")


def _prompt_single_ip_menu(label: str = "") -> str:
    """
    Afiseaza sub-meniu IP cu optiunile 1-5 (fara Multi-IP).
    Folosit pentru fiecare atacator in cadrul optiunii Multi-IP.
    """
    if label:
        print(f"\n  {label}")
    print()
    print("  ── Sursa IP ──────────────────────────────")
    print("    1) Clasa A      (10.x.x.x)")
    print("    2) Clasa B      (172.16-31.x.x)")
    print("    3) Clasa C      (192.168.x.x)")
    print("    4) CIDR custom  (ex: 10.20.0.0/16)")
    print("    5) IP fix       (introduceti manual)")
    print("  ──────────────────────────────────────────")
    choice = _prompt_choice(["1", "2", "3", "4", "5"])
    return _get_ip_from_choice(choice)


def _prompt_ip_source() -> list:
    """
    Afiseaza sub-meniu complet pentru selectarea sursei IP (optiunile 1-6).
    Returneaza o lista de IP-uri (un element sau mai multe pentru Multi-IP).
    """
    print()
    print("  ── Sursa IP ──────────────────────────────")
    print("    1) Clasa A      (10.x.x.x)")
    print("    2) Clasa B      (172.16-31.x.x)")
    print("    3) Clasa C      (192.168.x.x)")
    print("    4) CIDR custom  (ex: 10.20.0.0/16)")
    print("    5) IP fix       (introduceti manual)")
    print("    6) Multi-IP     (N atacatori diferiti)")
    print("  ──────────────────────────────────────────")
    choice = _prompt_choice(["1", "2", "3", "4", "5", "6"])

    if choice == "6":
        n = _prompt_int("Numar de atacatori", 3)
        return [
            _prompt_single_ip_menu(f"[Atacator {i + 1}/{n}]")
            for i in range(n)
        ]
    return [_get_ip_from_choice(choice)]


def _ask_format() -> str:
    """Intreaba utilizatorul formatul de log dorit. Returneaza 'gaia' sau 'cef'."""
    print()
    print("  Format:")
    print("    1) GAIA")
    print("    2) CEF")
    c = _prompt_choice(["1", "2"], "1")
    return "gaia" if c == "1" else "cef"


def _print_summary(items: list) -> None:
    """Afiseaza un sumar formatat al configuratiei inainte de rulare."""
    print()
    print("  ── Configuratie ──────────────────────────")
    for label, value in items:
        print(f"    {label:<12}: {value}")
    print("  ──────────────────────────────────────────")


def run_interactive_menu() -> None:
    """
    Meniu interactiv principal.
    Activat automat cand scriptul este rulat fara argumente CLI.
    """
    print()
    print("=" * 60)
    print("  IDS-RS Tester — Meniu Principal")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        while True:
            print()
            print("  1) Fast Scan      (declanseaza alerta)")
            print("  2) Slow Scan      (declanseaza alerta lent)")
            print("  3) Trafic Normal  (fara alerta)")
            print("  4) Replay fisier  (trimite log-uri dintr-un fisier)")
            print("  5) Random         (generare aleatorie cu IP custom)")
            print("  0) Iesire")
            print()

            choice = _prompt_choice(["0", "1", "2", "3", "4", "5"])

            if choice == "0":
                print("\nIesire.")
                break

            try:
                if choice == "1":
                    fmt = _ask_format()
                    host, port = _prompt_host_port()
                    num_ports = _prompt_int("Numar porturi", 20)
                    delay = _prompt_float("Delay intre pachete (s)", 0.1)
                    source = _prompt("IP sursa simulat", "192.168.11.7")
                    _print_summary([
                        ("Scenariu", "Fast Scan"),
                        ("Format", fmt.upper()),
                        ("Host:Port", f"{host}:{port}"),
                        ("IP sursa", source),
                        ("Porturi", num_ports),
                        ("Delay", f"{delay}s"),
                    ])
                    input("  Apasa Enter pentru a incepe sau Ctrl+C pentru anulare...")
                    print()
                    simulate_fast_scan(
                        sock=sock, host=host, port=port,
                        source_ip=source, num_ports=num_ports,
                        delay=delay, batch_size=1, fmt=fmt,
                    )

                elif choice == "2":
                    fmt = _ask_format()
                    host, port = _prompt_host_port()
                    num_ports = _prompt_int("Numar porturi", 40)
                    delay = _prompt_float("Delay intre pachete (s)", 7.0)
                    source = _prompt("IP sursa simulat", "192.168.11.7")
                    _print_summary([
                        ("Scenariu", "Slow Scan"),
                        ("Format", fmt.upper()),
                        ("Host:Port", f"{host}:{port}"),
                        ("IP sursa", source),
                        ("Porturi", num_ports),
                        ("Delay", f"{delay}s"),
                    ])
                    input("  Apasa Enter pentru a incepe sau Ctrl+C pentru anulare...")
                    print()
                    simulate_slow_scan(
                        sock=sock, host=host, port=port,
                        source_ip=source, num_ports=num_ports,
                        delay=delay, batch_size=1, fmt=fmt,
                    )

                elif choice == "3":
                    fmt = _ask_format()
                    host, port = _prompt_host_port()
                    count = _prompt_int("Numar log-uri", 10)
                    source = _prompt("IP sursa simulat", "192.168.11.7")
                    _print_summary([
                        ("Scenariu", "Trafic Normal"),
                        ("Format", fmt.upper()),
                        ("Host:Port", f"{host}:{port}"),
                        ("IP sursa", source),
                        ("Log-uri", count),
                    ])
                    input("  Apasa Enter pentru a incepe sau Ctrl+C pentru anulare...")
                    print()
                    simulate_normal(
                        sock=sock, host=host, port=port,
                        source_ip=source, count=count, fmt=fmt,
                    )

                elif choice == "4":
                    host, port = _prompt_host_port()
                    file_path = _prompt("Cale fisier")
                    delay = _prompt_float("Delay intre pachete (s)", 0.1)
                    _print_summary([
                        ("Scenariu", "Replay"),
                        ("Host:Port", f"{host}:{port}"),
                        ("Fisier", file_path),
                        ("Delay", f"{delay}s"),
                    ])
                    input("  Apasa Enter pentru a incepe sau Ctrl+C pentru anulare...")
                    print()
                    replay_file(
                        sock=sock, host=host, port=port,
                        file_path=file_path, delay=delay, batch_size=1,
                    )

                elif choice == "5":
                    ips = _prompt_ip_source()

                    print()
                    print("  Tip scenariu:")
                    print("    1) Fast Scan")
                    print("    2) Slow Scan")
                    print("    3) Normal")
                    scan_choice = _prompt_choice(["1", "2", "3"], "1")

                    fmt = _ask_format()
                    host, port = _prompt_host_port()

                    if scan_choice in ("1", "2"):
                        default_ports = 20 if scan_choice == "1" else 40
                        default_delay = 0.1 if scan_choice == "1" else 7.0
                        num_ports = _prompt_int("Numar porturi", default_ports)
                        delay = _prompt_float("Delay intre pachete (s)", default_delay)
                        extra_items = [("Porturi", num_ports), ("Delay", f"{delay}s")]
                    else:
                        count = _prompt_int("Numar log-uri", 10)
                        extra_items = [("Log-uri", count)]

                    scan_names = {"1": "Fast Scan", "2": "Slow Scan", "3": "Normal"}
                    _print_summary([
                        ("Scenariu", f"Random — {scan_names[scan_choice]}"),
                        ("Format", fmt.upper()),
                        ("Host:Port", f"{host}:{port}"),
                        ("Atacatori", len(ips)),
                        ("IP(uri)", ", ".join(ips)),
                        *extra_items,
                    ])
                    input("  Apasa Enter pentru a incepe sau Ctrl+C pentru anulare...")
                    print()

                    for i, ip in enumerate(ips):
                        if len(ips) > 1:
                            print(f"\n[Atacator {i + 1}/{len(ips)}] IP: {ip}\n")
                        if scan_choice == "1":
                            simulate_fast_scan(
                                sock=sock, host=host, port=port,
                                source_ip=ip, num_ports=num_ports,
                                delay=delay, batch_size=1, fmt=fmt,
                            )
                        elif scan_choice == "2":
                            simulate_slow_scan(
                                sock=sock, host=host, port=port,
                                source_ip=ip, num_ports=num_ports,
                                delay=delay, batch_size=1, fmt=fmt,
                            )
                        else:
                            simulate_normal(
                                sock=sock, host=host, port=port,
                                source_ip=ip, count=count, fmt=fmt,
                            )
                        if len(ips) > 1 and i < len(ips) - 1:
                            time.sleep(1.0)

            except KeyboardInterrupt:
                print("\n  [!] Scenariu anulat.")

            print()
            try:
                again = input("  Rulezi alt scenariu? [D/n]: ").strip().lower()
                if again == "n":
                    print("\nIesire.")
                    break
            except KeyboardInterrupt:
                print("\nIesire.")
                break
            print()

    except KeyboardInterrupt:
        print("\nIesire.")
    finally:
        sock.close()


# =============================================================================
# CLI - Argparse
# =============================================================================

def add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    """Adauga argumentele comune pentru comenzile de scan."""
    parser.add_argument(
        "--format",
        choices=["gaia", "cef"],
        default="gaia",
        help="Formatul log-urilor: gaia sau cef (default: gaia)",
    )
    parser.add_argument(
        "--source",
        default="192.168.11.7",
        help="IP-ul sursa simulat (default: 192.168.11.7)",
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=1,
        help="Log-uri per pachet UDP / buffer coalescing (default: 1)",
    )


def main() -> None:
    if len(sys.argv) == 1:
        run_interactive_menu()
        return

    root_parser = argparse.ArgumentParser(
        description="Tester IDS-RS - Simuleaza log-uri de firewall pe UDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Preset-uri (replay automat din sample):\n"
            "  python tester.py fast                  # Fast Scan GAIA\n"
            "  python tester.py fast --cef            # Fast Scan CEF\n"
            "  python tester.py slow                  # Slow Scan GAIA\n"
            "  python tester.py normal                # Trafic normal GAIA\n"
            "\n"
            "Replay / sample (fisier la alegere):\n"
            "  python tester.py replay tester/sample2_gaia.log\n"
            "  python tester.py sample tester/sample2_gaia.log raw-gaia\n"
            "\n"
            "Generare dinamica (avansat):\n"
            "  python tester.py fast-scan --format gaia --ports 20 --delay 0.1\n"
            "  python tester.py slow-scan --format gaia --ports 40\n"
        ),
    )

    # Argumente globale.
    root_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Adresa IP a IDS-RS (default: 127.0.0.1)",
    )
    root_parser.add_argument(
        "--port",
        type=int,
        default=5555,
        help="Portul UDP al IDS-RS (default: 5555)",
    )

    subparsers = root_parser.add_subparsers(dest="command", help="Modul de testare")
    subparsers.required = True

    # --- fast (preset) ---
    fast_preset = subparsers.add_parser(
        "fast",
        help="Replay sample_fast_*.log (Fast Scan)",
    )
    fast_preset.add_argument("--cef", action="store_true", help="Format CEF in loc de GAIA")
    fast_preset.add_argument("--delay", type=float, default=0.1, help="Delay intre batch-uri (default: 0.1)")
    fast_preset.add_argument("--batch", type=int, default=1, help="Linii per pachet UDP (default: 1)")

    # --- slow (preset) ---
    slow_preset = subparsers.add_parser(
        "slow",
        help="Replay sample_slow_*.log (Slow Scan)",
    )
    slow_preset.add_argument("--cef", action="store_true", help="Format CEF in loc de GAIA")
    slow_preset.add_argument("--delay", type=float, default=0.5, help="Delay intre batch-uri (default: 0.5)")
    slow_preset.add_argument("--batch", type=int, default=1, help="Linii per pachet UDP (default: 1)")

    # --- normal (preset) ---
    normal_preset = subparsers.add_parser(
        "normal",
        help="Replay sample_normal_*.log (trafic normal, fara alerta)",
    )
    normal_preset.add_argument("--cef", action="store_true", help="Format CEF in loc de GAIA")
    normal_preset.add_argument("--delay", type=float, default=0.1, help="Delay intre batch-uri (default: 0.1)")
    normal_preset.add_argument("--batch", type=int, default=1, help="Linii per pachet UDP (default: 1)")

    # --- fast-scan (generare dinamica) ---
    fast_parser = subparsers.add_parser(
        "fast-scan",
        help="Genereaza dinamic un atac Fast Scan (>15 porturi in <10s)",
    )
    add_common_scan_args(fast_parser)
    fast_parser.add_argument(
        "--ports",
        type=int,
        default=20,
        help="Numar de porturi unice de scanat (default: 20)",
    )
    fast_parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay intre batch-uri in secunde (default: 0.1)",
    )

    # --- slow-scan (generare dinamica) ---
    slow_parser = subparsers.add_parser(
        "slow-scan",
        help="Genereaza dinamic un atac Slow Scan (>30 porturi in <5 min)",
    )
    add_common_scan_args(slow_parser)
    slow_parser.add_argument(
        "--ports",
        type=int,
        default=40,
        help="Numar de porturi unice de scanat (default: 40)",
    )
    slow_parser.add_argument(
        "--delay",
        type=float,
        default=7.0,
        help="Delay intre batch-uri in secunde (default: 7.0)",
    )

    # --- replay ---
    replay_parser = subparsers.add_parser(
        "replay",
        help="Trimite log-uri dintr-un fisier catre IDS-RS",
    )
    replay_parser.add_argument(
        "file",
        help="Calea catre fisierul cu log-uri (o linie = un log)",
    )
    replay_parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay intre batch-uri in secunde (default: 0.1)",
    )
    replay_parser.add_argument(
        "--batch",
        type=int,
        default=1,
        help="Linii per pachet UDP (default: 1)",
    )

    # --- sample ---
    sample_parser = subparsers.add_parser(
        "sample",
        help="Citeste log-uri reale dintr-un fisier si le trimite in multiple formate",
    )
    sample_parser.add_argument(
        "file",
        help="Calea catre fisierul cu log-uri GAIA reale",
    )
    sample_parser.add_argument(
        "mode",
        choices=["raw-gaia", "raw-cef", "scan-gaia", "scan-cef", "fast-gaia", "fast-cef"],
        help="Modul de trimitere: raw-gaia, raw-cef, scan-gaia, scan-cef, fast-gaia, fast-cef",
    )
    sample_parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay intre batch-uri in secunde (default: 0.5)",
    )
    sample_parser.add_argument(
        "--batch",
        type=int,
        default=1,
        help="Linii per pachet UDP (default: 1)",
    )

    args = root_parser.parse_args()

    # =========================================================================
    # Executie
    # =========================================================================
    print("=" * 60)
    print("  IDS-RS Tester")
    print("=" * 60)
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        if args.command in ("fast", "slow", "normal"):
            run_preset(
                sock=sock,
                host=args.host,
                port=args.port,
                preset=args.command,
                cef=args.cef,
                delay=args.delay,
                batch_size=args.batch,
            )
        elif args.command == "fast-scan":
            simulate_fast_scan(
                sock=sock,
                host=args.host,
                port=args.port,
                source_ip=args.source,
                num_ports=args.ports,
                delay=args.delay,
                batch_size=args.batch,
                fmt=args.format,
            )
        elif args.command == "slow-scan":
            simulate_slow_scan(
                sock=sock,
                host=args.host,
                port=args.port,
                source_ip=args.source,
                num_ports=args.ports,
                delay=args.delay,
                batch_size=args.batch,
                fmt=args.format,
            )
        elif args.command == "replay":
            replay_file(
                sock=sock,
                host=args.host,
                port=args.port,
                file_path=args.file,
                delay=args.delay,
                batch_size=args.batch,
            )
        elif args.command == "sample":
            run_sample(
                sock=sock,
                host=args.host,
                port=args.port,
                file_path=args.file,
                mode=args.mode,
                delay=args.delay,
                batch_size=args.batch,
            )
    except KeyboardInterrupt:
        print("\n[!] Intrerupt de utilizator.")
        sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
