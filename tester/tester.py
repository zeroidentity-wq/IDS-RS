#!/usr/bin/env python3
"""
tester.py - Script de testare pentru IDS-RS

Trimite pachete UDP catre IDS-RS simuland log-uri de firewall.
Suporta urmatoarele moduri de testare:

  1. fast-scan   - Simuleaza un atac Fast Scan (multe porturi intr-un interval scurt)
  2. slow-scan   - Simuleaza un atac Slow Scan (porturi distribuite pe un interval lung)
  3. normal      - Trimite trafic normal (sub pragul de detectie)
  4. replay      - Trimite log-uri dintr-un fisier catre IDS-RS

Fiecare mod de scanare suporta formatele: gaia si cef (--format).

Utilizare:
  python tester.py fast-scan --format gaia --ports 20 --delay 0.1
  python tester.py fast-scan --format cef --ports 25 --batch 5
  python tester.py slow-scan --format gaia --ports 40
  python tester.py slow-scan --format cef --ports 35 --delay 8
  python tester.py normal --format gaia --count 5
  python tester.py normal --format cef --count 3
  python tester.py replay --file /path/to/logs.txt
  python tester.py replay --file /path/to/logs.txt --delay 0.05
"""

import argparse
import socket
import sys
import time
import random


# =============================================================================
# Generatoare de log-uri
# =============================================================================

def generate_gaia_log(source_ip: str, dst_port: int, action: str = "drop") -> str:
    """Genereaza un log Checkpoint Gaia realist."""
    src_port = random.randint(1024, 65535)
    second = random.randint(0, 59)
    return (
        f"Sep  3 15:12:{second:02d} 192.168.99.1 "
        f"Checkpoint: {action} {source_ip} "
        f"proto: tcp; service: {dst_port}; s_port: {src_port}"
    )


def generate_cef_log(source_ip: str, dst_port: int, action: str = "drop") -> str:
    """Genereaza un log CEF (Common Event Format) realist."""
    severity = 5 if action == "drop" else 3
    name = "Drop" if action == "drop" else "Accept"
    return (
        f"CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|{name}|{severity}|"
        f"src={source_ip} dst=192.168.1.1 dpt={dst_port} proto=TCP act={action}"
    )


def generate_log(fmt: str, source_ip: str, dst_port: int, action: str = "drop") -> str:
    """Genereaza un log in formatul specificat (gaia sau cef)."""
    if fmt == "cef":
        return generate_cef_log(source_ip, dst_port, action)
    return generate_gaia_log(source_ip, dst_port, action)


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
    root_parser = argparse.ArgumentParser(
        description="Tester IDS-RS - Simuleaza log-uri de firewall pe UDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemple:\n"
            "  python tester.py fast-scan --format gaia --ports 20 --delay 0.1\n"
            "  python tester.py fast-scan --format cef --ports 25 --batch 5\n"
            "  python tester.py slow-scan --format gaia --ports 40\n"
            "  python tester.py slow-scan --format cef --ports 35 --delay 8\n"
            "  python tester.py normal --format gaia --count 5\n"
            "  python tester.py normal --format cef --count 3\n"
            "  python tester.py replay --file /path/to/logs.txt\n"
            "  python tester.py replay --file /path/to/logs.txt --delay 0.05 --batch 10\n"
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

    # --- fast-scan ---
    fast_parser = subparsers.add_parser(
        "fast-scan",
        help="Simuleaza un atac Fast Scan (>15 porturi in <10s)",
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

    # --- slow-scan ---
    slow_parser = subparsers.add_parser(
        "slow-scan",
        help="Simuleaza un atac Slow Scan (>30 porturi in <5 min)",
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

    # --- normal ---
    normal_parser = subparsers.add_parser(
        "normal",
        help="Trimite trafic normal (sub pragul de detectie)",
    )
    add_common_scan_args(normal_parser)
    normal_parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Numar de log-uri de trimis (default: 5)",
    )

    # --- replay ---
    replay_parser = subparsers.add_parser(
        "replay",
        help="Trimite log-uri dintr-un fisier catre IDS-RS",
    )
    replay_parser.add_argument(
        "--file",
        required=True,
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
        if args.command == "fast-scan":
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
        elif args.command == "normal":
            simulate_normal(
                sock=sock,
                host=args.host,
                port=args.port,
                source_ip=args.source,
                count=args.count,
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
    except KeyboardInterrupt:
        print("\n[!] Intrerupt de utilizator.")
        sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
