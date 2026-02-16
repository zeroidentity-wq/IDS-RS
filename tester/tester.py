#!/usr/bin/env python3
"""
tester.py - Script de testare pentru IDS-RS

Trimite pachete UDP catre IDS-RS simuland log-uri de firewall.
Suporta doua moduri de testare:

  1. fast-scan  - Simuleaza un atac Fast Scan cu log-uri Gaia
                  (multe porturi unice intr-un interval scurt)

  2. cef-normal - Trimite un log CEF normal (o singura conexiune)

Utilizare:
  python tester.py fast-scan --ports 20 --delay 0.1
  python tester.py fast-scan --ports 50 --delay 0.05 --batch 5
  python tester.py cef-normal
  python tester.py fast-scan --host 192.168.1.100 --port 5555

Parametri:
  --host     Adresa IDS-RS (default: 127.0.0.1)
  --port     Portul UDP al IDS-RS (default: 5555)
  --ports    Numar de porturi unice de scanat (fast-scan)
  --delay    Delay intre pachete in secunde (fast-scan)
  --source   IP-ul sursa simulat (fast-scan)
  --batch    Numar de log-uri per pachet UDP (simuleaza buffer coalescing)
"""

import argparse
import socket
import sys
import time
import random


def send_udp(sock: socket.socket, host: str, port: int, message: str) -> None:
    """Trimite un mesaj UDP catre IDS-RS."""
    sock.sendto(message.encode("utf-8"), (host, port))


def simulate_fast_scan(
    sock: socket.socket,
    host: str,
    port: int,
    source_ip: str,
    num_ports: int,
    delay: float,
    batch_size: int,
) -> None:
    """
    Simuleaza un Fast Scan: trimite log-uri Gaia de tip 'drop' cu porturi
    unice diferite de la acelasi IP sursa, intr-un interval scurt.

    Daca batch_size > 1, mai multe log-uri sunt concatenate intr-un singur
    pachet UDP (simuleaza buffer coalescing).
    """
    print(f"[*] Simulare Fast Scan de la {source_ip}")
    print(f"    Porturi: {num_ports} | Delay: {delay}s | Batch: {batch_size}")
    print(f"    Destinatie: {host}:{port}")
    print()

    # Generam o lista de porturi unice (1-65535).
    ports = random.sample(range(1, 65536), min(num_ports, 65535))

    # Procesam porturile in batch-uri.
    batch_buffer = []
    sent_count = 0

    for i, dst_port in enumerate(ports):
        # Construim un log Gaia realist.
        # Formatul: timestamp gateway Checkpoint: action src_ip proto: X; service: Y; s_port: Z
        src_port = random.randint(1024, 65535)
        log_line = (
            f"Sep  3 15:12:{20 + (i % 40):02d} 192.168.99.1 "
            f"Checkpoint: drop {source_ip} "
            f"proto: tcp; service: {dst_port}; s_port: {src_port}"
        )
        batch_buffer.append(log_line)

        # Trimitem cand batch-ul este plin sau la ultimul port.
        if len(batch_buffer) >= batch_size or i == len(ports) - 1:
            # Concatenam log-urile cu newline (simuleaza coalescing).
            message = "\n".join(batch_buffer)
            send_udp(sock, host, port, message)
            sent_count += len(batch_buffer)

            # Afisam progresul.
            print(
                f"  [{sent_count:>4}/{num_ports}] "
                f"Trimis {len(batch_buffer)} log(uri) | "
                f"Ultimul port: {dst_port}"
            )

            batch_buffer.clear()

            if delay > 0 and i < len(ports) - 1:
                time.sleep(delay)

    print()
    print(f"[+] Fast Scan complet: {sent_count} log-uri trimise")
    print(f"    IDS-RS ar trebui sa detecteze scanarea daca pragul este < {num_ports}")


def simulate_cef_normal(
    sock: socket.socket,
    host: str,
    port: int,
) -> None:
    """
    Trimite un singur log CEF de tip 'drop' - pentru testarea parser-ului CEF.
    """
    print(f"[*] Trimitere log CEF normal catre {host}:{port}")

    cef_log = (
        "CEF:0|CheckPoint|VPN-1 & FireWall-1|R81.20|100|Drop|5|"
        "src=10.20.30.40 dst=192.168.1.1 dpt=443 proto=TCP act=drop"
    )

    send_udp(sock, host, port, cef_log)
    print(f"  Log trimis: {cef_log[:80]}...")
    print()
    print("[+] Done. Verificati output-ul IDS-RS.")


def main() -> None:
    # =========================================================================
    # Parsare argumente CLI cu argparse
    # =========================================================================
    root_parser = argparse.ArgumentParser(
        description="Tester IDS-RS - Simuleaza log-uri de firewall pe UDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemple:\n"
            "  python tester.py fast-scan --ports 20 --delay 0.1\n"
            "  python tester.py fast-scan --ports 50 --batch 5 --source 10.0.0.99\n"
            "  python tester.py cef-normal\n"
        ),
    )

    # Argumente comune.
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

    # Sub-comenzi.
    subparsers = root_parser.add_subparsers(dest="command", help="Modul de testare")
    subparsers.required = True

    # --- Sub-comanda: fast-scan ---
    fast_parser = subparsers.add_parser(
        "fast-scan",
        help="Simuleaza un atac Fast Scan cu log-uri Gaia",
    )
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
    fast_parser.add_argument(
        "--source",
        default="192.168.11.7",
        help="IP-ul sursa simulat (default: 192.168.11.7)",
    )
    fast_parser.add_argument(
        "--batch",
        type=int,
        default=1,
        help="Log-uri per pachet UDP / buffer coalescing (default: 1)",
    )

    # --- Sub-comanda: cef-normal ---
    subparsers.add_parser(
        "cef-normal",
        help="Trimite un log CEF normal de test",
    )

    args = root_parser.parse_args()

    # =========================================================================
    # Executie
    # =========================================================================
    print("=" * 50)
    print("  IDS-RS Tester")
    print("=" * 50)
    print()

    # Cream socket-ul UDP (reutilizabil pentru toate trimiterile).
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
            )
        elif args.command == "cef-normal":
            simulate_cef_normal(
                sock=sock,
                host=args.host,
                port=args.port,
            )
    except KeyboardInterrupt:
        print("\n[!] Intrerupt de utilizator.")
        sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
