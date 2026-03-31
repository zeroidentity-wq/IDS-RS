#!/usr/bin/env python3
"""
smtp_server.py - Server SMTP local pentru testarea alertelor IDS-RS.

Primeste emailuri si le afiseaza in terminal — nu trimite nimic mai departe.
Util pentru testarea alertelor fara un server SMTP real.

Utilizare:
  python3 tester/smtp_server.py           # Port 1025 (default)
  python3 tester/smtp_server.py --port 25 # Port 25 (necesita root)

Configurare config.toml pentru a folosi acest server:
  [alerting.email]
  enabled = true
  smtp_server = "127.0.0.1"
  smtp_port = 1025
  smtp_tls = false
  from = "ids-rs@test.local"
  to = ["security@test.local"]
  username = ""
  password = ""
"""

import argparse
import asyncio
import email
import sys
from datetime import datetime

from aiosmtpd.controller import Controller


# =============================================================================
# Handler SMTP
# =============================================================================

class PrintHandler:
    """Afiseaza fiecare email primit in terminal cu formatare clara."""

    async def handle_DATA(self, server, session, envelope):
        peer = session.peer
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        raw_data = envelope.content

        # Parsam mesajul pentru a extrage subject si body.
        if isinstance(raw_data, bytes):
            msg = email.message_from_bytes(raw_data)
        else:
            msg = email.message_from_string(raw_data)

        subject = msg.get("Subject", "(fara subiect)")
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print()
        print("=" * 70)
        print(f"  EMAIL NOU — {date_str}")
        print("=" * 70)
        print(f"  De la  : {mail_from}")
        print(f"  Catre  : {', '.join(rcpt_tos)}")
        print(f"  Subiect: {subject}")
        print(f"  Client : {peer}")
        print("-" * 70)

        # Extragem body-ul (text sau HTML).
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body = part.get_payload(decode=True).decode(charset, errors="replace")
                    except Exception:
                        body = str(part.get_payload())
                    print(f"  [{ctype}]")
                    # Limitam afisarea la 80 linii pentru lizibilitate.
                    lines = body.splitlines()
                    for line in lines[:80]:
                        print(f"  {line}")
                    if len(lines) > 80:
                        print(f"  ... (+{len(lines) - 80} linii)")
                    print()
        else:
            charset = msg.get_content_charset() or "utf-8"
            try:
                body = msg.get_payload(decode=True).decode(charset, errors="replace")
            except Exception:
                body = str(msg.get_payload())
            lines = body.splitlines()
            for line in lines[:80]:
                print(f"  {line}")
            if len(lines) > 80:
                print(f"  ... (+{len(lines) - 80} linii)")

        print("=" * 70)
        print()
        sys.stdout.flush()

        return "250 OK"


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Server SMTP local pentru testare IDS-RS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Configureaza config.toml:\n"
            "  smtp_server = \"127.0.0.1\"\n"
            "  smtp_port   = 1025\n"
            "  smtp_tls    = false\n"
            "  username    = \"\"\n"
            "  password    = \"\"\n"
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1025,
        help="Portul pe care asculta serverul SMTP (default: 1025)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Adresa pe care asculta serverul (default: 127.0.0.1)",
    )
    args = parser.parse_args()

    handler = PrintHandler()
    controller = Controller(handler, hostname=args.host, port=args.port)

    print("=" * 70)
    print("  IDS-RS SMTP Test Server")
    print("=" * 70)
    print(f"  Ascult pe : {args.host}:{args.port}")
    print(f"  Mod       : afisare in terminal (nu trimite emailuri reale)")
    print()
    print("  Configurare config.toml:")
    print(f'    smtp_server = "{args.host}"')
    print(f"    smtp_port   = {args.port}")
    print( "    smtp_tls    = false")
    print( "    username    = \"\"")
    print( "    password    = \"\"")
    print()
    print("  Asteapta emailuri... (Ctrl+C pentru oprire)")
    print("=" * 70)

    controller.start()
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("\n[*] Oprire server SMTP.")
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
