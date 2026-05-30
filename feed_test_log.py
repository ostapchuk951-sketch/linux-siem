#!/usr/bin/env python3
"""
Добавляет в лог-файл строки, имитирующие SSH brute-force (для теста на Windows/Linux).
Запускайте во ВТОРОМ терминале, пока в первом работает: py auth_siem.py -f test_auth.log -v
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path


def syslog_prefix() -> str:
    """Префикс как в auth.log: 'May 30 12:34:56 server sshd[1001]:'."""
    now = datetime.now()
    # День без ведущего нуля: Linux %-d, Windows %#d
    fmt = "%b %#d %H:%M:%S" if sys.platform == "win32" else "%b %-d %H:%M:%S"
    ts = now.strftime(fmt)
    return f"{ts} server sshd[9999]:"


def main() -> int:
    parser = argparse.ArgumentParser(description="Append fake SSH failures to a log file")
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=Path("test_auth.log"),
        help="Log file to append (default: test_auth.log in current directory)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.4,
        help="Seconds between lines (default: 0.4)",
    )
    args = parser.parse_args()

    attacks = [
        " Failed password for root from 203.0.113.77 port 22 ssh2",
        " Invalid user admin from 203.0.113.77 port 22 ssh2",
        " Failed password for invalid user test from 203.0.113.77 port 22 ssh2",
        " Failed password for root from 203.0.113.77 port 22 ssh2",
        " Failed password for root from 203.0.113.77 port 22 ssh2",
        " Failed password for root from 203.0.113.77 port 22 ssh2",
    ]

    args.file.parent.mkdir(parents=True, exist_ok=True)
    print(f"Appending {len(attacks)} lines to {args.file.resolve()}")

    with open(args.file, "a", encoding="utf-8") as fh:
        for i, suffix in enumerate(attacks, start=1):
            line = syslog_prefix() + suffix + "\n"
            fh.write(line)
            fh.flush()
            print(f"  [{i}/{len(attacks)}] {line.rstrip()}")
            time.sleep(args.delay)

    print("Done. SIEM should alert on the 6th failure if it is already tailing this file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
