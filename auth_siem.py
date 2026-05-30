#!/usr/bin/env python3
"""
Легковесный SIEM-подобный анализатор auth.log в реальном времени.
Мониторинг SSH-событий, детекция brute-force, консольные и внешние алерты.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Deque, Iterator, Optional


# ---------------------------------------------------------------------------
# Конфигурация (правило детекции и пути по умолчанию)
# ---------------------------------------------------------------------------

DEFAULT_LOG_PATH = "/var/log/auth.log"
WINDOW_SECONDS = 60
# Инцидент при СТРОГО более 5 неудачных попыток (т.е. на 6-й и далее)
FAILED_THRESHOLD = 5
# Пауза между повторными алертами по одному IP (секунды)
ALERT_COOLDOWN_SECONDS = 300


# ---------------------------------------------------------------------------
# Модель данных
# ---------------------------------------------------------------------------


class EventStatus(str, Enum):
    """Классификация SSH-события из auth.log."""

    SUCCESS = "Success"
    FAILED = "Failed"
    INVALID_USER = "Invalid User"
    IGNORED = "Ignored"  # строки без SSH-аутентификации


@dataclass(frozen=True)
class LogEvent:
    """Нормализованная запись после парсинга одной строки лога."""

    timestamp: datetime
    ip: str
    username: str
    status: EventStatus
    raw_line: str


# ---------------------------------------------------------------------------
# Reader — потоковое чтение лога (аналог tail -F)
# ---------------------------------------------------------------------------


class AuthLogTailer:
    """
    Непрерывно читает новые строки из файла, не перечитывая весь файл.
    При старте переходит в конец файла (только новые события).
    При ротации лога переоткрывает файл по inode/размеру.
    """

    def __init__(self, log_path: Path, poll_interval: float = 0.5) -> None:
        self.log_path = log_path
        self.poll_interval = poll_interval
        self._file: Optional[object] = None
        self._inode: Optional[int] = None

    def _open_for_tail(self) -> None:
        """Открывает файл и ставит курсор в конец (пропуск истории)."""
        self._close()
        # errors='replace' — не падаем на битой кодировке в логе
        self._file = open(self.log_path, "r", encoding="utf-8", errors="replace")
        self._file.seek(0, 2)  # только новые строки после запуска
        try:
            self._inode = self.log_path.stat().st_ino
        except OSError:
            self._inode = None

    def _close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None

    def _maybe_reopen(self) -> bool:
        """
        Проверяет ротацию (logrotate): файл мог быть пересоздан.
        Возвращает True, если файл успешно открыт/переоткрыт.
        """
        if not self.log_path.exists():
            return False

        try:
            current_inode = self.log_path.stat().st_ino
        except OSError:
            return False

        # Первое открытие или смена inode после ротации
        if self._file is None or (self._inode is not None and current_inode != self._inode):
            self._open_for_tail()
            return True

        # Файл уменьшился — типичный признак truncate при ротации
        if self._file is not None:
            try:
                if self._file.tell() > self.log_path.stat().st_size:
                    self._open_for_tail()
            except OSError:
                self._close()
                return False

        return self._file is not None

    def follow(self) -> Iterator[str]:
        """
        Бесконечный генератор новых строк.
        При ошибках доступа ждёт и повторяет (устойчивость к временным сбоям).
        """
        while True:
            try:
                if not self._maybe_reopen():
                    yield from self._wait_and_retry(
                        f"[Reader] Файл недоступен: {self.log_path}. "
                        "Проверьте путь и права (например, группа adm)."
                    )
                    continue

                line = self._file.readline()
                if line:
                    yield line.rstrip("\n")
                else:
                    # Нет новых данных — короткая пауза, чтобы не грузить CPU
                    time.sleep(self.poll_interval)

            except PermissionError:
                self._close()
                yield from self._wait_and_retry(
                    f"[Reader] Нет прав на чтение {self.log_path}. "
                    "Запустите от root или добавьте пользователя в группу adm."
                )
            except OSError as exc:
                self._close()
                yield from self._wait_and_retry(f"[Reader] Ошибка I/O: {exc}")

    def _wait_and_retry(self, message: str) -> Iterator[str]:
        """Печатает предупреждение раз в poll_interval; строк лога не отдаёт."""
        print(message, file=sys.stderr)
        time.sleep(self.poll_interval)
        if False:  # pragma: no cover — пустой генератор
            yield


# ---------------------------------------------------------------------------
# Parser — извлечение полей регулярными выражениями
# ---------------------------------------------------------------------------


class AuthLogParser:
    """
    Парсит типовые строки sshd из Debian/Ubuntu auth.log.
    Примеры:
      May 30 12:00:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
      May 30 12:00:02 host sshd[1234]: Invalid user admin from 1.2.3.4 port 22 ssh2
      May 30 12:00:03 host sshd[1234]: Accepted publickey for root from 1.2.3.4 port 22 ssh2
    """

    # Общий префикс syslog: "May 30 12:34:56 hostname sshd[pid]:"
    _PREFIX = re.compile(
        r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\S+\s+sshd\[\d+\]:\s+"
    )

    _ACCEPTED = re.compile(
        r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+"
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+",
        re.IGNORECASE,
    )

    _FAILED_PASSWORD = re.compile(
        r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+"
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+",
        re.IGNORECASE,
    )

    _INVALID_USER = re.compile(
        r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+"
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+",
        re.IGNORECASE,
    )

    @staticmethod
    def _parse_timestamp(ts_str: str, reference: Optional[datetime] = None) -> datetime:
        """
        В auth.log нет года — подставляем текущий.
        Если событие «из будущего» (годовой перелом), откатываем год на 1.
        """
        ref = reference or datetime.now()
        # Формат: "May 30 12:34:56"
        parsed = datetime.strptime(f"{ts_str} {ref.year}", "%b %d %H:%M:%S %Y")
        if parsed > ref:
            parsed = parsed.replace(year=ref.year - 1)
        return parsed

    def parse(self, line: str, reference: Optional[datetime] = None) -> Optional[LogEvent]:
        """Возвращает LogEvent или None, если строка не относится к SSH-входу."""
        prefix = self._PREFIX.match(line)
        if not prefix:
            return None

        ts = self._parse_timestamp(prefix.group("ts"), reference)
        payload = line[prefix.end() :]

        match = self._ACCEPTED.search(payload)
        if match:
            return LogEvent(
                timestamp=ts,
                ip=match.group("ip"),
                username=match.group("user"),
                status=EventStatus.SUCCESS,
                raw_line=line,
            )

        match = self._FAILED_PASSWORD.search(payload)
        if match:
            # "invalid user" в Failed password — отдельный подтип неудачи
            status = (
                EventStatus.INVALID_USER
                if "invalid user" in payload.lower()
                else EventStatus.FAILED
            )
            return LogEvent(
                timestamp=ts,
                ip=match.group("ip"),
                username=match.group("user"),
                status=status,
                raw_line=line,
            )

        match = self._INVALID_USER.search(payload)
        if match:
            return LogEvent(
                timestamp=ts,
                ip=match.group("ip"),
                username=match.group("user"),
                status=EventStatus.INVALID_USER,
                raw_line=line,
            )

        return None


# ---------------------------------------------------------------------------
# Analyzer — in-memory rule engine (скользящее окно по IP)
# ---------------------------------------------------------------------------


@dataclass
class BruteForceIncident:
    """Результат срабатывания правила brute-force."""

    ip: str
    usernames: list[str]
    attempt_count: int
    window_seconds: int
    first_seen: datetime
    last_seen: datetime


class BruteForceDetector:
    """
    Хранит только неудачные попытки (Failed / Invalid User) за последние WINDOW_SECONDS.
    Старые записи удаляются при каждом событии — память не растёт бесконечно.
    """

    def __init__(
        self,
        window_seconds: int = WINDOW_SECONDS,
        failed_threshold: int = FAILED_THRESHOLD,
        alert_cooldown: int = ALERT_COOLDOWN_SECONDS,
    ) -> None:
        self.window_seconds = window_seconds
        self.failed_threshold = failed_threshold
        self.alert_cooldown = alert_cooldown
        # IP -> deque[(monotonic_time, username)]
        self._attempts: dict[str, Deque[tuple[float, str]]] = defaultdict(deque)
        # IP -> monotonic time последнего алерта (антиспам)
        self._last_alert: dict[str, float] = {}

    def _purge_old(self, ip: str, now_mono: float) -> None:
        """Удаляет попытки старше скользящего окна (TTL)."""
        dq = self._attempts[ip]
        cutoff = now_mono - self.window_seconds
        while dq and dq[0][0] <= cutoff:
            dq.popleft()
        if not dq:
            del self._attempts[ip]

    def process(self, event: LogEvent) -> Optional[BruteForceIncident]:
        """
        Регистрирует событие. Возвращает инцидент, если правило сработало.
        Успешные входы в счётчик brute-force не идут.
        """
        if event.status not in (EventStatus.FAILED, EventStatus.INVALID_USER):
            return None

        now_mono = time.monotonic()
        dq = self._attempts[event.ip]
        dq.append((now_mono, event.username))
        self._purge_old(event.ip, now_mono)

        count = len(self._attempts.get(event.ip, ()))
        # «Более 5» => строго больше порога (6-я попытка и выше)
        if count <= self.failed_threshold:
            return None

        # Не слать повторные алерты по тому же IP слишком часто
        last = self._last_alert.get(event.ip, 0.0)
        if now_mono - last < self.alert_cooldown:
            return None

        self._last_alert[event.ip] = now_mono

        usernames = sorted({u for _, u in self._attempts[event.ip]})
        times = [t for t, _ in self._attempts[event.ip]]
        return BruteForceIncident(
            ip=event.ip,
            usernames=usernames,
            attempt_count=count,
            window_seconds=self.window_seconds,
            first_seen=event.timestamp,  # приблизительно; для UI достаточно
            last_seen=event.timestamp,
        )


# ---------------------------------------------------------------------------
# Alerter — консоль и заглушка внешних уведомлений
# ---------------------------------------------------------------------------


class ConsoleAlerter:
    """Выводит предупреждения в stderr с ANSI-цветом (красный)."""

    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def alert(self, incident: BruteForceIncident) -> None:
        users = ", ".join(incident.usernames) if incident.usernames else "unknown"
        msg = (
            f"{self.BOLD}{self.RED}"
            f"!!! BRUTE-FORCE DETECTED !!!{self.RESET}\n"
            f"  IP:       {incident.ip}\n"
            f"  Users:    {users}\n"
            f"  Attempts: {incident.attempt_count} "
            f"(failed/invalid) in {incident.window_seconds}s\n"
            f"  Rule:     >{FAILED_THRESHOLD} failures / {WINDOW_SECONDS}s window"
        )
        print(msg, file=sys.stderr)

    @staticmethod
    def info(message: str) -> None:
        print(f"[SIEM] {message}", file=sys.stderr)


def send_telegram_alert(ip: str, attempts: int, usernames: Optional[list[str]] = None) -> None:
    """
    Заглушка для интеграции с Telegram Bot API.
    Позже подставьте BOT_TOKEN, CHAT_ID и requests.post(...).

    Пример (раскомментировать после настройки):
        import requests
        text = f"Brute-force: {ip}, attempts={attempts}, users={usernames}"
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text},
            timeout=10,
        )
    """
    # Пока только логируем факт вызова — без сетевых запросов
    ConsoleAlerter.info(
        f"[Telegram stub] Would alert: ip={ip}, attempts={attempts}, users={usernames}"
    )


# ---------------------------------------------------------------------------
# Оркестратор — связывает Reader → Parser → Analyzer → Alerter
# ---------------------------------------------------------------------------


class AuthSiemApp:
    """Главный цикл обработки."""

    def __init__(self, log_path: Path, verbose: bool = False) -> None:
        self.reader = AuthLogTailer(log_path)
        self.parser = AuthLogParser()
        self.analyzer = BruteForceDetector()
        self.alerter = ConsoleAlerter()
        self.verbose = verbose

    def run(self) -> None:
        self.alerter.info(f"Monitoring {self.reader.log_path} (Ctrl+C to stop)")
        for line in self.reader.follow():
            event = self.parser.parse(line)
            if event is None:
                continue

            if self.verbose:
                self.alerter.info(
                    f"{event.timestamp:%Y-%m-%d %H:%M:%S} | {event.status.value} | "
                    f"{event.ip} | {event.username}"
                )

            incident = self.analyzer.process(event)
            if incident:
                self.alerter.alert(incident)
                send_telegram_alert(
                    incident.ip,
                    incident.attempt_count,
                    incident.usernames,
                )


# ---------------------------------------------------------------------------
# Режим демо / локальное тестирование без auth.log
# ---------------------------------------------------------------------------


SAMPLE_LINES = [
    "May 30 10:00:01 server sshd[1001]: Failed password for root from 203.0.113.10 port 22 ssh2",
    "May 30 10:00:02 server sshd[1002]: Invalid user admin from 203.0.113.10 port 22 ssh2",
    "May 30 10:00:03 server sshd[1003]: Failed password for invalid user test from 203.0.113.10 port 22 ssh2",
    "May 30 10:00:04 server sshd[1004]: Failed password for root from 203.0.113.10 port 22 ssh2",
    "May 30 10:00:05 server sshd[1005]: Failed password for root from 203.0.113.10 port 22 ssh2",
    "May 30 10:00:06 server sshd[1006]: Failed password for root from 203.0.113.10 port 22 ssh2",
    "May 30 10:00:07 server sshd[1007]: Accepted publickey for root from 10.0.0.5 port 22 ssh2",
]


def init_test_log(path: Path) -> None:
    """Создаёт пустой файл лога для локального tail-теста (Windows и т.д.)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    print(f"Created empty test log: {path.resolve()}", file=sys.stderr)
    print(
        "  Terminal 1: py auth_siem.py -f "
        f"{path} -v\n"
        "  Terminal 2: py feed_test_log.py -f "
        f"{path}",
        file=sys.stderr,
    )


def run_demo() -> None:
    """Прогон синтетических строк через Parser + Analyzer (без tail)."""
    parser = AuthLogParser()
    analyzer = BruteForceDetector()
    alerter = ConsoleAlerter()
    ref = datetime.now()

    alerter.info("DEMO mode — synthetic auth.log lines")
    for line in SAMPLE_LINES:
        event = parser.parse(line, reference=ref)
        if not event:
            continue
        alerter.info(
            f"Parsed: {event.status.value} | {event.ip} | {event.username}"
        )
        incident = analyzer.process(event)
        if incident:
            alerter.alert(incident)
            send_telegram_alert(incident.ip, incident.attempt_count, incident.usernames)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Real-time auth.log SIEM-lite (SSH brute-force detector)",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=Path(DEFAULT_LOG_PATH),
        help=f"Path to auth log (default: {DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print every parsed SSH event",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run offline demo with sample lines (no log file needed)",
    )
    parser.add_argument(
        "--init-test-log",
        action="store_true",
        help="Create an empty log file (use with -f), then use feed_test_log.py",
    )
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return 0

    if args.init_test_log:
        init_test_log(args.file)
        return 0

    if not args.file.exists():
        script_dir = Path(__file__).resolve().parent
        local_test = script_dir / "test_auth.log"
        print(
            f"Log file not found: {args.file}\n\n"
            "Windows quick start:\n"
            f"  cd {script_dir}\n"
            "  py auth_siem.py --demo\n"
            f"  py auth_siem.py -f {local_test} -v\n"
            "  (in another terminal) py feed_test_log.py\n\n"
            "Note: use 'py', not 'python3' (Store stub on Windows). "
            "sudo is not available on Windows.",
            file=sys.stderr,
        )
        return 1

    try:
        AuthSiemApp(args.file, verbose=args.verbose).run()
    except KeyboardInterrupt:
        print("\n[SIEM] Stopped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
