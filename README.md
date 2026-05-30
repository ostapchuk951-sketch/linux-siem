# Auth SIEM Lite

Легковесный анализатор `auth.log` в реальном времени для Linux-серверов: мониторинг SSH, детекция brute-force и консольные алерты (с заглушкой Telegram).

> Учебный/пет-проект уровня mini-SIEM: один файл, без внешних зависимостей, только стандартная библиотека Python 3.10+.

## Возможности

- **Tailer** — чтение только новых строк из лога (без перечитывания всего файла)
- **Parser** — извлечение timestamp, IP, username, статуса (`Success` / `Failed` / `Invalid User`)
- **Rule Engine** — brute-force: **> 5** неудачных попыток с одного IP за **60 секунд**
- **Alerter** — цветное предупреждение в консоль + `send_telegram_alert()` для вашей интеграции
- **Память** — скользящее окно по IP, старые попытки удаляются по TTL

## Архитектура

```
/var/log/auth.log
        │
        ▼
┌─────────────────┐
│ AuthLogTailer   │  Reader — tail новых строк, ротация logrotate
└────────┬────────┘
         ▼
┌─────────────────┐
│ AuthLogParser   │  Parser — regex → LogEvent
└────────┬────────┘
         ▼
┌─────────────────┐
│ BruteForceDetector │  Analyzer — deque + окно 60 с
└────────┬────────┘
         ▼
┌─────────────────┐     ┌──────────────────────┐
│ ConsoleAlerter  │     │ send_telegram_alert  │
└─────────────────┘     └──────────────────────┘
```

## Требования

- Python **3.10+**
- Linux: доступ к `/var/log/auth.log` (`root` или группа `adm`)
- Windows: только для локального теста (см. ниже)

## Быстрый старт (Linux)

```bash
git clone https://github.com/YOUR_USERNAME/linux-siem.git
cd linux-siem

# Просмотр демо без лога
python3 auth_siem.py --demo

# Мониторинг production-лога
sudo python3 auth_siem.py -f /var/log/auth.log -v
```

## Тест на Windows

На Windows используйте лаунчер **`py`**, а не `python3` (часто открывается заглушка Microsoft Store).

**Терминал 1** — мониторинг:

```powershell
cd path\to\linux-siem
py auth_siem.py -f .\test_auth.log -v
```

**Терминал 2** — имитация атаки:

```powershell
py feed_test_log.py
```

Офлайн-демо без файла:

```powershell
py auth_siem.py --demo
```

## Параметры CLI

| Флаг | Описание |
|------|----------|
| `-f`, `--file` | Путь к логу (по умолчанию `/var/log/auth.log`) |
| `-v`, `--verbose` | Печатать каждое распознанное SSH-событие |
| `--demo` | Синтетические строки, без файла |
| `--init-test-log` | Создать пустой файл для `-f` |

## Настройка правила

В начале `auth_siem.py`:

```python
WINDOW_SECONDS = 60          # окно подсчёта
FAILED_THRESHOLD = 5         # инцидент при > 5 (на 6-й попытке)
ALERT_COOLDOWN_SECONDS = 300   # пауза повторных алертов по IP
```

## Telegram

В функции `send_telegram_alert()` добавьте токен бота и `chat_id`, раскомментируйте вызов `requests.post` (понадобится `pip install requests`).

## Файлы проекта

| Файл | Назначение |
|------|------------|
| `auth_siem.py` | Основной SIEM-скрипт |
| `feed_test_log.py` | Генератор тестовых строк в `test_auth.log` |
| `test_auth.log` | Локальный лог (в `.gitignore`, создаётся при тесте) |

## Примеры строк auth.log

```
May 30 12:00:01 host sshd[1234]: Failed password for root from 203.0.113.10 port 22 ssh2
May 30 12:00:02 host sshd[1234]: Invalid user admin from 203.0.113.10 port 22 ssh2
May 30 12:00:03 host sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2
```

## Ограничения

- Рассчитан на формат **Debian/Ubuntu** `sshd` в `auth.log`
- IPv6 и нестандартные форматы могут потребовать доработки regex
- Это не полноценная SIEM: нет БД, веб-UI и корреляции между хостами

## Лицензия

MIT — используйте свободно в учебных и личных проектах.

## Автор

Пет-проект по кибербезопасности. Pull requests приветствуются.
