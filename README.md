# Auth SIEM Lite

Легкий аналізатор `auth.log` у реальному часі для Linux-серверів: моніторинг SSH, виявлення brute-force і сповіщення в консоль (з заглушкою Telegram).

> Навчальний pet-проект рівня mini-SIEM: один основний файл, без зовнішніх залежностей, лише стандартна бібліотека Python 3.10+.

## Можливості

- **Tailer** — читання лише нових рядків логу (без повного перечитування файлу)
- **Parser** — витягування timestamp, IP, username, статусу (`Success` / `Failed` / `Invalid User`)
- **Rule Engine** — brute-force: **> 5** невдалих спроб з одного IP за **60 секунд**
- **Alerter** — кольорове попередження в консоль + `send_telegram_alert()` для вашої інтеграції
- **Пам’ять** — ковзне вікно по IP, старі спроби видаляються за TTL

## Архітектура

```
/var/log/auth.log
        │
        ▼
┌─────────────────┐
│ AuthLogTailer   │  Reader — tail нових рядків, ротація logrotate
└────────┬────────┘
         ▼
┌─────────────────┐
│ AuthLogParser   │  Parser — regex → LogEvent
└────────┬────────┘
         ▼
┌─────────────────┐
│ BruteForceDetector │  Analyzer — deque + вікно 60 с
└────────┬────────┘
         ▼
┌─────────────────┐     ┌──────────────────────┐
│ ConsoleAlerter  │     │ send_telegram_alert  │
└─────────────────┘     └──────────────────────┘
```

## Вимоги

- Python **3.10+**
- Linux: доступ до `/var/log/auth.log` (`root` або група `adm`)
- Windows: лише для локального тесту (див. нижче)

## Швидкий старт (Linux)

```bash
git clone https://github.com/ostapchuk951-sketch/linux-siem.git
cd linux-siem

# Демо без файлу логу
python3 auth_siem.py --demo

# Моніторинг production-логу
sudo python3 auth_siem.py -f /var/log/auth.log -v
```

## Тест на Windows

На Windows використовуйте **`py`**, а не `python3` (часто відкривається заглушка Microsoft Store).

**Термінал 1** — моніторинг:

```powershell
cd path\to\linux-siem
py auth_siem.py -f .\test_auth.log -v
```

**Термінал 2** — імітація атаки:

```powershell
py feed_test_log.py
```

Офлайн-демо без файлу:

```powershell
py auth_siem.py --demo
```

> Скрипт читає лише **нові** рядки після запуску. Спочатку запустіть `auth_siem.py`, потім `feed_test_log.py`.

## Параметри CLI

| Прапорець | Опис |
|-----------|------|
| `-f`, `--file` | Шлях до логу (за замовчуванням `/var/log/auth.log`) |
| `-v`, `--verbose` | Виводити кожну розпізнану SSH-подію |
| `--demo` | Синтетичні рядки, без файлу |
| `--init-test-log` | Створити порожній файл для `-f` |

## Налаштування правила

На початку `auth_siem.py`:

```python
WINDOW_SECONDS = 60            # вікно підрахунку
FAILED_THRESHOLD = 5           # інцидент при > 5 (на 6-й спробі)
ALERT_COOLDOWN_SECONDS = 300   # пауза між повторними алертами по IP
```

## Telegram

У функції `send_telegram_alert()` додайте токен бота та `chat_id`, розкоментуйте `requests.post` (потрібно `pip install requests`).

## Файли проєкту

| Файл | Призначення |
|------|-------------|
| `auth_siem.py` | Основний SIEM-скрипт |
| `feed_test_log.py` | Генератор тестових рядків у `test_auth.log` |
| `test_auth.log` | Локальний лог (у `.gitignore`, створюється під час тесту) |

## Приклади рядків auth.log

```
May 30 12:00:01 host sshd[1234]: Failed password for root from 203.0.113.10 port 22 ssh2
May 30 12:00:02 host sshd[1234]: Invalid user admin from 203.0.113.10 port 22 ssh2
May 30 12:00:03 host sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2
```

## Обмеження

- Розраховано на формат **Debian/Ubuntu** `sshd` у `auth.log`
- IPv6 і нестандартні формати можуть потребувати доопрацювання regex
- Це не повноцінна SIEM: немає БД, веб-UI та кореляції між хостами

## Ліцензія

MIT — вільне використання в навчальних і особистих проєктах.

## Автор

Pet-проєкт з кібербезпеки. Pull requests вітаються.
