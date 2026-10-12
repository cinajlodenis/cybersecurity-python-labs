# Лабораторна робота №2 — Розробка консольних утиліт для задач кібербезпеки

**Варіант 7:** Аналізатор журналів активності користувачів (User Activity Audit).

Утиліта виявляє аномальну активність співробітників у корпоративній системі: дії у позаробочий час (22:00–06:00 та вихідні) і масові запити до критичних ресурсів.

## Встановлення залежностей

Усі команди виконуються з **кореня репозиторію** `cybersecurity-python-labs` в активованому віртуальному середовищі з ЛР №1.

```bash
source .venv/bin/activate        # macOS/Linux
pip install -r requirements.txt  # ruff та наявні залежності
```

Код ЛР використовує лише стандартну бібліотеку Python (`argparse`, `csv`, `json`, `logging`, `pathlib`, `re`, `datetime`, `collections`, `hashlib`, `hmac`).

## Структура файлів

```
labs/lab02/
├── __init__.py
├── main.py        # команди demo та analyze
├── task1.py       # User, Admin, Session, AuditLog, UserAccount
├── task2.py       # утиліта варіанта 7
├── README.md
└── data/
    └── data_v07/  # файли з lab2_data.zip (вказати фактичні назви)
        └── user_activity.csv
```

**Вхідний файл:** CSV із колонками `Timestamp, UserID, Action, Resource, IP` (регістр назв колонок не важливий). Дата: ISO (`2026-09-27 02:14:03`) або `ДД.ММ.РРРР ГГ:ХХ:СС`.

## Запуск

```bash
# Завдання 1: демонстрація класів
python -m labs.lab02.main demo

# Завдання 2: аналіз журналу активності
python -m labs.lab02.main analyze \
    --activity-log labs/lab02/data/data_v07/user_activity.csv \
    --after-hours \
    --out-report labs/lab02/data/data_v07/off_hours_audit.json \
    --log-file audit.log
```

## Параметри `analyze`

| Параметр | Опис | Типово |
|---|---|---|
| `--activity-log` | шлях до CSV (обов'язковий) | — |
| `--after-hours` | прапорець: шукати дії у позаробочий час | вимкнено |
| `--out-report` | шлях до JSON-звіту | `data/off_hours_audit.json` |
| `--log-file` | додатково писати лог у файл | немає |
| `--threshold` | поріг масових запитів (більше N) | 50 |
| `--window-sec` | розмір вікна, секунди | 60 |
| `--night-start`, `--night-end` | межі «ночі» (години) | 22, 6 |

## Поведінка при помилках

- Файл не знайдено, немає потрібних колонок або не вдалося записати звіт → `[ERROR]` і код виходу `1`.
- Некоректні `--threshold`/`--window-sec` (≤ 0) → `[ERROR]` і код виходу `2`.
- Рядок із некоректною датою пропускається з `[WARNING]`, обробка продовжується.

## Перевірка коду

```bash
ruff check .
ruff format --check .
```
