import csv
import json
import os
import sys
from datetime import datetime
from functools import wraps

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import HASH_ALGORITHM, MIN_PASSWORD_LENGTH, VARIANT_NUMBER


class ValidationError(Exception):
    pass


SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = "labs/lab01/data"
USERS_FILE = f"{DATA_DIR}/users.csv"
LOG_FILE = f"{DATA_DIR}/log.json"


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Password or salt is empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must contain at least {MIN_PASSWORD_LENGTH} characters"
        )

    return HASH_ALGORITHM((password + salt).encode()).hexdigest()


users_to_register = (
    ("admin", "Admin12345!"),
    ("user1", "SecurePass123"),
    ("alex_dev", "AlexPassword2026"),
    ("john_doe", "JohnDoePass999"),
    ("kate_cyber", "CyberKate2026!"),
    ("michael_s", "MikePass789000"),
    ("olga_sec", "OlgaSecurity#1"),
    ("robert_p", "RobertPass321!"),
    ("bad_user1", "123"),
    ("bad_user2", ""),
)


def create_user(username, password):
    return username, generate_hash(password, SALT)


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(USERS_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            for username, password in users_list:
                try:
                    writer.writerow(create_user(username, password))
                except (ValueError, ValidationError) as e:
                    print(f"Помилка створення {username}: {e}")

    except FileNotFoundError as e:
        print(f"Файл не знайдено: {e}")
    except PermissionError as e:
        print(f"Немає прав доступу до файлу: {e}")
    except OSError as e:
        print(f"Помилка вводу-виводу: {e}")


def read_users():
    users_db = []

    try:
        with open(USERS_FILE, "r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    users_db.append(tuple(row))

    except FileNotFoundError as e:
        print(f"Файл не знайдено: {e}")
    except PermissionError as e:
        print(f"Немає прав доступу до файлу: {e}")
    except OSError as e:
        print(f"Помилка зчитування CSV: {e}")

    return users_db


def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")

        try:
            result = func(*args, **kwargs)
        except Exception as e:
            result = False
            raise e
        finally:
            log = {
                "event": "login",
                "user": username,
                "result": "success" if result else "failure",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                logs = []

                if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
                    with open(LOG_FILE, "r", encoding="utf-8") as file:
                        logs = json.load(file)

                logs.append(log)

                with open(LOG_FILE, "w", encoding="utf-8") as file:
                    json.dump(logs, file, ensure_ascii=False, indent=4)

            except FileNotFoundError as e:
                print(f"Файл логів не знайдено: {e}")
            except PermissionError as e:
                print(f"Немає прав на запис логу: {e}")
            except (OSError, ValueError, json.JSONDecodeError) as e:
                print(f"Помилка логування JSON: {e}")

        return result

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Login or password is empty")

    users_db = read_users()
    input_hash = generate_hash(password, SALT)

    for stored_user, stored_hash in users_db:
        if stored_user == username and stored_hash == input_hash:
            return True

    return False


def main():
    print("--- 1. Створення тестових користувачів ---")
    create_users(users_to_register)

    print("\n--- 2. База даних користувачів (users.csv) ---")
    users_db = read_users()
    print(f"{'Логін':<15} | {'Хеш пароля':<35}")
    print("-" * 55)
    for user, h_val in users_db:
        print(f"{user:<15} | {h_val[:30]}...")

    print("\n--- 3. Тестування автентифікації ---")

    try:
        is_logged = login("admin", "Admin12345!")
        print(f"Вхід admin: {'Успішно' if is_logged else 'Невдало'}")

        is_logged = login("admin", "WrongPassword123!")
        print(f"Вхід admin (невірний пароль): {'Успішно' if is_logged else 'Невдало'}")

        login("", "SomePassword123")
        login("kate_cyber", "123")

    except ValueError as e:
        print(f"Помилка значення: {e}")
    except ValidationError as e:
        print(f"Помилка валідації: {e}")


if __name__ == "__main__":
    main()
