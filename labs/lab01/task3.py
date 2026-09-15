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

    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"File error: {e}")


def read_users():
    users_db = []

    try:
        with open(USERS_FILE, "r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    users_db.append(tuple(row))

    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"File error: {e}")

    return users_db


def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        username = args[0] if args else kwargs.get("username", "unknown")

        try:
            result = func(*args, **kwargs)
        except Exception as e:
            # Якщо виникла помилка (наприклад, ValueError), також логуємо невдачу і прокидаємо далі
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

            except (
                OSError,
                FileNotFoundError,
                PermissionError,
                ValueError,
                json.JSONDecodeError,
            ) as e:
                print(f"Log error: {e}")

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

    test_users = [
        ("admin", "Admin12345!"),
        ("user1", "SecurePass123"),
        ("bad_user", "123"),
    ]

    try:
        print("--- Створення тестових користувачів ---")
        create_users(test_users)

        print("\n--- Тестування автентифікації ---")

        try:
            is_logged = login("admin", "Admin12345!")
            print(f"Вхід admin: {'Успішно' if is_logged else 'Невдало'}")
        except (
            OSError,
            ValueError,
            ValidationError,
            FileNotFoundError,
            PermissionError,
        ) as e:
            print(f"Помилка при вході: {e}")

        try:
            is_logged = login("admin", "WrongPassword123!")
            print(
                f"Вхід admin (невірний пароль): {'Успішно' if is_logged else 'Невдало'}"
            )
        except (
            OSError,
            ValueError,
            ValidationError,
            FileNotFoundError,
            PermissionError,
        ) as e:
            print(f"Помилка при вході: {e}")

        try:
            login("", "SomePassword123")
        except (
            OSError,
            ValueError,
            ValidationError,
            FileNotFoundError,
            PermissionError,
        ) as e:
            print(f"Перехоплено очікувану помилку (порожнє поле): {e}")

    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as e:
        print(f"Критична помилка виконання: {e}")


if __name__ == "__main__":
    main()
