```python
import sys
import os
import csv
import json
from datetime import datetime
from functools import wraps

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

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

    return HASH_ALGORITHM(
        (password + salt).encode()
    ).hexdigest()


def create_user(username, password):

    return username, generate_hash(password, SALT)


def create_users(users_list):

    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(USERS_FILE, "w", newline="", encoding="utf-8") as file:

            writer = csv.writer(file)

            for username, password in users_list:

                try:
                    writer.writerow(
                        create_user(username, password)
                    )

                except (ValueError, ValidationError) as e:
                    print(f"{username}: {e}")

    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"File error: {e}")


def read_users():

    users_db = []

    try:
        with open(
            USERS_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.reader(file)

            for row in reader:
                users_db.append(tuple(row))

    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"File error: {e}")

    return users_db


def log_event(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        result = func(*args, **kwargs)

        log = {
            "event": "login",
            "user": args[0],
            "result": "success" if result else "failure",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": list(args),
            "kwargs": kwargs
        }

        try:
            logs = []

            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:

                with open(LOG_FILE, "r", encoding="utf-8") as file:
                    logs = json.load(file)

            logs.append(log)

            with open(LOG_FILE, "w", encoding="utf-8") as file:
                json.dump(
                    logs,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

        except (
            FileNotFoundError,
            PermissionError,
            IOError,
            ValueError
        ) as e:

            print(f"Log error: {e}")

        return result

    return wrapper


@log_event
def login(username: str, password: str) -> bool:

    if not username or not password:
        raise ValueError("Login or password is empty")
```
