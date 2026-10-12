from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
SESSION_TIMEOUT_SEC = 900

# Локальна частина: літера + 2..63 літер/цифр/_ (разом 3-64); домен із крапкою.
EMAIL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def utc_now() -> datetime:
    """Поточний час UTC з часовим поясом."""
    return datetime.now(timezone.utc)


class User:
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
        password: str | None = None,
    ) -> None:
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""
        if password is not None:
            self.set_password(password)

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_RE.fullmatch(value):
            raise ValueError(f"Некоректний email: {value!r}")
        self._email = value

    def __derive(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def set_password(self, password: str) -> None:
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль має бути непорожнім рядком")
        self.__password_salt = os.urandom(SALT_SIZE)
        self.__password_hash = self.__derive(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not isinstance(password, str):
            return False
        candidate = self.__derive(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return f"User({self.username}, {self.email}, role={self.role}, {state})"


class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        password: str | None = None,
        permissions: Iterable[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(
            username, email, role="admin", active=active, password=password
        )
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "-"
        return f"{super().__str__()} permissions=[{perms}]"


@dataclass
class Session:
    ip: str
    login_time: datetime
    last_activity: datetime

    def touch(self, now: datetime | None = None) -> None:
        self.last_activity = now or utc_now()

    def is_active(self, timeout_sec: int, now: datetime | None = None) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        now = now or utc_now()
        return now - self.last_activity <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditEntry:
    timestamp: datetime
    username: str
    action: str  # login_success | login_failure | logout


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def add_log(
        self, username: str, action: str, timestamp: datetime | None = None
    ) -> None:
        self._entries.append(AuditEntry(timestamp or utc_now(), username, action))

    def show_all(self) -> None:
        for e in self._entries:
            print(
                f"{e.timestamp.isoformat(timespec='seconds')} | {e.username} | {e.action}"
            )


class UserAccount:
    _KEY_TYPES = {"user": User, "session": (Session, type(None)), "audit": AuditLog}

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit = audit if audit is not None else AuditLog()

    def login(
        self, username: str, password: str, ip: str, now: datetime | None = None
    ) -> bool:
        now = now or utc_now()
        ok = (
            username == self.user.username
            and self.user.active
            and self.user.check_password(password)
        )
        if not ok:
            self.audit.add_log(username, "login_failure", now)
            return False
        self.session = Session(ip=ip, login_time=now, last_activity=now)
        self.session.touch(now)
        self.audit.add_log(username, "login_success", now)
        return True

    def is_authenticated(self, now: datetime | None = None) -> bool:
        """Перевірка не подовжує сеанс."""
        return self.session is not None and self.session.is_active(
            SESSION_TIMEOUT_SEC, now
        )

    def logout(self, now: datetime | None = None) -> None:
        if self.session is None:
            return
        self.audit.add_log(self.user.username, "logout", now)
        self.session = None

    def __getitem__(self, key: str):
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value) -> None:
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        if not isinstance(value, self._KEY_TYPES[key]):
            raise TypeError(f"Неправильний тип для {key!r}: {type(value).__name__}")
        setattr(self, key, value)


def run_demo() -> None:

    admin = Admin("admin01", "admin_01@corp.ua", password="S3cret!pass")
    account = UserAccount(admin)
    print(" Користувач ")
    print(admin)

    print("\n== Входи ==")
    print("Невдалий вхід:", account.login("admin01", "wrong", "10.0.0.5"))
    print("Успішний вхід:", account.login("admin01", "S3cret!pass", "10.0.0.5"))
    print("Автентифікований:", account.is_authenticated())

    print("\n== Зміна email ==")
    admin.email = "new_admin@corp.ua"
    print("Новий email:", admin.email)
    try:
        admin.email = "1bad@corp"
    except ValueError as exc:
        print("Помилка валідації:", exc)

    print("\n== Права адміністратора ==")
    admin.grant_permission("read_logs")
    admin.grant_permission("manage_users")
    admin.revoke_permission("manage_users")
    print(admin, "| read_logs:", admin.has_permission("read_logs"))

    print("\nДоступ через ключі")
    print(account["user"].username)
    for bad in (
        lambda: account["password_hash"],
        lambda: account.__setitem__("user", 5),
    ):
        try:
            bad()
        except (KeyError, TypeError) as exc:
            print(type(exc).__name__, exc)

    print("\n Таймаут сеансу ")
    later = utc_now() + timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("Через 901 с автентифікований:", account.is_authenticated(later))

    print("\n== Вихід ==")
    account.login("admin01", "S3cret!pass", "10.0.0.5")
    account.logout()
    print("Після logout:", account.is_authenticated())

    print("\nAuditLog")
    account.audit.show_all()
