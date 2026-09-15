import sys
import os
import random
import string

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), '../../')
    )
)

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

passwords = [
    "NetworkS3c!",
    "easy",
    "Firewa11@Pass",
    "anonymous",
    "Intrus10n#Detect",
    "sample",
    "Malwar3@Scan",
    "qwerty",
    "Vulnerab1l!ty",
    "common"
]
criteria = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True
}
forbidden_passwords = {
    "easy",
    "anonymous",
    "sample",
    "qwerty",
    "common",
    "password"
}



print(
    f"Лабораторна робота №1 | "
    f"Виконав: {STUDENT_NAME} ({GROUP_NAME}), "
    f"Варіант: {VARIANT_NUMBER}\n"
)
min_length = criteria["min_length"]

print(
    f"Початкова кількість паролів у списку: "
    f"{len(passwords)}"
)

for _ in range(3):
    random_index = random.randint(0, len(passwords) - 1)
    duplicate_password = passwords[random_index]
    passwords.append(duplicate_password)

print(
    f"Кількість паролів після додавання дублікатів: "
    f"{len(passwords)}"
)

def analyze_password(pwd, passwords):

    
    if pwd in forbidden_passwords or len(pwd) < min_length:
        return "Заборонений"

    
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)

    has_special = any(
        c in string.punctuation
        or (not c.isalnum() and not c.isspace())
        for c in pwd
    )

    fulfilled_criteria = sum([
        has_upper,
        has_lower,
        has_digit,
        has_special
    ])

    
    is_unique = passwords.count(pwd) == 1

    
    if fulfilled_criteria <= 1:
        return "Слабкий"

    
    if fulfilled_criteria == 4:

        
        if len(pwd) >= (min_length + 4) and is_unique:
            return "Дуже сильний"
        else:
            return "Сильний"

    
    return "Середній"

print(
    f"{'№':<4} | "
    f"{'Пароль':<20} | "
    f"{'Довжина':<7} | "
    f"Оцінка надійності"
)

print("-" * 60)


for index, password in enumerate(passwords, start=1):

    status = analyze_password(password, passwords)

    print(
        f"[{index:<2}] | "
        f"{password:<20} | "
        f"{len(password):<7} | "
        f"{status}"
    )