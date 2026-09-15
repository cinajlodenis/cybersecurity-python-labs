import task1
import task2
import task3


def main():
    tasks = [("Task 1", task1), ("Task 2", task2), ("Task 3", task3)]

    for name, module in tasks:
        print(f"\n--- {name} ---")
        try:
            module.main()
        except Exception as e:
            print(f"Помилка в {name}: {e}")


if __name__ == "__main__":
    main()
