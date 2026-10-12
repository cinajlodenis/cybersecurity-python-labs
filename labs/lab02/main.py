from __future__ import annotations

import argparse
import sys

from labs.lab02 import task1, task2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="labs.lab02.main", description="ЛР №2, варіант 7"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="демонстрація Завдання 1")
    task2.add_arguments(sub.add_parser("analyze", help="аналіз журналу активності"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        task1.run_demo()
        return 0
    return task2.run(args)


if __name__ == "__main__":
    sys.exit(main())
