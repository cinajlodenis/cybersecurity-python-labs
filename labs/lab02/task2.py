from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

ALERT = 35
logging.addLevelName(ALERT, "ALERT")
logger = logging.getLogger("user_activity")

REQUIRED_COLUMNS = ("timestamp", "userid", "action", "resource", "ip")
DATE_FORMATS = ("%d.%m.%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S")
CRITICAL_RE = re.compile(
    r"confidential|finance|payroll|hr_|_hr|export|shadow|passwd|admin|backup|secret|db\b|_db",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ActivityRecord:
    timestamp: datetime
    user_id: str
    action: str
    resource: str
    ip: str


def parse_timestamp(value: str) -> datetime:
    value = value.strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"Невідомий формат дати: {value!r}")


def read_records(path: Path) -> tuple[list[ActivityRecord], int]:
    """Читає CSV; повертає (записи, кількість пропущених рядків)."""
    records: list[ActivityRecord] = []
    skipped = 0
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError("Порожній CSV-файл")
        header = {
            name.strip().lower().replace("_", ""): name for name in reader.fieldnames
        }
        missing = [c for c in REQUIRED_COLUMNS if c not in header]
        if missing:
            raise ValueError(f"У CSV немає колонок: {', '.join(missing)}")
        for line_no, row in enumerate(reader, start=2):
            try:
                records.append(
                    ActivityRecord(
                        timestamp=parse_timestamp(row[header["timestamp"]]),
                        user_id=row[header["userid"]].strip(),
                        action=row[header["action"]].strip(),
                        resource=row[header["resource"]].strip(),
                        ip=(row[header["ip"]] or "").strip(),
                    )
                )
            except (ValueError, AttributeError, TypeError) as exc:
                skipped += 1
                logger.warning("Рядок %d пропущено: %s", line_no, exc)
    return records, skipped


def is_off_hours(ts: datetime, night_start: int = 22, night_end: int = 6) -> bool:
    weekend = ts.weekday() >= 5
    night = ts.hour >= night_start or ts.hour < night_end
    return weekend or night


def group_by_user(records: list[ActivityRecord]) -> dict[str, list[ActivityRecord]]:
    groups: dict[str, list[ActivityRecord]] = defaultdict(list)
    for rec in records:
        groups[rec.user_id].append(rec)
    return groups


def find_off_hours(records, night_start: int, night_end: int) -> list[dict]:
    """Групує нічні/вихідні дії за (користувач, ресурс)."""
    grouped: dict[tuple[str, str], list[ActivityRecord]] = defaultdict(list)
    for rec in records:
        if is_off_hours(rec.timestamp, night_start, night_end):
            grouped[(rec.user_id, rec.resource)].append(rec)
    alerts = []
    for (user, resource), items in grouped.items():
        items.sort(key=lambda r: r.timestamp)
        first = items[0].timestamp
        alerts.append(
            {
                "user": user,
                "resource": resource,
                "actions": len(items),
                "first_seen": first.isoformat(),
                "weekday": first.strftime("%A"),
                "ips": sorted({r.ip for r in items if r.ip}),
                "critical": bool(CRITICAL_RE.search(resource)),
            }
        )
    alerts.sort(key=lambda a: (not a["critical"], -a["actions"]))
    return alerts


def find_mass_access(records, threshold: int, window_sec: int) -> list[dict]:
    anomalies = []
    for user, items in group_by_user(records).items():
        crit = sorted(
            (r for r in items if CRITICAL_RE.search(r.resource)),
            key=lambda r: r.timestamp,
        )
        left = best = best_left = 0
        for right, rec in enumerate(crit):
            while (rec.timestamp - crit[left].timestamp).total_seconds() > window_sec:
                left += 1
            if right - left + 1 > best:
                best, best_left = right - left + 1, left
        if best > threshold:
            window = crit[best_left : best_left + best]
            resources = defaultdict(int)
            for r in window:
                resources[r.resource] += 1
            anomalies.append(
                {
                    "user": user,
                    "requests": best,
                    "window_sec": window_sec,
                    "window_start": window[0].timestamp.isoformat(),
                    "top_resource": max(resources, key=resources.get),
                }
            )
    anomalies.sort(key=lambda a: -a["requests"])
    return anomalies


def setup_logging(log_file: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--activity-log", type=Path, required=True, help="CSV-файл дій")
    parser.add_argument(
        "--after-hours", action="store_true", help="шукати дії у позаробочий час"
    )
    parser.add_argument(
        "--out-report", type=Path, default=Path("data/off_hours_audit.json")
    )
    parser.add_argument("--log-file", type=Path, default=None)
    parser.add_argument(
        "--threshold", type=int, default=50, help="запитів за вікно (>)"
    )
    parser.add_argument("--window-sec", type=int, default=60)
    parser.add_argument("--night-start", type=int, default=22, choices=range(24))
    parser.add_argument("--night-end", type=int, default=6, choices=range(24))


def run(args: argparse.Namespace) -> int:
    setup_logging(args.log_file)
    if args.threshold < 1 or args.window_sec < 1:
        logger.error("--threshold і --window-sec мають бути додатними")
        return 2
    logger.info("Reading user activity log %s...", args.activity_log)
    try:
        records, skipped = read_records(args.activity_log)
    except (OSError, ValueError, csv.Error) as exc:
        logger.error("Не вдалося прочитати журнал: %s", exc)
        return 1
    logger.info("Total records processed: %d.", len(records))
    if skipped:
        logger.warning("Skipped invalid rows: %d", skipped)

    off_hours = []
    if args.after_hours:
        off_hours = find_off_hours(records, args.night_start, args.night_end)
        print(
            f"\n=== Off-Hours Activity Alerts ({args.night_start}:00 - {args.night_end:02d}:00 / Weekends) ==="
        )
        for a in off_hours:
            if a["actions"] > 1:
                logger.log(
                    ALERT,
                    "User '%s' performed %d actions at %s (Resource: %s)",
                    a["user"],
                    a["actions"],
                    a["first_seen"][11:19],
                    a["resource"],
                )
            else:
                logger.log(
                    ALERT,
                    "User '%s' accessed '%s' on %s %s from IP %s",
                    a["user"],
                    a["resource"],
                    a["weekday"],
                    a["first_seen"][11:19],
                    ", ".join(a["ips"]) or "-",
                )

    mass = find_mass_access(records, args.threshold, args.window_sec)
    print(
        f"\n=== Mass Download Anomalies (>{args.threshold} requests/{args.window_sec}s) ==="
    )
    for m in mass:
        logger.log(
            ALERT,
            "User '%s' executed %d requests to critical resources within %d seconds (top: %s)",
            m["user"],
            m["requests"],
            m["window_sec"],
            m["top_resource"],
        )

    report = {
        "source": str(args.activity_log),
        "total_records": len(records),
        "skipped_rows": skipped,
        "users": len(group_by_user(records)),
        "off_hours_alerts": off_hours,
        "mass_access_anomalies": mass,
        "records_example": [
            asdict(r) | {"timestamp": r.timestamp.isoformat()} for r in records[:3]
        ],
    }
    try:
        args.out_report.parent.mkdir(parents=True, exist_ok=True)
        args.out_report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        logger.error("Не вдалося записати звіт: %s", exc)
        return 1
    logger.info("Anomalous activity report written to %s", args.out_report)
    return 0
