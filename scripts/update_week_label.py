#!/usr/bin/env python3
"""
Recalcule automatiquement "week_label" (ex. "S29 · 13 – 19 juillet 2026")
à partir de la date du jour, en se basant sur la semaine ISO en cours
(lundi à dimanche).

Lancé en premier chaque jour par .github/workflows/daily-update.yml, avant
les autres scripts.
"""
import json
from datetime import datetime, timedelta, timezone

DATA_FILE = "data.json"

MOIS_FR = ["janvier", "février", "mars", "avril", "mai", "juin",
           "juillet", "août", "septembre", "octobre", "novembre", "décembre"]


def format_week_label(today):
    iso_year, iso_week, iso_weekday = today.isocalendar()
    monday = today - timedelta(days=iso_weekday - 1)
    sunday = monday + timedelta(days=6)

    if monday.month == sunday.month:
        date_range = f"{monday.day} – {sunday.day} {MOIS_FR[sunday.month - 1]} {sunday.year}"
    else:
        date_range = (f"{monday.day} {MOIS_FR[monday.month - 1]} – "
                      f"{sunday.day} {MOIS_FR[sunday.month - 1]} {sunday.year}")

    return f"S{iso_week:02d} · {date_range}"


def main():
    today = datetime.now(timezone.utc)
    label = format_week_label(today)

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["week_label"] = label

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[update_week_label] week_label mis à jour : {label}")


if __name__ == "__main__":
    main()
