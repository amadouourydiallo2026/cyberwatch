#!/usr/bin/env python3
"""
Met à jour data.json (section "actors") en agrégeant, par groupe, le nombre
de victimes revendiquées sur les 7 derniers jours via l'API Ransomware.live.

Comme pour fetch_attacks.py : ne couvre que les groupes de ransomware/
extorsion suivis par Ransomware.live, pas les acteurs étatiques (APT) sans
volet extorsion, faute de flux public équivalent et gratuit pour ceux-ci.

API : https://api.ransomware.live/v2 (aucune clé requise, mais rate-limitée)

Lancé chaque jour par .github/workflows/daily-update.yml
"""
import json
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

API_BASE = "https://api.ransomware.live/v2"
DATA_FILE = "data.json"
LOOKBACK_DAYS = 7
MAX_ROWS = 9


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cyberwatch-bot/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def build_actors():
    items = fetch_json(f"{API_BASE}/recentvictims")
    if not isinstance(items, list):
        items = items.get("data", []) if isinstance(items, dict) else []

    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    counts = defaultdict(int)
    countries = defaultdict(set)

    for item in items:
        date_str = item.get("attackdate") or item.get("date") or ""
        try:
            d = datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            d = None
        if d and d < cutoff:
            continue
        group = item.get("group") or "Inconnu"
        counts[group] += 1
        c = item.get("country")
        if c:
            countries[group].add(c)

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:MAX_ROWS]

    rows = []
    for group, victim_count in ranked:
        region_set = countries.get(group, set())
        if len(region_set) >= 4:
            region = "Global"
        elif region_set:
            region = ", ".join(sorted(region_set))
        else:
            region = "Non précisé"

        rows.append({
            "name": group,
            "type": "RaaS / Extorsion",
            "desc": f"{victim_count} victime(s) revendiquée(s) sur les {LOOKBACK_DAYS} derniers jours.",
            "victims": str(victim_count),
            "region": region,
            # Pas de page dédiée par groupe garantie sur le site : on pointe
            # vers la liste générale des groupes plutôt que de deviner une
            # URL susceptible de renvoyer une 404.
            "url": "https://www.ransomware.live/groups",
        })
    return rows


def main():
    try:
        new_actors = build_actors()
    except Exception as e:
        print(f"[fetch_actors] Échec de récupération de Ransomware.live : {e}", file=sys.stderr)
        sys.exit(1)

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if new_actors:
        data["actors"] = new_actors

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[fetch_actors] {len(new_actors)} acteur(s) mis à jour depuis Ransomware.live.")


if __name__ == "__main__":
    main()
