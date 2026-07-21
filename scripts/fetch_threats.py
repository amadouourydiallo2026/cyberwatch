#!/usr/bin/env python3
"""
Construit la section "threats" (top 5 menaces les plus dangereuses) en
combinant deux sources déjà présentes dans data.json :
  - les vulnérabilités CISA KEV marquées comme utilisées dans des campagnes
    ransomware actives (champ "note"),
  - les groupes de ransomware les plus actifs de la semaine (section "actors").

⚠️ Contrairement à fetch_kev.py / fetch_iocs.py / fetch_attacks.py /
fetch_actors.py, ce script ne fait AUCUN appel réseau : il recombine des
données déjà écrites dans data.json par les scripts précédents. Il doit donc
être lancé APRÈS fetch_kev.py et APRÈS fetch_actors.py dans le workflow.

Lancé chaque jour par .github/workflows/daily-update.yml
"""
import json
import sys
from datetime import datetime, timezone

DATA_FILE = "data.json"
MAX_ROWS = 5


def build_threats(data):
    rows = []

    # 1) Vulnérabilités KEV liées à des campagnes ransomware connues
    for v in data.get("vulns", []):
        if v.get("note"):
            rows.append({
                "title": f"{v['cve']} — {v.get('product','')}".strip(" —"),
                "desc": f"{v.get('type','Vulnérabilité exploitée')} — {v['note']}.",
                "url": v.get("url", ""),
            })
        if len(rows) >= 3:
            break

    # 2) Groupes de ransomware les plus actifs de la semaine
    for a in data.get("actors", [])[:3]:
        if len(rows) >= MAX_ROWS:
            break
        rows.append({
            "title": f"Activité soutenue de {a['name']}",
            "desc": a.get("desc", "Groupe de ransomware actif cette semaine."),
            "url": a.get("url", ""),
        })

    return rows[:MAX_ROWS]


def main():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    new_threats = build_threats(data)
    if new_threats:
        data["threats"] = new_threats
    else:
        print("[fetch_threats] Aucune donnée source disponible (vulns/actors vides) — conservation des menaces précédentes.", file=sys.stderr)

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[fetch_threats] {len(new_threats)} menace(s) recalculée(s) à partir de vulns/actors.")


if __name__ == "__main__":
    main()
